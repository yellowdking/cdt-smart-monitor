package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cdt-smart-monitor/internal/aliyun"
	"cdt-smart-monitor/internal/auth"
	"cdt-smart-monitor/internal/domain"
	"cdt-smart-monitor/internal/notify"
	"cdt-smart-monitor/internal/policy"
	"cdt-smart-monitor/internal/store"
	"cdt-smart-monitor/internal/web"
)

type App struct {
	store    *store.Store
	auth     *auth.Manager
	ali      *aliyun.Client
	notifier *notify.Notifier
	logger   *slog.Logger
}

func main() {
	dataDir := envOr("CDT_DATA_DIR", "./data")
	listen := envOr("CDT_LISTEN", ":8080")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	st, err := store.Open(dataDir)
	if err != nil {
		logger.Error("failed to open store", "err", err)
		os.Exit(1)
	}

	app := &App{
		store:    st,
		auth:     auth.NewManager(),
		ali:      aliyun.NewClient(),
		notifier: notify.New(),
		logger:   logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleIndex)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	// Auth & Passkey endpoints
	mux.HandleFunc("/api/v1/auth/status", app.handleAuthStatus)
	mux.HandleFunc("/api/v1/auth/setup", app.handleAuthSetup)
	mux.HandleFunc("/api/v1/auth/login", app.handleAuthLogin)
	mux.HandleFunc("/api/v1/auth/logout", app.handleAuthLogout)
	mux.HandleFunc("/api/v1/auth/password", app.requireAuth(app.handleChangePassword))
	mux.HandleFunc("/api/v1/auth/passkey/register/begin", app.requireAuth(app.handlePasskeyRegisterBegin))
	mux.HandleFunc("/api/v1/auth/passkey/register/finish", app.requireAuth(app.handlePasskeyRegisterFinish))
	mux.HandleFunc("/api/v1/auth/passkey/delete", app.requireAuth(app.handlePasskeyDelete))
	mux.HandleFunc("/api/v1/auth/passkey/login/begin", app.handlePasskeyLoginBegin)
	mux.HandleFunc("/api/v1/auth/passkey/login/finish", app.handlePasskeyLoginFinish)

	// Protected API endpoints
	mux.HandleFunc("/api/v1/state", app.requireAuth(app.handleGetState))
	mux.HandleFunc("/api/v1/pool", app.requireAuth(app.handleSavePool))
	mux.HandleFunc("/api/v1/notify", app.requireAuth(app.handleSaveNotify))
	mux.HandleFunc("/api/v1/notify/test", app.requireAuth(app.handleTestNotify))
	mux.HandleFunc("/api/v1/notify/weekly-test", app.requireAuth(app.handleTestWeeklyReport))
	mux.HandleFunc("/api/v1/servers", app.requireAuth(app.handleServers))
	mux.HandleFunc("/api/v1/servers/", app.requireAuth(app.handleServerAction))
	mux.HandleFunc("/api/v1/refresh-all", app.requireAuth(app.handleRefreshAll))

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go app.runScheduler(ctx)

	go func() {
		logger.Info("CDT Smart Monitor listening", "addr", listen, "data_dir", dataDir)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	logger.Info("CDT Smart Monitor stopped gracefully")
}

func (a *App) runScheduler(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	var lastPoll time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			snap := a.store.SnapshotRaw()
			interval := time.Duration(snap.Pool.PollIntervalMinutes) * time.Minute
			if interval < time.Minute {
				interval = 5 * time.Minute
			}
			if lastPoll.IsZero() || now.Sub(lastPoll) >= interval {
				a.syncAllServers(ctx)
				lastPoll = now
			}
			a.evaluateAndExecutePool(ctx, now)
			a.maybeSendWeeklyReport(ctx, now)
		}
	}
}

func (a *App) syncAllServers(ctx context.Context) {
	snap := a.store.SnapshotRaw()
	for _, srv := range snap.Servers {
		_ = a.syncOneServer(ctx, srv.ID)
	}
}

func (a *App) syncOneServer(ctx context.Context, id int64) error {
	snap := a.store.SnapshotRaw()
	var target *domain.Server
	for i := range snap.Servers {
		if snap.Servers[i].ID == id {
			s := snap.Servers[i]
			target = &s
			break
		}
	}
	if target == nil {
		return fmt.Errorf("server %d not found", id)
	}

	now := time.Now()
	inst, ecsErr := a.ali.DescribeInstance(ctx, *target)
	trafficGB, cdtErr := a.ali.GetCDTTrafficGB(ctx, *target)
	costUSD, bssErr := a.ali.GetMonthlyBillUSD(ctx, *target, now)

	var errs []string
	if ecsErr != nil {
		errs = append(errs, "ECS: "+ecsErr.Error())
	}
	if cdtErr != nil {
		errs = append(errs, "CDT: "+cdtErr.Error())
	}
	if bssErr != nil {
		errs = append(errs, "BSS: "+bssErr.Error())
	}

	return a.store.Update(func(st *domain.AppState) error {
		for i := range st.Servers {
			if st.Servers[i].ID == id {
				if ecsErr == nil {
					st.Servers[i].Status = inst.Status
					st.Servers[i].PublicIP = inst.PublicIP
					if inst.Status == domain.StatusRunning {
						st.Servers[i].KeepAliveFails = 0
					}
				}
				if cdtErr == nil {
					if st.Servers[i].LastSyncAt == "" {
						st.Servers[i].PrevTrafficGB = trafficGB
					} else {
						st.Servers[i].PrevTrafficGB = st.Servers[i].UsedTrafficGB
					}
					st.Servers[i].UsedTrafficGB = trafficGB
				}
				if bssErr == nil {
					if st.Servers[i].LastSyncAt == "" {
						st.Servers[i].PrevCostUSD = costUSD
					} else {
						st.Servers[i].PrevCostUSD = st.Servers[i].BilledCostUSD
					}
					st.Servers[i].BilledCostUSD = costUSD
				}
				st.Servers[i].LastSyncAt = now.Format("2006-01-02 15:04:05")
				st.Servers[i].LastError = strings.Join(errs, " | ")
				break
			}
		}
		return nil
	})
}

func (a *App) evaluateAndExecutePool(ctx context.Context, now time.Time) {
	snap := a.store.SnapshotRaw()
	dec := policy.EvaluatePool(snap.Pool, snap.Servers, now)

	serverMap := make(map[int64]domain.Server, len(snap.Servers))
	for _, s := range snap.Servers {
		serverMap[s.ID] = s
	}

	for _, act := range dec.Actions {
		switch act.Type {
		case "start":
			srv := serverMap[act.ServerID]
			if err := a.ali.StartInstance(ctx, srv); err != nil {
				a.store.AddEvent("error", srv.Name, "开机/保活失败", err.Error())
				_ = a.store.Update(func(st *domain.AppState) error {
					for i := range st.Servers {
						if st.Servers[i].ID == srv.ID {
							st.Servers[i].KeepAliveFails++
						}
					}
					return nil
				})
			} else {
				a.store.AddEvent("info", srv.Name, "自动开机", act.Reason)
				a.notifier.Send(ctx, snap.Notify, "CDT 智能轮换 · 自动开机", srv.Name+": "+act.Reason)
				_ = a.store.Update(func(st *domain.AppState) error {
					for i := range st.Servers {
						if st.Servers[i].ID == srv.ID {
							st.Servers[i].Status = domain.StatusStarting
							st.Servers[i].LastActiveAt = now
							st.Servers[i].KeepAliveFails = 0
						}
					}
					return nil
				})
			}
		case "stop":
			srv := serverMap[act.ServerID]
			if err := a.ali.StopInstance(ctx, srv, act.StopMode); err != nil {
				a.store.AddEvent("error", srv.Name, "停机失败", err.Error())
			} else {
				a.store.AddEvent("warn", srv.Name, "自动停机", act.Reason)
				a.notifier.Send(ctx, snap.Notify, "CDT 智能轮换 · 自动停机", srv.Name+": "+act.Reason)
				_ = a.store.Update(func(st *domain.AppState) error {
					for i := range st.Servers {
						if st.Servers[i].ID == srv.ID {
							st.Servers[i].Status = domain.StatusStopping
						}
					}
					return nil
				})
			}
		case "lock":
			until := policy.NextBillingCycleReset(now, snap.Pool.Timezone).Format(time.RFC3339)
			srv := serverMap[act.ServerID]
			_ = a.store.Update(func(st *domain.AppState) error {
				for i := range st.Servers {
					if st.Servers[i].ID == srv.ID {
						st.Servers[i].LockedUntil = until
						st.Servers[i].LockReason = act.Reason
					}
				}
				return nil
			})
			a.store.AddEvent("warn", srv.Name, "本月熔断锁定", fmt.Sprintf("原因: %s，解锁时间: %s", act.Reason, until))
		case "notify":
			a.store.AddEvent("warn", "轮换池", "全池告警", act.Reason)
			a.notifier.Send(ctx, snap.Notify, "CDT 智能轮换 · 全池告警", act.Reason)
		}
	}

	if dec.ResetSliceTracking && dec.TargetServerID != 0 {
		srv := serverMap[dec.TargetServerID]
		_ = a.store.Update(func(st *domain.AppState) error {
			st.Pool.CurrentServerID = dec.TargetServerID
			st.Pool.CurrentSliceStartedAt = now
			st.Pool.CurrentSliceStartTrafficGB = srv.UsedTrafficGB
			return nil
		})
	}
}

// --- HTTP Handlers ---

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(web.IndexHTML)
}

func (a *App) handleGetState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, a.store.SnapshotMasked())
}

func (a *App) handleSavePool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req domain.PoolConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	applyAll := r.URL.Query().Get("sync_limits") == "1"
	err := a.store.Update(func(st *domain.AppState) error {
		req.CurrentServerID = st.Pool.CurrentServerID
		req.CurrentSliceStartedAt = st.Pool.CurrentSliceStartedAt
		req.CurrentSliceStartTrafficGB = st.Pool.CurrentSliceStartTrafficGB
		if req.Timezone == "" {
			req.Timezone = "Asia/Shanghai"
		}
		if req.StopMode == "" {
			req.StopMode = domain.StopModeStopCharging
		}
		if req.PollIntervalMinutes < 1 {
			req.PollIntervalMinutes = 5
		}
		st.Pool = req
		if applyAll {
			for i := range st.Servers {
				st.Servers[i].MaxTrafficGB = req.DefaultMaxTrafficGB
				st.Servers[i].MaxCostUSD = req.DefaultMaxCostUSD
			}
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.store.AddEvent("info", "轮换池", "更新策略", fmt.Sprintf("模式=%s，使用时段=%02d:00-%02d:00，高峰=%02d:00-%02d:00", req.Strategy, req.ActiveStartHour, req.ActiveEndHour, req.PeakStartHour, req.PeakEndHour))
	writeJSON(w, http.StatusOK, a.store.SnapshotMasked())
}

func (a *App) handleSaveNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req domain.NotifyConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_ = a.store.Update(func(st *domain.AppState) error {
		if req.TelegramBotToken == "********" || req.TelegramBotToken == "" {
			req.TelegramBotToken = st.Notify.TelegramBotToken
		}
		req.LastWeeklyReportDate = st.Notify.LastWeeklyReportDate
		st.Notify = req
		return nil
	})
	a.store.AddEvent("info", "系统", "保存通知设置", "已更新通知配置")
	writeJSON(w, http.StatusOK, a.store.SnapshotMasked())
}

// handleTestNotify sends a real test message using current (even unsaved) form settings.
func (a *App) handleTestNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req domain.NotifyConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	snap := a.store.SnapshotRaw()
	if req.TelegramBotToken == "********" || req.TelegramBotToken == "" {
		req.TelegramBotToken = snap.Notify.TelegramBotToken
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	sent, err := a.notifier.SendSync(ctx, req, "CDT Smart Monitor 测试通知", "如果你收到这条消息，说明通知渠道配置正常！时间: "+time.Now().Format("2006-01-02 15:04:05"))
	if err != nil {
		a.store.AddEvent("error", "通知测试", "发送失败", err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	msg := "测试消息已成功发送至: " + strings.Join(sent, ", ")
	a.store.AddEvent("info", "通知测试", "发送成功", msg)
	writeJSON(w, http.StatusOK, map[string]string{"message": msg})
}

func (a *App) handleServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req domain.Server
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.InstanceID) == "" || strings.TrimSpace(req.Region) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "节点名称、地域和实例ID不能为空"})
		return
	}
	var newID int64
	err := a.store.Update(func(st *domain.AppState) error {
		req.ID = st.NextServerID
		newID = req.ID
		st.NextServerID++
		if req.Site == "" {
			req.Site = domain.SiteIntl
		}
		if req.MaxTrafficGB <= 0 {
			req.MaxTrafficGB = st.Pool.DefaultMaxTrafficGB
		}
		if req.MaxCostUSD <= 0 {
			req.MaxCostUSD = st.Pool.DefaultMaxCostUSD
		}
		if req.Priority <= 0 {
			req.Priority = int(req.ID) * 10
		}
		req.InPool = true
		req.Status = domain.StatusUnknown
		st.Servers = append(st.Servers, req)
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.store.AddEvent("info", req.Name, "添加服务器", fmt.Sprintf("地域=%s，上限=%.0fGB/$%.2f，保活=%v", req.Region, req.MaxTrafficGB, req.MaxCostUSD, req.KeepAlive))
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = a.syncOneServer(ctx, newID)
	}()
	writeJSON(w, http.StatusCreated, a.store.SnapshotMasked())
}

func (a *App) handleServerAction(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/servers/")
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) == 0 {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid server id"})
		return
	}

	if r.Method == http.MethodPut && len(parts) == 1 {
		var req domain.Server
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var updatedName string
		err := a.store.Update(func(st *domain.AppState) error {
			for i := range st.Servers {
				if st.Servers[i].ID == id {
					if strings.TrimSpace(req.Name) != "" {
						st.Servers[i].Name = strings.TrimSpace(req.Name)
					}
					if req.Site != "" {
						st.Servers[i].Site = req.Site
					}
					if strings.TrimSpace(req.Region) != "" {
						st.Servers[i].Region = strings.TrimSpace(req.Region)
					}
					if strings.TrimSpace(req.InstanceID) != "" {
						st.Servers[i].InstanceID = strings.TrimSpace(req.InstanceID)
					}
					if strings.TrimSpace(req.AccessKeyID) != "" {
						st.Servers[i].AccessKeyID = strings.TrimSpace(req.AccessKeyID)
					}
					if req.AccessKeySecret != "" && req.AccessKeySecret != "********" {
						st.Servers[i].AccessKeySecret = req.AccessKeySecret
					}
					if req.MaxTrafficGB > 0 {
						st.Servers[i].MaxTrafficGB = req.MaxTrafficGB
					}
					if req.MaxCostUSD > 0 {
						st.Servers[i].MaxCostUSD = req.MaxCostUSD
					}
					if req.Priority > 0 {
						st.Servers[i].Priority = req.Priority
					}
					st.Servers[i].KeepAlive = req.KeepAlive
					updatedName = st.Servers[i].Name
					return nil
				}
			}
			return fmt.Errorf("server not found")
		})
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		a.store.AddEvent("info", updatedName, "更新节点配置", "已保存节点参数与凭据")
		writeJSON(w, http.StatusOK, a.store.SnapshotMasked())
		return
	}

	if r.Method == http.MethodDelete && len(parts) == 1 {
		_ = a.store.Update(func(st *domain.AppState) error {
			out := make([]domain.Server, 0, len(st.Servers))
			for _, s := range st.Servers {
				if s.ID != id {
					out = append(out, s)
				}
			}
			st.Servers = out
			if st.Pool.CurrentServerID == id {
				st.Pool.CurrentServerID = 0
			}
			return nil
		})
		a.store.AddEvent("info", fmt.Sprintf("#%d", id), "移除服务器", "已从轮换池移出")
		writeJSON(w, http.StatusOK, a.store.SnapshotMasked())
		return
	}

	if len(parts) != 2 || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	action := parts[1]
	snap := a.store.SnapshotRaw()
	var srv *domain.Server
	for i := range snap.Servers {
		if snap.Servers[i].ID == id {
			cp := snap.Servers[i]
			srv = &cp
			break
		}
	}
	if srv == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	switch action {
	case "start":
		if err := a.ali.StartInstance(ctx, *srv); err != nil {
			a.store.AddEvent("error", srv.Name, "手动开机失败", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		a.store.AddEvent("info", srv.Name, "手动开机", "已下发 StartInstance")
	case "stop":
		if err := a.ali.StopInstance(ctx, *srv, snap.Pool.StopMode); err != nil {
			a.store.AddEvent("error", srv.Name, "手动停机失败", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		a.store.AddEvent("info", srv.Name, "手动节省停机", "已下发 StopInstance ("+snap.Pool.StopMode+")")
	case "refresh":
		if err := a.syncOneServer(ctx, id); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		a.evaluateAndExecutePool(ctx, time.Now())
		a.store.AddEvent("info", srv.Name, "手动刷新", "已完成状态、流量与账单同步")
	case "unlock":
		_ = a.store.Update(func(st *domain.AppState) error {
			for i := range st.Servers {
				if st.Servers[i].ID == id {
					st.Servers[i].LockedUntil = ""
					st.Servers[i].LockReason = ""
					st.Servers[i].KeepAliveFails = 0
				}
			}
			return nil
		})
		a.store.AddEvent("info", srv.Name, "手动解锁", "已清除本月熔断锁定")
	case "toggle-keepalive":
		var newVal bool
		_ = a.store.Update(func(st *domain.AppState) error {
			for i := range st.Servers {
				if st.Servers[i].ID == id {
					st.Servers[i].KeepAlive = !st.Servers[i].KeepAlive
					st.Servers[i].KeepAliveFails = 0
					newVal = st.Servers[i].KeepAlive
				}
			}
			return nil
		})
		a.store.AddEvent("info", srv.Name, "切换抢占式保活", fmt.Sprintf("保活状态已设为: %v", newVal))
	default:
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, a.store.SnapshotMasked())
}

func (a *App) handleRefreshAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		a.syncAllServers(ctx)
		a.evaluateAndExecutePool(ctx, time.Now())
	}()
	a.store.AddEvent("info", "轮换池", "全局刷新", "已触发全池状态同步与策略评估")
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "refreshing"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// --- Auth & Passkey Handlers ---

func (a *App) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := a.store.SnapshotRaw()
		if snap.Auth.PasswordHash == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "请先完成首次管理员密码初始化"})
			return
		}
		if !a.auth.IsAuthenticated(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "请先登录"})
			return
		}
		next(w, r)
	}
}

func (a *App) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	snap := a.store.SnapshotRaw()
	writeJSON(w, http.StatusOK, map[string]any{
		"initialized":   snap.Auth.PasswordHash != "",
		"authenticated": snap.Auth.PasswordHash != "" && a.auth.IsAuthenticated(r),
		"has_passkeys":  len(snap.Auth.Passkeys) > 0,
		"is_https":      auth.IsHTTPS(r),
		"rp_id":         auth.RequestRPID(r),
	})
}

func (a *App) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := a.store.SnapshotRaw()
	if snap.Auth.PasswordHash != "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "管理员密码已初始化，请直接登录"})
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.store.Update(func(st *domain.AppState) error {
		st.Auth.PasswordHash = hash
		return nil
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.auth.CreateSession(w, r)
	a.store.AddEvent("info", "安全", "初始化密码", "已完成首次管理员密码设置")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := auth.ClientIP(r)
	if err := a.auth.CheckRateLimit(ip); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	snap := a.store.SnapshotRaw()
	if snap.Auth.PasswordHash == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "尚未初始化密码"})
		return
	}
	if !auth.VerifyPassword(req.Password, snap.Auth.PasswordHash) {
		a.auth.RecordFailure(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "管理员密码错误"})
		return
	}
	a.auth.ClearFailures(ip)
	a.auth.CreateSession(w, r)
	a.store.AddEvent("info", "安全", "密码登录", "来源 IP: "+ip)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	a.auth.DestroySession(w, r)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	snap := a.store.SnapshotRaw()
	if !auth.VerifyPassword(req.OldPassword, snap.Auth.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "原密码不正确"})
		return
	}
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_ = a.store.Update(func(st *domain.AppState) error {
		st.Auth.PasswordHash = newHash
		return nil
	})
	a.store.AddEvent("info", "安全", "修改密码", "管理员密码已更新")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rpID := auth.RequestRPID(r)
	ch, err := a.auth.NewChallenge(rpID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	snap := a.store.SnapshotRaw()
	exclude := make([]string, 0, len(snap.Auth.Passkeys))
	for _, pk := range snap.Auth.Passkeys {
		exclude = append(exclude, pk.ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":   ch,
		"rp_id":       rpID,
		"rp_name":     "CDT Smart Monitor",
		"exclude_ids": exclude,
	})
}

func (a *App) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		ClientDataB64 string `json:"client_data_b64"`
		AuthDataB64   string `json:"auth_data_b64"`
		PublicKeyB64  string `json:"public_key_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	cred, err := a.auth.VerifyPasskeyRegistration(req.ID, req.Name, req.ClientDataB64, req.AuthDataB64, req.PublicKeyB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_ = a.store.Update(func(st *domain.AppState) error {
		st.Auth.Passkeys = append(st.Auth.Passkeys, cred)
		return nil
	})
	a.store.AddEvent("info", "安全", "绑定 Passkey", "已新增通行密钥: "+cred.Name)
	writeJSON(w, http.StatusOK, a.store.SnapshotMasked())
}

func (a *App) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_ = a.store.Update(func(st *domain.AppState) error {
		out := make([]domain.PasskeyCredential, 0, len(st.Auth.Passkeys))
		for _, pk := range st.Auth.Passkeys {
			if pk.ID != req.ID {
				out = append(out, pk)
			}
		}
		st.Auth.Passkeys = out
		return nil
	})
	a.store.AddEvent("info", "安全", "移除 Passkey", "已删除指定通行密钥")
	writeJSON(w, http.StatusOK, a.store.SnapshotMasked())
}

func (a *App) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := a.store.SnapshotRaw()
	if len(snap.Auth.Passkeys) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "尚未绑定任何 Passkey"})
		return
	}
	rpID := auth.RequestRPID(r)
	ch, err := a.auth.NewChallenge(rpID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	allow := make([]string, 0, len(snap.Auth.Passkeys))
	for _, pk := range snap.Auth.Passkeys {
		allow = append(allow, pk.ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge": ch,
		"rp_id":     rpID,
		"allow_ids": allow,
	})
}

func (a *App) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := auth.ClientIP(r)
	if err := a.auth.CheckRateLimit(ip); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		return
	}
	var req struct {
		ID            string `json:"id"`
		ClientDataB64 string `json:"client_data_b64"`
		AuthDataB64   string `json:"auth_data_b64"`
		SignatureB64  string `json:"signature_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	snap := a.store.SnapshotRaw()
	pkName, newCount, err := a.auth.VerifyPasskeyAssertion(snap.Auth.Passkeys, req.ID, req.ClientDataB64, req.AuthDataB64, req.SignatureB64)
	if err != nil {
		a.auth.RecordFailure(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	_ = a.store.Update(func(st *domain.AppState) error {
		for i := range st.Auth.Passkeys {
			if st.Auth.Passkeys[i].ID == req.ID {
				st.Auth.Passkeys[i].SignCount = newCount
			}
		}
		return nil
	})
	a.auth.ClearFailures(ip)
	a.auth.CreateSession(w, r)
	a.store.AddEvent("info", "安全", "Passkey 登录", fmt.Sprintf("密钥 %s（IP: %s）", pkName, ip))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Weekly Monday 08:00 Report ---

func (a *App) buildWeeklyReport(snap domain.AppState, localNow time.Time) (string, string) {
	title := fmt.Sprintf("CDT Smart Monitor 周报 (%s)", localNow.Format("2006-01-02"))
	var b strings.Builder
	var totalGB, totalUSD float64
	dutyName := "无"
	for _, s := range snap.Servers {
		totalGB += s.UsedTrafficGB
		totalUSD += s.BilledCostUSD
		if s.ID == snap.Pool.CurrentServerID {
			dutyName = s.Name
		}
	}
	fmt.Fprintf(&b, "总流量: %.2f GB | 总费用: $%.3f | 当前当班: %s\n", totalGB, totalUSD, dutyName)
	for _, s := range snap.Servers {
		icon := "⚪"
		if s.LockedUntil != "" {
			icon = "🔴"
		} else if s.Status == domain.StatusRunning {
			icon = "🟢"
		}
		fmt.Fprintf(&b, "%s %s (%s): %.2f/%.0f GB | $%.3f/$%.2f\n",
			icon, s.Name, s.Status, s.UsedTrafficGB, s.MaxTrafficGB, s.BilledCostUSD, s.MaxCostUSD)
	}
	if len(snap.Servers) == 0 {
		b.WriteString("当前轮换池暂无服务器。")
	}
	return title, strings.TrimSpace(b.String())
}

func (a *App) maybeSendWeeklyReport(ctx context.Context, now time.Time) {
	snap := a.store.SnapshotRaw()
	if !snap.Notify.WeeklyReportEnabled {
		return
	}
	loc, err := time.LoadLocation(snap.Pool.Timezone)
	if err != nil {
		loc = time.UTC
	}
	localNow := now.In(loc)
	// Every Monday at 08:00 (08:00..08:09 window, sent once per date)
	if localNow.Weekday() != time.Monday || localNow.Hour() != 8 || localNow.Minute() > 9 {
		return
	}
	today := localNow.Format("2006-01-02")
	if snap.Notify.LastWeeklyReportDate == today {
		return
	}
	title, body := a.buildWeeklyReport(snap, localNow)
	a.notifier.Send(ctx, snap.Notify, title, body)
	_ = a.store.Update(func(st *domain.AppState) error {
		st.Notify.LastWeeklyReportDate = today
		return nil
	})
	a.store.AddEvent("info", "周报推送", "周一 08:00 周报", "已推送每周流量与费用汇总")
}

func (a *App) handleTestWeeklyReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req domain.NotifyConfig
	_ = json.NewDecoder(r.Body).Decode(&req)
	snap := a.store.SnapshotRaw()
	if req.TelegramBotToken == "********" || req.TelegramBotToken == "" {
		req.TelegramBotToken = snap.Notify.TelegramBotToken
	}
	loc, err := time.LoadLocation(snap.Pool.Timezone)
	if err != nil {
		loc = time.UTC
	}
	title, body := a.buildWeeklyReport(snap, time.Now().In(loc))
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	sent, err := a.notifier.SendSync(ctx, req, title, body)
	if err != nil {
		a.store.AddEvent("error", "周报推送", "手动发送失败", err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	msg := "周报已立即发送至: " + strings.Join(sent, ", ")
	a.store.AddEvent("info", "周报推送", "手动发送成功", msg)
	writeJSON(w, http.StatusOK, map[string]string{"message": msg})
}
