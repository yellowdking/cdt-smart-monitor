package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

const (
	maxJSONBodyBytes         = 1 << 20 // 1 MiB
	allExhaustedAlertBackoff = 6 * time.Hour
	maxConcurrentServerSyncs = 4
	schedulerTickTimeout     = 90 * time.Second
	schedulerSyncTimeout     = 60 * time.Second
	rolloverGraceWindow      = 24 * time.Hour
	passkeyBeginWindow       = time.Minute
	passkeyBeginMaxPerMin    = 20
	passkeyBeginMaxTracked   = 1024
)

var (
	errAlreadyInitialized = errors.New("already initialized")
	errNotFound           = errors.New("not found")
	errDuplicatePasskey   = errors.New("duplicate passkey")
	errNoopUpdate         = errors.New("noop")

	regionPattern     = regexp.MustCompile(`^[a-z0-9-]+$`)
	instanceIDPattern = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
)

type serverSyncMeta struct {
	hasCDTBaseline bool
	hasBSSBaseline bool
	syncedOnce     bool
	lastFreshSync  time.Time
	lastCDTOk      bool
	lastBSSOk      bool
}

type passkeyBeginRate struct {
	count     int
	windowEnd time.Time
}

type App struct {
	store              *store.Store
	auth               *auth.Manager
	ali                *aliyun.Client
	notifier           *notify.Notifier
	logger             *slog.Logger
	syncSem            chan struct{}
	refreshAllInFlight atomic.Bool

	metaMu       sync.Mutex
	syncMeta     map[int64]serverSyncMeta
	pkRateMu     sync.Mutex
	pkBeginRates map[string]passkeyBeginRate
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "run HTTP healthcheck against local server and exit")
	flag.Parse()

	listen := envOr("CDT_LISTEN", ":8080")
	if *healthcheck {
		os.Exit(runHealthcheck(listen))
	}

	dataDir := envOr("CDT_DATA_DIR", "./data")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	st, err := store.Open(dataDir)
	if err != nil {
		logger.Error("failed to open store", "err", err)
		os.Exit(1)
	}

	app := &App{
		store:        st,
		auth:         auth.NewManager(),
		ali:          aliyun.NewClient(),
		notifier:     notify.NewWithLogger(logger),
		logger:       logger,
		syncSem:      make(chan struct{}, 1),
		syncMeta:     make(map[int64]serverSyncMeta),
		pkBeginRates: make(map[string]passkeyBeginRate),
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
	mux.HandleFunc("/api/v1/pool/manual", app.requireAuth(app.handlePoolManual))
	mux.HandleFunc("/api/v1/pool/schedule", app.requireAuth(app.handlePoolSchedule))
	mux.HandleFunc("/api/v1/notify", app.requireAuth(app.handleSaveNotify))
	mux.HandleFunc("/api/v1/notify/test", app.requireAuth(app.handleTestNotify))
	mux.HandleFunc("/api/v1/notify/weekly-test", app.requireAuth(app.handleTestWeeklyReport))
	mux.HandleFunc("/api/v1/servers", app.requireAuth(app.handleServers))
	mux.HandleFunc("/api/v1/servers/", app.requireAuth(app.handleServerAction))
	mux.HandleFunc("/api/v1/refresh-all", app.requireAuth(app.handleRefreshAll))

	srv := &http.Server{
		Addr:              listen,
		Handler:           securityHeadersMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go app.runScheduler(ctx)

	srvErrCh := make(chan error, 1)
	go func() {
		logger.Info("CDT Smart Monitor listening", "addr", listen, "data_dir", dataDir)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErrCh <- err
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	select {
	case err := <-srvErrCh:
		logger.Error("http server error", "err", err)
		os.Exit(1)
	default:
	}
	logger.Info("CDT Smart Monitor stopped gracefully")
}

func runHealthcheck(listen string) int {
	_, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		port = strings.TrimPrefix(listen, ":")
	}
	if port == "" {
		port = "8080"
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'")
		if auth.IsHTTPS(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) acquireSync(ctx context.Context) bool {
	select {
	case a.syncSem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (a *App) releaseSync() {
	<-a.syncSem
}

func (a *App) deleteSyncMeta(id int64) {
	a.metaMu.Lock()
	delete(a.syncMeta, id)
	a.metaMu.Unlock()
}

func (a *App) allowPasskeyBegin(ip string) bool {
	now := time.Now()
	a.pkRateMu.Lock()
	defer a.pkRateMu.Unlock()
	if a.pkBeginRates == nil {
		a.pkBeginRates = make(map[string]passkeyBeginRate)
	}
	if len(a.pkBeginRates) >= passkeyBeginMaxTracked {
		for k, v := range a.pkBeginRates {
			if now.After(v.windowEnd) {
				delete(a.pkBeginRates, k)
			}
		}
		if len(a.pkBeginRates) >= passkeyBeginMaxTracked {
			if _, exists := a.pkBeginRates[ip]; !exists {
				return false
			}
		}
	}
	ent, ok := a.pkBeginRates[ip]
	if !ok || now.After(ent.windowEnd) {
		a.pkBeginRates[ip] = passkeyBeginRate{count: 1, windowEnd: now.Add(passkeyBeginWindow)}
		return true
	}
	if ent.count >= passkeyBeginMaxPerMin {
		return false
	}
	ent.count++
	a.pkBeginRates[ip] = ent
	return true
}

func parseLockTime(s domain.Server) (time.Time, bool) {
	if s.LockedUntil == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s.LockedUntil)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func hasExpiredLocks(servers []domain.Server, now time.Time) bool {
	for _, s := range servers {
		if s.LockedUntil != "" && !policy.IsLockActive(s, now) {
			return true
		}
	}
	return false
}

func hasUnpolledExpiredLock(servers []domain.Server, now, lastPoll time.Time) bool {
	for _, s := range servers {
		if s.LockedUntil != "" && !policy.IsLockActive(s, now) {
			lockTime, ok := parseLockTime(s)
			if !ok || lastPoll.IsZero() || lastPoll.Before(lockTime) {
				return true
			}
		}
	}
	return false
}

func (a *App) runScheduler(ctx context.Context) {
	// Run an initial sync shortly after startup so metrics are populated promptly.
	bootTimer := time.NewTimer(5 * time.Second)
	defer bootTimer.Stop()

	var lastPoll time.Time
	select {
	case <-ctx.Done():
		return
	case now := <-bootTimer.C:
		a.runSchedulerTick(ctx, now, &lastPoll, true)
	}

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			a.runSchedulerTick(ctx, now, &lastPoll, false)
		}
	}
}

func (a *App) runSchedulerTick(parentCtx context.Context, now time.Time, lastPoll *time.Time, forceSync bool) {
	tickCtx, cancel := context.WithTimeout(parentCtx, schedulerTickTimeout)
	defer cancel()

	snap := a.store.SnapshotRaw()
	interval := time.Duration(snap.Pool.PollIntervalMinutes) * time.Minute
	if interval < time.Minute {
		interval = 5 * time.Minute
	}
	needPoll := forceSync || lastPoll.IsZero() || now.Sub(*lastPoll) >= interval
	if !needPoll && hasUnpolledExpiredLock(snap.Servers, now, *lastPoll) {
		needPoll = true
	}
	if a.syncAndEvaluate(tickCtx, now, needPoll) && needPoll {
		*lastPoll = now
	}
	a.maybeSendWeeklyReport(tickCtx, now)
}

func (a *App) syncAndEvaluate(ctx context.Context, now time.Time, doSync bool) bool {
	if !a.acquireSync(ctx) {
		return false
	}
	defer a.releaseSync()

	if doSync {
		syncCtx, syncCancel := context.WithTimeout(ctx, schedulerSyncTimeout)
		a.syncAllServersLocked(syncCtx)
		syncCancel()
	}
	a.evaluateAndExecutePoolLocked(ctx, now, doSync)
	return true
}

func (a *App) syncAllServers(ctx context.Context) {
	if !a.acquireSync(ctx) {
		return
	}
	defer a.releaseSync()
	a.syncAllServersLocked(ctx)
}

func (a *App) syncAllServersLocked(ctx context.Context) {
	snap := a.store.SnapshotRaw()
	if len(snap.Servers) == 0 {
		return
	}
	sem := make(chan struct{}, maxConcurrentServerSyncs)
	var wg sync.WaitGroup
	for _, srv := range snap.Servers {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			_ = a.syncOneServerNoLock(ctx, id)
		}(srv.ID)
	}
	wg.Wait()
}

func (a *App) syncOneServer(ctx context.Context, id int64) error {
	if !a.acquireSync(ctx) {
		return ctx.Err()
	}
	defer a.releaseSync()
	return a.syncOneServerNoLock(ctx, id)
}

func (a *App) syncOneServerNoLock(ctx context.Context, id int64) error {
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
	var (
		inst      aliyun.InstanceSnapshot
		ecsErr    error
		trafficGB float64
		cdtErr    error
		costUSD   float64
		bssErr    error
		wg        sync.WaitGroup
	)
	wg.Add(3)
	go func() {
		defer wg.Done()
		inst, ecsErr = a.ali.DescribeInstance(ctx, *target)
	}()
	go func() {
		defer wg.Done()
		trafficGB, cdtErr = a.ali.GetCDTTrafficGB(ctx, *target)
	}()
	go func() {
		defer wg.Done()
		costUSD, bssErr = a.ali.GetMonthlyBillUSD(ctx, *target, now, snap.Pool.Timezone)
	}()
	wg.Wait()

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

	a.metaMu.Lock()
	prevMeta := a.syncMeta[id]
	a.metaMu.Unlock()

	syncTime := now
	if loc, err := time.LoadLocation(snap.Pool.Timezone); err == nil {
		syncTime = now.In(loc)
	}

	nextMeta := prevMeta
	nextMeta.syncedOnce = true
	nextMeta.lastFreshSync = now
	nextMeta.lastCDTOk = (cdtErr == nil)
	nextMeta.lastBSSOk = (bssErr == nil)

	err := a.store.Update(func(st *domain.AppState) error {
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
					hadCDTBaseline := prevMeta.hasCDTBaseline || (!prevMeta.syncedOnce && st.Servers[i].LastSyncAt != "" && !strings.Contains(st.Servers[i].LastError, "CDT:"))
					if !hadCDTBaseline {
						st.Servers[i].PrevTrafficGB = trafficGB
					} else {
						st.Servers[i].PrevTrafficGB = st.Servers[i].UsedTrafficGB
					}
					st.Servers[i].UsedTrafficGB = trafficGB
					nextMeta.hasCDTBaseline = true
				}
				if bssErr == nil {
					hadBSSBaseline := prevMeta.hasBSSBaseline || (!prevMeta.syncedOnce && st.Servers[i].LastSyncAt != "" && !strings.Contains(st.Servers[i].LastError, "BSS:"))
					if !hadBSSBaseline {
						st.Servers[i].PrevCostUSD = costUSD
					} else {
						st.Servers[i].PrevCostUSD = st.Servers[i].BilledCostUSD
					}
					st.Servers[i].BilledCostUSD = costUSD
					nextMeta.hasBSSBaseline = true
				}
				st.Servers[i].LastSyncAt = syncTime.Format("2006-01-02 15:04:05")
				st.Servers[i].LastError = strings.Join(errs, " | ")
				break
			}
		}
		return nil
	})
	if err == nil {
		a.metaMu.Lock()
		a.syncMeta[id] = nextMeta
		a.metaMu.Unlock()
	}
	return err
}

func (a *App) clearExpiredLocksLocked(now time.Time) map[int64]bool {
	pending := make(map[int64]bool)

	a.metaMu.Lock()
	metaSnap := make(map[int64]serverSyncMeta, len(a.syncMeta))
	for k, v := range a.syncMeta {
		metaSnap[k] = v
	}
	a.metaMu.Unlock()

	_ = a.store.Update(func(st *domain.AppState) error {
		changed := false
		for i := range st.Servers {
			srv := st.Servers[i]
			if srv.LockedUntil == "" || policy.IsLockActive(srv, now) {
				continue
			}
			lockTime, validLockTime := parseLockTime(srv)
			meta := metaSnap[srv.ID]

			// Only unlock after a fresh sync at/after lock expiry succeeded for BOTH CDT and BSS.
			freshOK := meta.lastCDTOk && meta.lastBSSOk && (!validLockTime || !meta.lastFreshSync.Before(lockTime))
			if !freshOK {
				pending[srv.ID] = true
				continue
			}

			// Verify metrics have actually rolled over below cutoff before unlocking.
			probe := srv
			probe.LockedUntil = ""
			probe.LockReason = ""
			if policy.EvaluateServer(probe, now).ShouldCutoff {
				// Aliyun CDT/BSS counter may lag right after 00:05; keep waiting on subsequent polls
				// during the grace window rather than immediately re-locking for 31 days.
				if !validLockTime || now.Sub(lockTime) < rolloverGraceWindow {
					pending[srv.ID] = true
				}
				continue
			}

			st.Servers[i].LockedUntil = ""
			st.Servers[i].LockReason = ""
			st.Servers[i].KeepAliveFails = 0
			st.Servers[i].PrevTrafficGB = st.Servers[i].UsedTrafficGB
			st.Servers[i].PrevCostUSD = st.Servers[i].BilledCostUSD
			store.AppendEvent(st, "info", srv.Name, "新账期自动解锁", "熔断锁定已到期，新账期指标已复位，已重新恢复入池参与轮换")
			changed = true
		}
		if !changed {
			return errNoopUpdate
		}
		return nil
	})
	return pending
}

func (a *App) evaluateAndExecutePool(ctx context.Context, now time.Time) {
	if !a.acquireSync(ctx) {
		return
	}
	defer a.releaseSync()
	a.evaluateAndExecutePoolLocked(ctx, now, false)
}

func (a *App) evaluateAndExecutePoolLocked(ctx context.Context, now time.Time, alreadySynced bool) {
	snap := a.store.SnapshotRaw()

	// If any server has an expired lock and wasn't freshly synced after expiry, force a fresh sync first.
	if !alreadySynced && hasExpiredLocks(snap.Servers, now) {
		needFreshSync := false
		a.metaMu.Lock()
		for _, s := range snap.Servers {
			if s.LockedUntil != "" && !policy.IsLockActive(s, now) {
				lockTime, ok := parseLockTime(s)
				meta := a.syncMeta[s.ID]
				if !ok || meta.lastFreshSync.Before(lockTime) || !meta.lastCDTOk || !meta.lastBSSOk {
					needFreshSync = true
					break
				}
			}
		}
		a.metaMu.Unlock()
		if needFreshSync {
			syncCtx, syncCancel := context.WithTimeout(ctx, schedulerSyncTimeout)
			a.syncAllServersLocked(syncCtx)
			syncCancel()
		}
	}

	pendingRollover := a.clearExpiredLocksLocked(now)

	snap = a.store.SnapshotRaw()
	evalServers := snap.Servers
	if len(pendingRollover) > 0 {
		evalServers = make([]domain.Server, len(snap.Servers))
		copy(evalServers, snap.Servers)
		holdUntil := now.Add(time.Hour).Format(time.RFC3339)
		for i := range evalServers {
			if pendingRollover[evalServers[i].ID] {
				evalServers[i].LockedUntil = holdUntil
			}
		}
	}

	dec := policy.EvaluatePool(snap.Pool, evalServers, now)

	serverMap := make(map[int64]domain.Server, len(snap.Servers))
	for _, s := range snap.Servers {
		serverMap[s.ID] = s
	}

	if dec.Phase != "all_exhausted" && !snap.Pool.LastAllExhaustedAlertAt.IsZero() {
		_ = a.store.Update(func(st *domain.AppState) error {
			st.Pool.LastAllExhaustedAlertAt = time.Time{}
			return nil
		})
	}

	for _, act := range dec.Actions {
		switch act.Type {
		case "start":
			srv := serverMap[act.ServerID]
			if err := a.ali.StartInstance(ctx, srv); err != nil {
				_ = a.store.Update(func(st *domain.AppState) error {
					for i := range st.Servers {
						if st.Servers[i].ID == srv.ID {
							st.Servers[i].KeepAliveFails++
						}
					}
					store.AppendEvent(st, "error", srv.Name, "开机/保活失败", err.Error())
					return nil
				})
			} else {
				a.notifier.Send(ctx, snap.Notify, "CDT 智能轮换 · 自动开机", srv.Name+": "+act.Reason)
				_ = a.store.Update(func(st *domain.AppState) error {
					for i := range st.Servers {
						if st.Servers[i].ID == srv.ID {
							st.Servers[i].Status = domain.StatusStarting
							st.Servers[i].LastActiveAt = now
							st.Servers[i].KeepAliveFails = 0
						}
					}
					store.AppendEvent(st, "info", srv.Name, "自动开机", act.Reason)
					return nil
				})
			}
		case "stop":
			srv := serverMap[act.ServerID]
			if err := a.ali.StopInstance(ctx, srv, act.StopMode); err != nil {
				a.store.AddEvent("error", srv.Name, "停机失败", err.Error())
			} else {
				a.notifier.Send(ctx, snap.Notify, "CDT 智能轮换 · 自动停机", srv.Name+": "+act.Reason)
				_ = a.store.Update(func(st *domain.AppState) error {
					for i := range st.Servers {
						if st.Servers[i].ID == srv.ID {
							st.Servers[i].Status = domain.StatusStopping
						}
					}
					store.AppendEvent(st, "warn", srv.Name, "自动停机", act.Reason)
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
				store.AppendEvent(st, "warn", srv.Name, "本月熔断锁定", fmt.Sprintf("原因: %s，解锁时间: %s", act.Reason, until))
				return nil
			})
		case "notify":
			if snap.Pool.LastAllExhaustedAlertAt.IsZero() || now.Sub(snap.Pool.LastAllExhaustedAlertAt) >= allExhaustedAlertBackoff {
				a.notifier.Send(ctx, snap.Notify, "CDT 智能轮换 · 全池告警", act.Reason)
				_ = a.store.Update(func(st *domain.AppState) error {
					st.Pool.LastAllExhaustedAlertAt = now
					store.AppendEvent(st, "warn", "轮换池", "全池告警", act.Reason)
					return nil
				})
			}
		}
	}

	if dec.ClearManualSelection || dec.ResetExpiredOverrides || (dec.ResetSliceTracking && dec.TargetServerID != 0) {
		_ = a.store.Update(func(st *domain.AppState) error {
			if dec.ClearManualSelection {
				st.Pool.ManualServerID = 0
				st.Pool.ManualSelectedAt = time.Time{}
				st.Pool.ManualUntil = time.Time{}
				if dec.ClearManualReason != "" {
					store.AppendEvent(st, "info", "轮换池", "自动切回智能排班", dec.ClearManualReason)
				}
			}
			if dec.ResetExpiredOverrides {
				st.Pool.ManualHourlyOverrides = nil
				st.Pool.ManualScheduleDate = ""
				store.AppendEvent(st, "info", "轮换池", "新一日重置排班", "昨日手动排班已自动恢复为智能动态排班")
			}
			if dec.ResetSliceTracking && dec.TargetServerID != 0 {
				srv := serverMap[dec.TargetServerID]
				st.Pool.CurrentServerID = dec.TargetServerID
				st.Pool.CurrentSliceStartedAt = now
				st.Pool.CurrentSliceStartTrafficGB = srv.UsedTrafficGB
				if !dec.PeakOverrideUntil.IsZero() {
					st.Pool.PeakOverrideUntil = dec.PeakOverrideUntil
				} else if !now.Before(st.Pool.PeakOverrideUntil) {
					st.Pool.PeakOverrideUntil = time.Time{}
				}
			}
			return nil
		})
	}
}

// --- HTTP Handlers ---

type stateResponse struct {
	domain.AppState
	Schedule policy.DailySchedule `json:"schedule"`
}

func (a *App) buildStateResponse(now time.Time) stateResponse {
	masked := a.store.SnapshotMasked()
	return stateResponse{
		AppState: masked,
		Schedule: policy.BuildDailySchedule(masked.Pool, masked.Servers, now),
	}
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(web.IndexHTML)
}

func (a *App) handleGetState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, a.buildStateResponse(time.Now()))
}

func (a *App) handleSavePool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req domain.PoolConfig
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Timezone == "" {
		req.Timezone = "Asia/Shanghai"
	}
	if _, err := time.LoadLocation(req.Timezone); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无效的时区: " + req.Timezone})
		return
	}
	if req.ActiveStartHour < 0 || req.ActiveStartHour > 23 || req.ActiveEndHour < 0 || req.ActiveEndHour > 24 ||
		req.PeakStartHour < 0 || req.PeakStartHour > 23 || req.PeakEndHour < 0 || req.PeakEndHour > 24 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "时间段小时数范围无效"})
		return
	}
	if req.PeakMaxSliceGB < 0 || req.DefaultMaxTrafficGB <= 0 || req.DefaultMaxCostUSD <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "流量与金额上限必须大于 0"})
		return
	}
	if req.StopMode != domain.StopModeStopCharging && req.StopMode != domain.StopModeKeepCharging {
		req.StopMode = domain.StopModeStopCharging
	}
	if req.PollIntervalMinutes < 1 {
		req.PollIntervalMinutes = 5
	} else if req.PollIntervalMinutes > 60 {
		req.PollIntervalMinutes = 60
	}
	switch req.Strategy {
	case domain.StrategySmartHybrid, domain.StrategyExhaustSequential, domain.StrategyContinuousRoundRobin:
	default:
		req.Strategy = domain.StrategySmartHybrid
	}
	switch req.ManualAutoRevertMode {
	case domain.ManualRevertNextSlot, domain.ManualRevertDuration, domain.ManualRevertNextDay, domain.ManualRevertNever:
	default:
		req.ManualAutoRevertMode = domain.ManualRevertNextSlot
	}
	if req.ManualAutoRevertMinutes < 15 {
		req.ManualAutoRevertMinutes = 120
	} else if req.ManualAutoRevertMinutes > 1440 {
		req.ManualAutoRevertMinutes = 1440
	}

	applyAll := r.URL.Query().Get("sync_limits") == "1"
	err := a.store.Update(func(st *domain.AppState) error {
		req.CurrentServerID = st.Pool.CurrentServerID
		req.CurrentSliceStartedAt = st.Pool.CurrentSliceStartedAt
		req.CurrentSliceStartTrafficGB = st.Pool.CurrentSliceStartTrafficGB
		req.PeakOverrideUntil = st.Pool.PeakOverrideUntil
		req.LastAllExhaustedAlertAt = st.Pool.LastAllExhaustedAlertAt
		req.ManualServerID = st.Pool.ManualServerID
		req.ManualSelectedAt = st.Pool.ManualSelectedAt
		req.ManualUntil = st.Pool.ManualUntil
		req.ManualScheduleDate = st.Pool.ManualScheduleDate
		req.ManualHourlyOverrides = st.Pool.ManualHourlyOverrides
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
	a.store.AddEvent("info", "轮换池", "更新策略", fmt.Sprintf("模式=%s，使用时段=%02d:00-%02d:00，高峰=%02d:00-%02d:00，自动切回=%s", req.Strategy, req.ActiveStartHour, req.ActiveEndHour, req.PeakStartHour, req.PeakEndHour, req.ManualAutoRevertMode))
	writeJSON(w, http.StatusOK, a.buildStateResponse(time.Now()))
}

func isValidRevertMode(mode string) bool {
	switch mode {
	case domain.ManualRevertNextSlot, domain.ManualRevertDuration, domain.ManualRevertNextDay, domain.ManualRevertNever:
		return true
	default:
		return false
	}
}

// handlePoolManual implements Mihomo-style instant manual duty selection & one-click return to smart auto-scheduling.
func (a *App) handlePoolManual(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ServerID         int64  `json:"server_id"`
		RevertMode       string `json:"revert_mode"`
		RevertMinutes    int    `json:"revert_minutes"`
		ClearCurrentSlot *bool  `json:"clear_current_slot"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.ServerID < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无效的节点 ID"})
		return
	}
	req.RevertMode = strings.TrimSpace(req.RevertMode)
	if req.RevertMode != "" && !isValidRevertMode(req.RevertMode) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无效的自动切回模式: " + req.RevertMode})
		return
	}

	now := time.Now()
	snap := a.store.SnapshotRaw()
	loc, err := time.LoadLocation(snap.Pool.Timezone)
	if err != nil {
		loc = time.UTC
	}
	curHour := now.In(loc).Hour()

	if req.ServerID == 0 {
		clearSlot := true
		if req.ClearCurrentSlot != nil {
			clearSlot = *req.ClearCurrentSlot
		}
		if err := a.store.Update(func(st *domain.AppState) error {
			st.Pool.ManualServerID = 0
			st.Pool.ManualSelectedAt = time.Time{}
			st.Pool.ManualUntil = time.Time{}
			if req.RevertMode != "" {
				st.Pool.ManualAutoRevertMode = req.RevertMode
			}
			if req.RevertMinutes >= 15 && req.RevertMinutes <= 1440 {
				st.Pool.ManualAutoRevertMinutes = req.RevertMinutes
			}
			if clearSlot && st.Pool.ManualHourlyOverrides != nil {
				delete(st.Pool.ManualHourlyOverrides, curHour)
			}
			return nil
		}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.store.AddEvent("info", "轮换池", "一键切回智能排班", "已解除手动锁定，交回动态均衡排班引擎调度")
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		a.evaluateAndExecutePool(ctx, now)
		writeJSON(w, http.StatusOK, a.buildStateResponse(now))
		return
	}

	var target *domain.Server
	for i := range snap.Servers {
		if snap.Servers[i].ID == req.ServerID {
			cp := snap.Servers[i]
			target = &cp
			break
		}
	}
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "节点不存在"})
		return
	}
	if ev := policy.EvaluateServer(*target, now); ev.ShouldCutoff {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("节点 %s 已触及安全熔断线（%s），请先解锁或调整上限", target.Name, ev.CutoffReason)})
		return
	}

	revertMode := req.RevertMode
	if revertMode == "" {
		revertMode = snap.Pool.ManualAutoRevertMode
	}
	revertMins := req.RevertMinutes
	if revertMins <= 0 {
		revertMins = snap.Pool.ManualAutoRevertMinutes
	}
	until := policy.ComputeManualUntil(snap.Pool, snap.Servers, now, revertMode, revertMins)

	if err := a.store.Update(func(st *domain.AppState) error {
		st.Pool.ManualServerID = target.ID
		st.Pool.ManualSelectedAt = now
		st.Pool.ManualUntil = until
		if revertMode != "" {
			st.Pool.ManualAutoRevertMode = revertMode
		}
		if revertMins >= 15 && revertMins <= 1440 {
			st.Pool.ManualAutoRevertMinutes = revertMins
		}
		return nil
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	desc := fmt.Sprintf("已手动切换至 %s 值班", target.Name)
	if !until.IsZero() {
		desc += fmt.Sprintf("（将于 %s 自动切回智能排班）", until.In(loc).Format("15:04"))
	} else {
		desc += "（持续保持直到一键切回）"
	}
	a.store.AddEvent("info", target.Name, "手动指定当班", desc)

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	a.evaluateAndExecutePool(ctx, now)
	writeJSON(w, http.StatusOK, a.buildStateResponse(now))
}

// handlePoolSchedule allows clicking any hour in the 24h Gantt schedule to override or reset to smart scheduling.
func (a *App) handlePoolSchedule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Hours          []int `json:"hours"`
		ServerID       int64 `json:"server_id"` // 0 = follow auto, -1 = force idle, >0 = pin server
		ResetAll       bool  `json:"reset_all"`
		AutoResetDaily *bool `json:"auto_reset_daily"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.ServerID < domain.ManualSlotForceIdle {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无效的 server_id（必须 >= -1）"})
		return
	}

	now := time.Now()
	snap := a.store.SnapshotRaw()
	loc, err := time.LoadLocation(snap.Pool.Timezone)
	if err != nil {
		loc = time.UTC
	}
	localNow := now.In(loc)
	todayStr := localNow.Format("2006-01-02")
	curHour := localNow.Hour()

	var serverName string
	if req.ServerID > 0 {
		found := false
		for _, s := range snap.Servers {
			if s.ID == req.ServerID {
				found = true
				serverName = s.Name
				break
			}
		}
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "指定节点不存在"})
			return
		}
	}

	affectsCurrent := req.ResetAll
	if err := a.store.Update(func(st *domain.AppState) error {
		if req.AutoResetDaily != nil {
			st.Pool.ManualOverridesAutoResetDaily = *req.AutoResetDaily
		}
		if req.ResetAll {
			st.Pool.ManualHourlyOverrides = nil
			st.Pool.ManualScheduleDate = ""
			st.Pool.ManualServerID = 0
			st.Pool.ManualSelectedAt = time.Time{}
			st.Pool.ManualUntil = time.Time{}
			return nil
		}
		if len(req.Hours) > 0 {
			if st.Pool.ManualOverridesAutoResetDaily && st.Pool.ManualScheduleDate != "" && st.Pool.ManualScheduleDate != todayStr {
				st.Pool.ManualHourlyOverrides = nil
			}
			if st.Pool.ManualHourlyOverrides == nil {
				st.Pool.ManualHourlyOverrides = make(map[int]int64)
			}
			st.Pool.ManualScheduleDate = todayStr
			for _, h := range req.Hours {
				if h < 0 || h > 23 {
					continue
				}
				if h == curHour {
					affectsCurrent = true
					// Editing the current hour's slot overrides any live manual pin cleanly
					st.Pool.ManualServerID = 0
					st.Pool.ManualSelectedAt = time.Time{}
					st.Pool.ManualUntil = time.Time{}
				}
				if req.ServerID == 0 {
					delete(st.Pool.ManualHourlyOverrides, h)
				} else {
					st.Pool.ManualHourlyOverrides[h] = req.ServerID
				}
			}
			if len(st.Pool.ManualHourlyOverrides) == 0 {
				st.Pool.ManualHourlyOverrides = nil
			}
		}
		return nil
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if req.ResetAll {
		a.store.AddEvent("info", "轮换池", "一键恢复智能排班", "已清空全部手动排班覆盖，恢复动态负载均衡排班")
	} else if len(req.Hours) > 0 {
		lbl := "跟随智能排班"
		if req.ServerID == domain.ManualSlotForceIdle {
			lbl = "强制休眠"
		} else if req.ServerID > 0 {
			lbl = "指定 " + serverName
		}
		a.store.AddEvent("info", "排班表", "手动修改排班", fmt.Sprintf("修改 %d 个时段 → %s", len(req.Hours), lbl))
	}

	if affectsCurrent {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		a.evaluateAndExecutePool(ctx, now)
	}
	writeJSON(w, http.StatusOK, a.buildStateResponse(now))
}

func normalizeTelegramAPIBase(base string) string {
	b := strings.TrimRight(strings.TrimSpace(base), "/")
	if b == "" {
		return "https://api.telegram.org"
	}
	return b
}

func resolveTestNotifyConfig(req, saved domain.NotifyConfig) (domain.NotifyConfig, error) {
	req.ProxyURL = strings.TrimSpace(req.ProxyURL)
	req.TelegramAPIBase = strings.TrimSpace(req.TelegramAPIBase)
	req.TelegramBotToken = strings.TrimSpace(req.TelegramBotToken)
	req.TelegramChatID = strings.TrimSpace(req.TelegramChatID)
	req.WebhookURL = strings.TrimSpace(req.WebhookURL)
	if req.TelegramBotToken == "********" {
		if normalizeTelegramAPIBase(req.TelegramAPIBase) != normalizeTelegramAPIBase(saved.TelegramAPIBase) {
			return req, fmt.Errorf("修改 Telegram API 反代地址后测试，请重新输入完整的 Bot Token")
		}
		req.TelegramBotToken = saved.TelegramBotToken
	}
	return req, nil
}

func (a *App) handleSaveNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req domain.NotifyConfig
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	req.ProxyURL = strings.TrimSpace(req.ProxyURL)
	req.TelegramAPIBase = strings.TrimSpace(req.TelegramAPIBase)
	req.TelegramBotToken = strings.TrimSpace(req.TelegramBotToken)
	req.TelegramChatID = strings.TrimSpace(req.TelegramChatID)
	req.WebhookURL = strings.TrimSpace(req.WebhookURL)
	if err := a.store.Update(func(st *domain.AppState) error {
		if req.TelegramBotToken == "********" {
			req.TelegramBotToken = st.Notify.TelegramBotToken
		}
		req.LastWeeklyReportDate = st.Notify.LastWeeklyReportDate
		st.Notify = req
		store.AppendEvent(st, "info", "系统", "保存通知设置", "已更新通知配置")
		return nil
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a.buildStateResponse(time.Now()))
}

// handleTestNotify sends a real test message using current (even unsaved) form settings.
func (a *App) handleTestNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req domain.NotifyConfig
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	snap := a.store.SnapshotRaw()
	req, err := resolveTestNotifyConfig(req, snap.Notify)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
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
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Region = strings.TrimSpace(req.Region)
	req.InstanceID = strings.TrimSpace(req.InstanceID)
	req.AccessKeyID = strings.TrimSpace(req.AccessKeyID)
	req.AccessKeySecret = strings.TrimSpace(req.AccessKeySecret)
	if req.Name == "" || req.InstanceID == "" || req.Region == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "节点名称、地域和实例ID不能为空"})
		return
	}
	if !regionPattern.MatchString(req.Region) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无效的地域格式（仅允许小写字母、数字和连字符）"})
		return
	}
	if !instanceIDPattern.MatchString(req.InstanceID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无效的实例ID格式（仅允许字母、数字和连字符）"})
		return
	}
	var newID int64
	err := a.store.Update(func(st *domain.AppState) error {
		req.ID = st.NextServerID
		newID = req.ID
		st.NextServerID++
		if req.Site != domain.SiteChina {
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
		store.AppendEvent(st, "info", req.Name, "添加服务器", fmt.Sprintf("地域=%s，上限=%.0fGB/$%.2f，保活=%v", req.Region, req.MaxTrafficGB, req.MaxCostUSD, req.KeepAlive))
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = a.syncOneServer(ctx, newID)
	}()
	writeJSON(w, http.StatusCreated, a.buildStateResponse(time.Now()))
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
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.Region = strings.TrimSpace(req.Region)
		req.InstanceID = strings.TrimSpace(req.InstanceID)
		if req.Region != "" && !regionPattern.MatchString(req.Region) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无效的地域格式（仅允许小写字母、数字和连字符）"})
			return
		}
		if req.InstanceID != "" && !instanceIDPattern.MatchString(req.InstanceID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无效的实例ID格式（仅允许字母、数字和连字符）"})
			return
		}
		err := a.store.Update(func(st *domain.AppState) error {
			for i := range st.Servers {
				if st.Servers[i].ID == id {
					if strings.TrimSpace(req.Name) != "" {
						st.Servers[i].Name = strings.TrimSpace(req.Name)
					}
					if req.Site == domain.SiteIntl || req.Site == domain.SiteChina {
						st.Servers[i].Site = req.Site
					}
					if req.Region != "" {
						st.Servers[i].Region = req.Region
					}
					if req.InstanceID != "" {
						st.Servers[i].InstanceID = req.InstanceID
					}
					if strings.TrimSpace(req.AccessKeyID) != "" {
						st.Servers[i].AccessKeyID = strings.TrimSpace(req.AccessKeyID)
					}
					if req.AccessKeySecret != "" && req.AccessKeySecret != "********" {
						st.Servers[i].AccessKeySecret = strings.TrimSpace(req.AccessKeySecret)
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
					store.AppendEvent(st, "info", st.Servers[i].Name, "更新节点配置", "已保存节点参数与凭据")
					return nil
				}
			}
			return errNotFound
		})
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, a.buildStateResponse(time.Now()))
		return
	}

	if r.Method == http.MethodDelete && len(parts) == 1 {
		err := a.store.Update(func(st *domain.AppState) error {
			found := false
			var deletedName string
			out := make([]domain.Server, 0, len(st.Servers))
			for _, s := range st.Servers {
				if s.ID != id {
					out = append(out, s)
				} else {
					found = true
					deletedName = s.Name
				}
			}
			if !found {
				return errNotFound
			}
			st.Servers = out
			if st.Pool.CurrentServerID == id {
				st.Pool.CurrentServerID = 0
			}
			if st.Pool.ManualServerID == id {
				st.Pool.ManualServerID = 0
				st.Pool.ManualSelectedAt = time.Time{}
				st.Pool.ManualUntil = time.Time{}
			}
			for h, sid := range st.Pool.ManualHourlyOverrides {
				if sid == id {
					delete(st.Pool.ManualHourlyOverrides, h)
				}
			}
			if deletedName == "" {
				deletedName = fmt.Sprintf("#%d", id)
			}
			store.AppendEvent(st, "info", deletedName, "移除服务器", "已从轮换池移出")
			return nil
		})
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.deleteSyncMeta(id)
		writeJSON(w, http.StatusOK, a.buildStateResponse(time.Now()))
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
		if !a.acquireSync(ctx) {
			writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "系统正在同步，请稍后重试"})
			return
		}
		startErr := a.ali.StartInstance(ctx, *srv)
		if startErr != nil {
			a.releaseSync()
			a.store.AddEvent("error", srv.Name, "手动开机失败", startErr.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": startErr.Error()})
			return
		}
		updateErr := a.store.Update(func(st *domain.AppState) error {
			for i := range st.Servers {
				if st.Servers[i].ID == id {
					st.Servers[i].Status = domain.StatusStarting
					st.Servers[i].KeepAliveFails = 0
					st.Servers[i].LastActiveAt = time.Now()
					store.AppendEvent(st, "info", srv.Name, "手动开机", "已下发 StartInstance")
					return nil
				}
			}
			return errNotFound
		})
		a.releaseSync()
		if updateErr != nil {
			if errors.Is(updateErr, errNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": updateErr.Error()})
			return
		}
	case "stop":
		if !a.acquireSync(ctx) {
			writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "系统正在同步，请稍后重试"})
			return
		}
		stopErr := a.ali.StopInstance(ctx, *srv, snap.Pool.StopMode)
		if stopErr != nil {
			a.releaseSync()
			a.store.AddEvent("error", srv.Name, "手动停机失败", stopErr.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": stopErr.Error()})
			return
		}
		updateErr := a.store.Update(func(st *domain.AppState) error {
			for i := range st.Servers {
				if st.Servers[i].ID == id {
					st.Servers[i].Status = domain.StatusStopping
					store.AppendEvent(st, "info", srv.Name, "手动节省停机", "已下发 StopInstance ("+snap.Pool.StopMode+")")
					return nil
				}
			}
			return errNotFound
		})
		a.releaseSync()
		if updateErr != nil {
			if errors.Is(updateErr, errNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": updateErr.Error()})
			return
		}
	case "refresh":
		if !a.acquireSync(ctx) {
			writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "系统正在同步，请稍后重试"})
			return
		}
		syncErr := a.syncOneServerNoLock(ctx, id)
		if syncErr == nil {
			a.evaluateAndExecutePoolLocked(ctx, time.Now(), false)
		}
		a.releaseSync()
		if syncErr != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": syncErr.Error()})
			return
		}
		a.store.AddEvent("info", srv.Name, "手动刷新", "已完成状态、流量与账单同步")
	case "unlock":
		if err := a.store.Update(func(st *domain.AppState) error {
			for i := range st.Servers {
				if st.Servers[i].ID == id {
					st.Servers[i].LockedUntil = ""
					st.Servers[i].LockReason = ""
					st.Servers[i].KeepAliveFails = 0
					store.AppendEvent(st, "info", srv.Name, "手动解锁", "已清除本月熔断锁定")
					return nil
				}
			}
			return errNotFound
		}); err != nil {
			if errors.Is(err, errNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	case "toggle-keepalive":
		if err := a.store.Update(func(st *domain.AppState) error {
			for i := range st.Servers {
				if st.Servers[i].ID == id {
					st.Servers[i].KeepAlive = !st.Servers[i].KeepAlive
					st.Servers[i].KeepAliveFails = 0
					store.AppendEvent(st, "info", srv.Name, "切换抢占式保活", fmt.Sprintf("保活状态已设为: %v", st.Servers[i].KeepAlive))
					return nil
				}
			}
			return errNotFound
		}); err != nil {
			if errors.Is(err, errNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, a.buildStateResponse(time.Now()))
}

func (a *App) handleRefreshAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.refreshAllInFlight.CompareAndSwap(false, true) {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "refreshing"})
		return
	}
	go func() {
		defer a.refreshAllInFlight.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), schedulerSyncTimeout)
		defer cancel()
		a.syncAndEvaluate(ctx, time.Now(), true)
	}()
	a.store.AddEvent("info", "轮换池", "全局刷新", "已触发全池状态同步与策略评估")
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "refreshing"})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	return json.NewDecoder(r.Body).Decode(dst)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
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
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.store.Update(func(st *domain.AppState) error {
		if st.Auth.PasswordHash != "" {
			return errAlreadyInitialized
		}
		st.Auth.PasswordHash = hash
		return nil
	}); err != nil {
		if errors.Is(err, errAlreadyInitialized) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "管理员密码已初始化，请直接登录"})
			return
		}
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
	if err := decodeJSON(w, r, &req); err != nil {
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
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	if err := decodeJSON(w, r, &req); err != nil {
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
	if err := a.store.Update(func(st *domain.AppState) error {
		st.Auth.PasswordHash = newHash
		return nil
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Revoke all previous sessions and issue a fresh session for the current browser.
	a.auth.InvalidateAllSessions()
	a.auth.CreateSession(w, r)
	a.store.AddEvent("info", "安全", "修改密码", "管理员密码已更新，其余会话已失效")
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
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	cred, err := a.auth.VerifyPasskeyRegistration(req.ID, req.Name, req.ClientDataB64, req.AuthDataB64, req.PublicKeyB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.store.Update(func(st *domain.AppState) error {
		for _, pk := range st.Auth.Passkeys {
			if pk.ID == cred.ID {
				return errDuplicatePasskey
			}
		}
		st.Auth.Passkeys = append(st.Auth.Passkeys, cred)
		store.AppendEvent(st, "info", "安全", "绑定 Passkey", "已新增通行密钥: "+cred.Name)
		return nil
	}); err != nil {
		if errors.Is(err, errDuplicatePasskey) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "该 Passkey 凭据已绑定，请勿重复添加"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a.buildStateResponse(time.Now()))
}

func (a *App) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 Passkey ID"})
		return
	}
	if err := a.store.Update(func(st *domain.AppState) error {
		found := false
		out := make([]domain.PasskeyCredential, 0, len(st.Auth.Passkeys))
		for _, pk := range st.Auth.Passkeys {
			if pk.ID != req.ID {
				out = append(out, pk)
			} else {
				found = true
			}
		}
		if !found {
			return errNotFound
		}
		st.Auth.Passkeys = out
		store.AppendEvent(st, "info", "安全", "移除 Passkey", "已删除指定通行密钥")
		return nil
	}); err != nil {
		if errors.Is(err, errNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "Passkey 不存在"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a.buildStateResponse(time.Now()))
}

func (a *App) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := auth.ClientIP(r)
	if err := a.auth.CheckRateLimit(ip); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		return
	}
	if !a.allowPasskeyBegin(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "请求过于频繁，请稍后再试"})
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
	if err := decodeJSON(w, r, &req); err != nil {
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
	if err := a.store.Update(func(st *domain.AppState) error {
		for i := range st.Auth.Passkeys {
			if st.Auth.Passkeys[i].ID == req.ID {
				st.Auth.Passkeys[i].SignCount = newCount
			}
		}
		store.AppendEvent(st, "info", "安全", "Passkey 登录", fmt.Sprintf("密钥 %s（IP: %s）", pkName, ip))
		return nil
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.auth.ClearFailures(ip)
	a.auth.CreateSession(w, r)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Weekly Monday 08:00 Report ---

func (a *App) buildWeeklyReport(snap domain.AppState, localNow time.Time) (string, string) {
	title := fmt.Sprintf("CDT Smart Monitor 周报 (%s)", localNow.Format("2006-01-02"))
	var b strings.Builder
	var totalGB, totalUSD, totalCNY float64
	var hasIntl, hasChina bool
	dutyName := "无"
	for _, s := range snap.Servers {
		totalGB += s.UsedTrafficGB
		if s.Site == domain.SiteChina {
			totalCNY += s.BilledCostUSD
			hasChina = true
		} else {
			totalUSD += s.BilledCostUSD
			hasIntl = true
		}
		if s.ID == snap.Pool.CurrentServerID {
			dutyName = s.Name
		}
	}
	var costParts []string
	if hasIntl {
		costParts = append(costParts, fmt.Sprintf("$%.3f", totalUSD))
	}
	if hasChina {
		costParts = append(costParts, fmt.Sprintf("¥%.3f", totalCNY))
	}
	costSummary := "$0.000"
	if len(costParts) > 0 {
		costSummary = strings.Join(costParts, " + ")
	}
	fmt.Fprintf(&b, "总流量: %.2f GB | 总费用: %s | 当前当班: %s\n", totalGB, costSummary, dutyName)
	for _, s := range snap.Servers {
		icon := "⚪"
		if policy.IsLockActive(s, localNow) {
			icon = "🔴"
		} else if s.Status == domain.StatusRunning {
			icon = "🟢"
		}
		sym := "$"
		if s.Site == domain.SiteChina {
			sym = "¥"
		}
		fmt.Fprintf(&b, "%s %s (%s): %.2f/%.0f GB | %s%.3f/%s%.2f\n",
			icon, s.Name, s.Status, s.UsedTrafficGB, s.MaxTrafficGB, sym, s.BilledCostUSD, sym, s.MaxCostUSD)
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
	hasTelegram := snap.Notify.TelegramEnabled && snap.Notify.TelegramBotToken != "" && snap.Notify.TelegramChatID != ""
	hasWebhook := snap.Notify.WebhookEnabled && snap.Notify.WebhookURL != ""
	if !hasTelegram && !hasWebhook {
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
	sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	sent, err := a.notifier.SendSync(sendCtx, snap.Notify, title, body)
	if err != nil {
		a.logger.Warn("weekly report send failed", "err", err)
		return
	}
	_ = a.store.Update(func(st *domain.AppState) error {
		st.Notify.LastWeeklyReportDate = today
		store.AppendEvent(st, "info", "周报推送", "周一 08:00 周报", "已推送每周流量与费用汇总至: "+strings.Join(sent, ", "))
		return nil
	})
}

func (a *App) handleTestWeeklyReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req domain.NotifyConfig
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	snap := a.store.SnapshotRaw()
	req, err := resolveTestNotifyConfig(req, snap.Notify)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
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
