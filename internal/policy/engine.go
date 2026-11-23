package policy

import (
	"fmt"
	"math"
	"sort"
	"time"

	"cdt-smart-monitor/internal/domain"
)

type ServerEval struct {
	ServerID            int64
	EffectiveTrafficCap float64
	EffectiveCostCap    float64
	RemainingTrafficGB  float64
	CompositeHeadroom   float64
	DynamicWeight       float64
	ShouldCutoff        bool
	CutoffReason        string
}

type Action struct {
	ServerID int64
	Type     string // "start" | "stop" | "lock" | "notify"
	StopMode string
	Reason   string
}

type Decision struct {
	Phase                 string
	TargetServerID        int64
	AutoPeakSliceMins     int
	ResetSliceTracking    bool
	PeakOverrideUntil     time.Time
	ClearManualSelection  bool
	ClearManualReason     string
	ResetExpiredOverrides bool
	ScheduleMode          string // "auto" | "manual_live" | "manual_slot"
	Actions               []Action
	Summary               string
}

type ServerLoadPlan struct {
	ServerID       int64   `json:"server_id"`
	Name           string  `json:"name"`
	HeadroomPct    int     `json:"headroom_pct"`
	RemainingGB    float64 `json:"remaining_gb"`
	WeightPct      int     `json:"weight_pct"`
	ScheduledHours int     `json:"scheduled_hours"`
	PeakHours      int     `json:"peak_hours"`
	Eligible       bool    `json:"eligible"`
}

type HourSlot struct {
	Hour           int    `json:"hour"`
	Phase          string `json:"phase"` // "idle" | "normal" | "peak" | "exhausted"
	AutoServerID   int64  `json:"auto_server_id"`
	AutoServerName string `json:"auto_server_name,omitempty"`
	ServerID       int64  `json:"server_id"`
	ServerName     string `json:"server_name,omitempty"`
	Source         string `json:"source"`          // "auto" | "manual_slot" | "manual_live"
	ManualOverride int64  `json:"manual_override"` // 0 = auto, -1 = forced idle, >0 = pinned server
	IsCurrentHour  bool   `json:"is_current_hour"`
}

type DailySchedule struct {
	Date               string           `json:"date"`
	CurrentHour        int              `json:"current_hour"`
	Mode               string           `json:"mode"` // "auto" | "manual_live" | "manual_slot"
	ModeSummary        string           `json:"mode_summary"`
	BalanceScore       int              `json:"balance_score"`
	BalanceStatus      string           `json:"balance_status"`
	ImbalanceGapPct    int              `json:"imbalance_gap_pct"`
	ActiveOverrideCnt  int              `json:"active_override_count"`
	AutoPeakSliceMins  int              `json:"auto_peak_slice_mins"`
	ManualServerID     int64            `json:"manual_server_id"`
	ManualServerName   string           `json:"manual_server_name,omitempty"`
	ManualUntil        string           `json:"manual_until,omitempty"`
	ManualRemainMins   int              `json:"manual_remain_mins,omitempty"`
	AutoRevertMode     string           `json:"auto_revert_mode"`
	AutoRevertMinutes  int              `json:"auto_revert_minutes"`
	Hours              []HourSlot       `json:"hours"`
	ServerPlans        []ServerLoadPlan `json:"server_plans"`
}

// IsLockActive reports whether a server currently has an unexpired monthly cutoff lock.
func IsLockActive(s domain.Server, now time.Time) bool {
	if s.LockedUntil == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, s.LockedUntil)
	if err != nil {
		return false
	}
	return now.Before(t)
}

func ApplyInternalBuffer(limit, buf float64) float64 {
	if limit <= 0 {
		return 0
	}
	if limit <= buf {
		return limit * 0.9
	}
	return limit - buf
}

func EvaluateServer(s domain.Server, now time.Time) ServerEval {
	effTraffic := ApplyInternalBuffer(s.MaxTrafficGB, domain.InternalTrafficBufferGB)
	effCost := ApplyInternalBuffer(s.MaxCostUSD, domain.InternalCostBufferUSD)

	remT := math.Max(0, effTraffic-s.UsedTrafficGB)
	remC := math.Max(0, effCost-s.BilledCostUSD)

	tRatio := 1.0
	if effTraffic > 0 {
		tRatio = clamp01(remT / effTraffic)
	}
	cRatio := 1.0
	if effCost > 0 {
		cRatio = clamp01(remC / effCost)
	}

	ev := ServerEval{
		ServerID:            s.ID,
		EffectiveTrafficCap: effTraffic,
		EffectiveCostCap:    effCost,
		RemainingTrafficGB:  remT,
		CompositeHeadroom:   math.Min(tRatio, cRatio),
	}

	if IsLockActive(s, now) {
		ev.ShouldCutoff = true
		ev.CutoffReason = s.LockReason
		if ev.CutoffReason == "" {
			ev.CutoffReason = "cost_cutoff"
		}
		ev.CompositeHeadroom = 0
		ev.RemainingTrafficGB = 0
		return ev
	}

	if effCost > 0 && s.BilledCostUSD >= effCost {
		ev.ShouldCutoff = true
		ev.CutoffReason = "cost_cutoff"
		ev.CompositeHeadroom = 0
		return ev
	}
	if effTraffic > 0 && s.UsedTrafficGB >= effTraffic {
		ev.ShouldCutoff = true
		ev.CutoffReason = "traffic_cutoff"
		ev.CompositeHeadroom = 0
		ev.RemainingTrafficGB = 0
		return ev
	}
	return ev
}

// CheckRefreshDelta checks whether adjacent refresh jumps require immediate stop & switch.
// PeakMaxSliceGB takes higher priority than GlobalRefreshTrafficDeltaGB (30GB) during peak hours.
func CheckRefreshDelta(s domain.Server, inPeak bool, peakMaxSliceGB, sliceStartTrafficGB float64) (bool, string) {
	costDelta := s.BilledCostUSD - s.PrevCostUSD
	if costDelta > domain.GlobalRefreshCostDeltaUSD {
		return true, fmt.Sprintf("两次刷新费用增幅 $%.3f > $%.2f，立即停机切换", costDelta, domain.GlobalRefreshCostDeltaUSD)
	}

	if inPeak && peakMaxSliceGB > 0 {
		sliceUsed := s.UsedTrafficGB - sliceStartTrafficGB
		if sliceUsed >= peakMaxSliceGB {
			return true, fmt.Sprintf("高峰单班流量已达 %.1f / %.1f GB 上限，自动切换下一台", sliceUsed, peakMaxSliceGB)
		}
		return false, ""
	}

	trafficDelta := s.UsedTrafficGB - s.PrevTrafficGB
	if trafficDelta > domain.GlobalRefreshTrafficDeltaGB {
		return true, fmt.Sprintf("两次刷新流量增幅 %.1f GB > %.0f GB，立即停机切换", trafficDelta, domain.GlobalRefreshTrafficDeltaGB)
	}
	return false, ""
}

func loadLocation(tz string) *time.Location {
	if tz == "" {
		tz = "Asia/Shanghai"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.UTC
	}
	return loc
}

func normalizeRevertMode(mode string) string {
	switch mode {
	case domain.ManualRevertNextSlot, domain.ManualRevertDuration, domain.ManualRevertNextDay, domain.ManualRevertNever:
		return mode
	default:
		return domain.ManualRevertNextSlot
	}
}

// computeDynamicWeights assigns smooth progressive load-balancing weights (H^2.2 * capScale * failPenalty)
// so healthier machines naturally absorb proportionally more peak & normal hours without cliff starvation.
func computeDynamicWeights(eligible []domain.Server, evals map[int64]ServerEval) ([]float64, float64) {
	n := len(eligible)
	weights := make([]float64, n)
	if n == 0 {
		return weights, 0
	}

	avgEffT := 0.0
	for _, s := range eligible {
		avgEffT += evals[s.ID].EffectiveTrafficCap
	}
	avgEffT /= float64(n)

	total := 0.0
	for i, s := range eligible {
		ev := evals[s.ID]
		h := math.Max(0.02, ev.CompositeHeadroom)
		capScale := 1.0
		if avgEffT > 0 && ev.EffectiveTrafficCap > 0 {
			capScale = math.Sqrt(ev.EffectiveTrafficCap / avgEffT)
		}
		w := math.Pow(h, 2.2) * capScale
		// Only penalize repeated keep-alive failures (>= 2) so 1 transient preemption doesn't churn the schedule.
		if s.KeepAliveFails >= domain.MaxKeepAliveFailures {
			w = 0.001
		} else if s.KeepAliveFails >= 2 {
			w *= 0.35
		}
		weights[i] = w
		ev.DynamicWeight = w
		evals[s.ID] = ev
		total += w
	}
	return weights, total
}

// allocateWeightedHours distributes totalHours across N servers proportionally to weights
// using the Largest Remainder (Hamilton) method for exact integer sums and minimal rounding error.
func allocateWeightedHours(totalHours int, weights []float64, totalWeight float64) []int {
	n := len(weights)
	quotas := make([]int, n)
	if n == 0 || totalHours <= 0 {
		return quotas
	}
	if totalWeight <= 0 {
		for i := 0; i < totalHours; i++ {
			quotas[i%n]++
		}
		return quotas
	}

	type remEntry struct {
		idx int
		rem float64
		w   float64
	}
	rems := make([]remEntry, n)
	assigned := 0
	for i, w := range weights {
		exact := float64(totalHours) * (w / totalWeight)
		q := int(math.Floor(exact))
		quotas[i] = q
		assigned += q
		rems[i] = remEntry{idx: i, rem: exact - float64(q), w: w}
	}
	sort.SliceStable(rems, func(i, j int) bool {
		if math.Abs(rems[i].rem-rems[j].rem) > 1e-9 {
			return rems[i].rem > rems[j].rem
		}
		return rems[i].w > rems[j].w
	})
	for i := 0; assigned < totalHours && i < n; i++ {
		quotas[rems[i].idx]++
		assigned++
	}
	return quotas
}

// assignWindowContiguous lays out server hour quotas in contiguous blocks rotated by dayOffset
// so each day shifts prime hours fairly while minimizing ECS stop/start transitions.
func assignWindowContiguous(hours []int, eligible []domain.Server, quotas []int, dayOffset int, assign map[int]int64) {
	n := len(eligible)
	if n == 0 || len(hours) == 0 {
		return
	}
	pos := 0
	for step := 0; step < n && pos < len(hours); step++ {
		idx := (step + dayOffset) % n
		q := quotas[idx]
		for k := 0; k < q && pos < len(hours); k++ {
			assign[hours[pos]] = eligible[idx].ID
			pos++
		}
	}
}

// assignWindowInterleaved distributes normal hours in smooth 2-hour weighted chunks for StrategyContinuousRoundRobin.
func assignWindowInterleaved(hours []int, eligible []domain.Server, quotas []int, dayOffset int, assign map[int]int64) {
	n := len(eligible)
	if n == 0 || len(hours) == 0 {
		return
	}
	rem := make([]int, n)
	copy(rem, quotas)
	chunk := 2
	if len(hours) < n*2 {
		chunk = 1
	}
	pos := 0
	for pos < len(hours) {
		progressed := false
		for step := 0; step < n && pos < len(hours); step++ {
			idx := (step + dayOffset) % n
			if rem[idx] <= 0 {
				continue
			}
			take := chunk
			if rem[idx] < take {
				take = rem[idx]
			}
			for k := 0; k < take && pos < len(hours); k++ {
				assign[hours[pos]] = eligible[idx].ID
				rem[idx]--
				pos++
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
}

func activeOverridesForDate(pool domain.PoolConfig, todayStr string) (map[int]int64, bool) {
	if len(pool.ManualHourlyOverrides) == 0 {
		return nil, false
	}
	if pool.ManualOverridesAutoResetDaily && pool.ManualScheduleDate != "" && pool.ManualScheduleDate != todayStr {
		return nil, true
	}
	return pool.ManualHourlyOverrides, false
}

// BuildDailySchedule produces the single-source-of-truth 24-hour dynamic load-balancing schedule
// used by BOTH the Go scheduler and the Web UI Gantt chart.
func BuildDailySchedule(pool domain.PoolConfig, servers []domain.Server, now time.Time) DailySchedule {
	loc := loadLocation(pool.Timezone)
	localNow := now.In(loc)
	todayStr := localNow.Format("2006-01-02")
	curHour := localNow.Hour()

	revertMode := normalizeRevertMode(pool.ManualAutoRevertMode)
	revertMins := pool.ManualAutoRevertMinutes
	if revertMins <= 0 {
		revertMins = 120
	}

	evals := make(map[int64]ServerEval, len(servers))
	nameByID := make(map[int64]string, len(servers))
	eligible := make([]domain.Server, 0, len(servers))
	eligibleMap := make(map[int64]domain.Server, len(servers))
	for _, s := range servers {
		ev := EvaluateServer(s, now)
		evals[s.ID] = ev
		nameByID[s.ID] = s.Name
		if !ev.ShouldCutoff && s.InPool {
			eligible = append(eligible, s)
			eligibleMap[s.ID] = s
		}
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		if eligible[i].Priority != eligible[j].Priority {
			return eligible[i].Priority < eligible[j].Priority
		}
		return eligible[i].ID < eligible[j].ID
	})

	weights, totalWeight := computeDynamicWeights(eligible, evals)

	// Balance score & headroom gap
	balanceScore := 100
	imbalanceGapPct := 0
	balanceStatus := "单机/待添加"
	if len(eligible) >= 2 {
		maxH, minH := -1.0, 2.0
		for _, s := range eligible {
			h := evals[s.ID].CompositeHeadroom
			if h > maxH {
				maxH = h
			}
			if h < minH {
				minH = h
			}
		}
		gap := math.Max(0, maxH-minH)
		imbalanceGapPct = int(math.Round(gap * 100))
		balanceScore = int(math.Round(clamp01(1.0-gap) * 100))
		switch {
		case gap < 0.08:
			balanceStatus = "高度均衡 · 按日轮转"
		case gap < 0.20:
			balanceStatus = fmt.Sprintf("动态加权微调中（余量差 %d%%）", imbalanceGapPct)
		default:
			balanceStatus = fmt.Sprintf("余量失衡强纠偏（余量差 %d%%）", imbalanceGapPct)
		}
	} else if len(eligible) == 1 {
		balanceStatus = "单机值班模式"
	} else if len(servers) > 0 {
		balanceScore = 0
		balanceStatus = "全池已熔断"
	}

	// Collect ordered peak & normal hours in local day order
	peakHoursList := make([]int, 0, 24)
	normalHoursList := make([]int, 0, 24)
	for offset := 0; offset < 24; offset++ {
		h := (pool.PeakStartHour + offset) % 24
		if inHourRange(h, pool.ActiveStartHour, pool.ActiveEndHour) && inHourRange(h, pool.PeakStartHour, pool.PeakEndHour) {
			peakHoursList = append(peakHoursList, h)
		}
	}
	for offset := 0; offset < 24; offset++ {
		h := (pool.ActiveStartHour + offset) % 24
		if inHourRange(h, pool.ActiveStartHour, pool.ActiveEndHour) && !inHourRange(h, pool.PeakStartHour, pool.PeakEndHour) {
			normalHoursList = append(normalHoursList, h)
		}
	}

	autoPeakSliceMins := 0
	if len(eligible) > 0 && len(peakHoursList) > 0 {
		autoPeakSliceMins = int(math.Max(15, math.Round(float64(len(peakHoursList)*60)/float64(len(eligible)))))
	}

	autoAssign := make(map[int]int64, 24)
	if len(eligible) > 0 {
		dayOffset := localNow.Day() % len(eligible)
		if pool.Strategy == domain.StrategyExhaustSequential || len(eligible) == 1 {
			firstID := eligible[0].ID
			for _, h := range peakHoursList {
				autoAssign[h] = firstID
			}
			for _, h := range normalHoursList {
				autoAssign[h] = firstID
			}
		} else {
			peakQuotas := allocateWeightedHours(len(peakHoursList), weights, totalWeight)
			normalQuotas := allocateWeightedHours(len(normalHoursList), weights, totalWeight)
			assignWindowContiguous(peakHoursList, eligible, peakQuotas, dayOffset, autoAssign)
			if pool.Strategy == domain.StrategyContinuousRoundRobin {
				assignWindowInterleaved(normalHoursList, eligible, normalQuotas, (dayOffset+1)%len(eligible), autoAssign)
			} else {
				assignWindowContiguous(normalHoursList, eligible, normalQuotas, (dayOffset+1)%len(eligible), autoAssign)
			}
		}
	}

	// Check active live manual pin & hourly overrides
	manualActive := false
	if pool.ManualServerID > 0 {
		if _, ok := eligibleMap[pool.ManualServerID]; ok {
			if pool.ManualUntil.IsZero() || now.Before(pool.ManualUntil) {
				manualActive = true
			}
		}
	}
	overrides, _ := activeOverridesForDate(pool, todayStr)

	hours := make([]HourSlot, 24)
	schedHoursBySrv := make(map[int64]int, len(servers))
	peakHoursBySrv := make(map[int64]int, len(servers))
	activeOverrideCnt := 0

	for h := 0; h < 24; h++ {
		inAct := inHourRange(h, pool.ActiveStartHour, pool.ActiveEndHour)
		inPk := inAct && inHourRange(h, pool.PeakStartHour, pool.PeakEndHour)
		phase := "idle"
		if inAct {
			if len(eligible) == 0 {
				phase = "exhausted"
			} else if inPk {
				phase = "peak"
			} else {
				phase = "normal"
			}
		}

		autoID := autoAssign[h]
		effID := autoID
		source := "auto"
		var ov int64
		if overrides != nil {
			if val, ok := overrides[h]; ok && val != 0 {
				ov = val
				activeOverrideCnt++
				if val == domain.ManualSlotForceIdle {
					effID = 0
					phase = "idle"
					source = "manual_slot"
				} else if _, okSrv := eligibleMap[val]; okSrv {
					effID = val
					if phase == "idle" {
						phase = "normal"
					}
					source = "manual_slot"
				}
			}
		}
		if h == curHour && manualActive {
			effID = pool.ManualServerID
			source = "manual_live"
		}

		if effID > 0 {
			schedHoursBySrv[effID]++
			if inPk {
				peakHoursBySrv[effID]++
			}
		}

		hours[h] = HourSlot{
			Hour:           h,
			Phase:          phase,
			AutoServerID:   autoID,
			AutoServerName: nameByID[autoID],
			ServerID:       effID,
			ServerName:     nameByID[effID],
			Source:         source,
			ManualOverride: ov,
			IsCurrentHour:  h == curHour,
		}
	}

	// Build per-server load plan
	weightByID := make(map[int64]float64, len(eligible))
	for i, s := range eligible {
		if totalWeight > 0 {
			weightByID[s.ID] = weights[i] / totalWeight
		}
	}
	plans := make([]ServerLoadPlan, 0, len(servers))
	for _, s := range servers {
		ev := evals[s.ID]
		_, isElig := eligibleMap[s.ID]
		plans = append(plans, ServerLoadPlan{
			ServerID:       s.ID,
			Name:           s.Name,
			HeadroomPct:    int(math.Round(ev.CompositeHeadroom * 100)),
			RemainingGB:    math.Round(ev.RemainingTrafficGB*10) / 10,
			WeightPct:      int(math.Round(weightByID[s.ID] * 100)),
			ScheduledHours: schedHoursBySrv[s.ID],
			PeakHours:      peakHoursBySrv[s.ID],
			Eligible:       isElig,
		})
	}

	mode := "auto"
	modeSummary := fmt.Sprintf("智能排班 · %s", balanceStatus)
	manualUntilStr := ""
	manualRemainMins := 0
	manualSrvName := ""
	if manualActive {
		mode = "manual_live"
		manualSrvName = nameByID[pool.ManualServerID]
		if !pool.ManualUntil.IsZero() {
			manualUntilStr = pool.ManualUntil.In(loc).Format("15:04")
			rem := int(math.Ceil(pool.ManualUntil.Sub(now).Minutes()))
			if rem < 1 {
				rem = 1
			}
			manualRemainMins = rem
			modeSummary = fmt.Sprintf("手动指定 %s · 将于 %s 自动切回智能排班", manualSrvName, manualUntilStr)
		} else {
			modeSummary = fmt.Sprintf("手动指定 %s · 持续保持直到一键切回", manualSrvName)
		}
	} else if hours[curHour].Source == "manual_slot" {
		mode = "manual_slot"
		if hours[curHour].ServerID == 0 {
			modeSummary = fmt.Sprintf("手动排班时段（%02d:00 强制休眠）", curHour)
		} else {
			modeSummary = fmt.Sprintf("手动排班时段（%02d:00 指定 %s）", curHour, hours[curHour].ServerName)
		}
	}

	return DailySchedule{
		Date:              todayStr,
		CurrentHour:       curHour,
		Mode:              mode,
		ModeSummary:       modeSummary,
		BalanceScore:      balanceScore,
		BalanceStatus:     balanceStatus,
		ImbalanceGapPct:   imbalanceGapPct,
		ActiveOverrideCnt: activeOverrideCnt,
		AutoPeakSliceMins: autoPeakSliceMins,
		ManualServerID:    pool.ManualServerID,
		ManualServerName:  manualSrvName,
		ManualUntil:       manualUntilStr,
		ManualRemainMins:  manualRemainMins,
		AutoRevertMode:    revertMode,
		AutoRevertMinutes: revertMins,
		Hours:             hours,
		ServerPlans:       plans,
	}
}

// ComputeManualUntil calculates when a Mihomo-style manual selection should automatically revert
// back to smart scheduling according to revertMode ("next_slot", "duration", "next_day", "never").
func ComputeManualUntil(pool domain.PoolConfig, servers []domain.Server, now time.Time, revertMode string, revertMinutes int) time.Time {
	loc := loadLocation(pool.Timezone)
	localNow := now.In(loc)
	mode := normalizeRevertMode(revertMode)

	switch mode {
	case domain.ManualRevertNever:
		return time.Time{}
	case domain.ManualRevertNextDay:
		y, m, d := localNow.Date()
		return time.Date(y, m, d+1, 0, 0, 0, 0, loc)
	case domain.ManualRevertDuration:
		mins := revertMinutes
		if mins <= 0 {
			mins = pool.ManualAutoRevertMinutes
		}
		if mins <= 0 {
			mins = 120
		}
		return now.Add(time.Duration(mins) * time.Minute)
	default: // ManualRevertNextSlot
		tmpPool := pool
		tmpPool.ManualServerID = 0
		tmpPool.ManualUntil = time.Time{}
		sched := BuildDailySchedule(tmpPool, servers, now)
		curHour := localNow.Hour()
		curAutoID := sched.Hours[curHour].AutoServerID
		curPhase := sched.Hours[curHour].Phase
		y, m, d := localNow.Date()
		for step := 1; step <= 24; step++ {
			nextH := (curHour + step) % 24
			slot := sched.Hours[nextH]
			if slot.AutoServerID != curAutoID || slot.Phase != curPhase {
				dayAdd := 0
				if curHour+step >= 24 {
					dayAdd = 1
				}
				return time.Date(y, m, d+dayAdd, nextH, 0, 0, 0, loc)
			}
		}
		// Fallback if single server occupies all 24h: revert at next day 00:00
		return time.Date(y, m, d+1, 0, 0, 0, 0, loc)
	}
}

// EvaluatePool evaluates dual-threshold safety cutoffs, Mihomo-style manual duty pin & auto-revert,
// per-hour manual schedule overrides, idle collective shutdown, spot keep-alive (with 3-fail failover),
// refresh-delta protection, and weighted dynamic load-balancing rotation (matching BuildDailySchedule 100%).
func EvaluatePool(pool domain.PoolConfig, servers []domain.Server, now time.Time) Decision {
	if len(servers) == 0 {
		return Decision{Phase: "disabled", ScheduleMode: "auto", Summary: "暂无服务器"}
	}
	loc := loadLocation(pool.Timezone)
	localNow := now.In(loc)
	todayStr := localNow.Format("2006-01-02")
	stopMode := pool.StopMode
	if stopMode == "" {
		stopMode = domain.StopModeStopCharging
	}

	dec := Decision{ScheduleMode: "auto"}
	evals := make(map[int64]ServerEval, len(servers))
	eligible := make([]domain.Server, 0, len(servers))
	eligibleMap := make(map[int64]domain.Server, len(servers))
	standaloneKeepAlive := make([]domain.Server, 0)

	// 1. Dual-threshold safety check across ALL servers (ALWAYS overrides manual selection, keep-alive & rotation)
	for _, s := range servers {
		ev := EvaluateServer(s, now)
		evals[s.ID] = ev
		if ev.ShouldCutoff {
			if s.Status == domain.StatusRunning || s.Status == domain.StatusStarting {
				dec.Actions = append(dec.Actions, Action{
					ServerID: s.ID,
					Type:     "stop",
					StopMode: stopMode,
					Reason:   fmt.Sprintf("触发%s：流量 %.1f/%.0fGB，费用 $%.3f/$%.2f", ev.CutoffReason, s.UsedTrafficGB, ev.EffectiveTrafficCap, s.BilledCostUSD, ev.EffectiveCostCap),
				})
			}
			if !IsLockActive(s, now) {
				dec.Actions = append(dec.Actions, Action{
					ServerID: s.ID,
					Type:     "lock",
					Reason:   ev.CutoffReason,
				})
			}
			continue
		}
		if s.InPool && pool.Enabled {
			eligible = append(eligible, s)
			eligibleMap[s.ID] = s
		} else if s.KeepAlive {
			standaloneKeepAlive = append(standaloneKeepAlive, s)
		}
	}

	inActive := inHourRange(localNow.Hour(), pool.ActiveStartHour, pool.ActiveEndHour)

	// Standalone spot keep-alive
	for _, s := range standaloneKeepAlive {
		if !inActive {
			if s.Status == domain.StatusRunning || s.Status == domain.StatusStarting {
				dec.Actions = append(dec.Actions, Action{
					ServerID: s.ID,
					Type:     "stop",
					StopMode: stopMode,
					Reason:   "非使用时段停机（保活暂停）",
				})
			}
		} else if s.Status == domain.StatusStopped {
			dec.Actions = append(dec.Actions, Action{
				ServerID: s.ID,
				Type:     "start",
				Reason:   "抢占式保活：检测到实例停止，自动拉起",
			})
		}
	}

	// Check daily auto-reset for yesterday's hourly overrides
	overrides, overridesExpired := activeOverridesForDate(pool, todayStr)
	if overridesExpired {
		dec.ResetExpiredOverrides = true
	}

	if !pool.Enabled {
		dec.Phase = "disabled"
		dec.Summary = "智能轮换未启用（单机熔断与抢占式保活正常运行）"
		return dec
	}

	// 2. Check Mihomo-style manual duty pin & auto-revert BEFORE idle/auto evaluation
	var manualPinned *domain.Server
	if pool.ManualServerID > 0 {
		if !pool.ManualUntil.IsZero() && !now.Before(pool.ManualUntil) {
			dec.ClearManualSelection = true
			dec.ClearManualReason = "已到达自动切回时间，恢复智能排班"
		} else if srv, ok := eligibleMap[pool.ManualServerID]; !ok {
			dec.ClearManualSelection = true
			dec.ClearManualReason = "手动指定节点已熔断或不可用，自动切回智能排班"
		} else if srv.Status == domain.StatusStopped && srv.KeepAliveFails >= domain.MaxKeepAliveFailures && len(eligible) > 1 {
			dec.ClearManualSelection = true
			dec.ClearManualReason = fmt.Sprintf("手动指定节点 %s 连续 %d 次拉起失败，自动切回智能排班", srv.Name, srv.KeepAliveFails)
		} else {
			cp := srv
			manualPinned = &cp
		}
	}

	if manualPinned != nil {
		// Emergency billing spike guard still applies even in manual mode!
		if (manualPinned.BilledCostUSD - manualPinned.PrevCostUSD) > domain.GlobalRefreshCostDeltaUSD {
			dec.ClearManualSelection = true
			dec.ClearManualReason = fmt.Sprintf("手动节点 %s 单次费用增幅超 $%.2f，安全急停并切回智能排班", manualPinned.Name, domain.GlobalRefreshCostDeltaUSD)
			manualPinned = nil
		} else {
			dec.Phase = "manual"
			dec.ScheduleMode = "manual_live"
			dec.TargetServerID = manualPinned.ID
			dec.ResetSliceTracking = (manualPinned.ID != pool.CurrentServerID)
			dec.Summary = fmt.Sprintf("手动值班：%s", manualPinned.Name)
			appendStartAndStopOthers(&dec, *manualPinned, eligible, nil, false, stopMode, pool.MakeBeforeBreak, fmt.Sprintf("手动切换至 %s 值班", manualPinned.Name))
			return dec
		}
	}

	// 3. All exhausted
	if len(eligible) == 0 {
		if !inActive {
			dec.Phase = "idle"
			dec.Summary = "非使用时段：全池停机"
			return dec
		}
		dec.Phase = "all_exhausted"
		dec.Summary = "池内所有服务器均已达到流量或金额安全线"
		dec.Actions = append(dec.Actions, Action{
			ServerID: 0,
			Type:     "notify",
			Reason:   "全池服务器均已触及流量或金额安全线，已全部熔断停机",
		})
		return dec
	}

	// 4. Check per-hour manual schedule override for the current hour
	curHour := localNow.Hour()
	if overrides != nil {
		if ovID, ok := overrides[curHour]; ok && ovID != 0 {
			if ovID == domain.ManualSlotForceIdle {
				dec.Phase = "idle"
				dec.ScheduleMode = "manual_slot"
				dec.Summary = fmt.Sprintf("%02d:00 时段已手动设为休眠停机", curHour)
				for _, s := range eligible {
					if s.Status == domain.StatusRunning || s.Status == domain.StatusStarting {
						dec.Actions = append(dec.Actions, Action{
							ServerID: s.ID,
							Type:     "stop",
							StopMode: stopMode,
							Reason:   fmt.Sprintf("手动排班：%02d:00 强制休眠", curHour),
						})
					}
				}
				return dec
			}
			if srv, okSrv := eligibleMap[ovID]; okSrv && srv.KeepAliveFails < domain.MaxKeepAliveFailures {
				// Still protect against sudden billing spikes
				if (srv.BilledCostUSD - srv.PrevCostUSD) <= domain.GlobalRefreshCostDeltaUSD {
					dec.Phase = "normal"
					if inHourRange(curHour, pool.PeakStartHour, pool.PeakEndHour) {
						dec.Phase = "peak"
					}
					dec.ScheduleMode = "manual_slot"
					dec.TargetServerID = srv.ID
					dec.ResetSliceTracking = (srv.ID != pool.CurrentServerID)
					dec.Summary = fmt.Sprintf("手动排班时段（%02d:00）：由 %s 值班", curHour, srv.Name)
					appendStartAndStopOthers(&dec, srv, eligible, nil, false, stopMode, pool.MakeBeforeBreak, fmt.Sprintf("按手动排班表切换至 %s", srv.Name))
					return dec
				}
			}
		}
	}

	// 5. Idle window -> collective shutdown (overrides keep-alive)
	if !inActive {
		dec.Phase = "idle"
		dec.Summary = "非使用时段：执行全池集体节省停机"
		for _, s := range eligible {
			if s.Status == domain.StatusRunning || s.Status == domain.StatusStarting {
				dec.Actions = append(dec.Actions, Action{
					ServerID: s.ID,
					Type:     "stop",
					StopMode: stopMode,
					Reason:   "非使用时段集体关机",
				})
			}
		}
		return dec
	}

	// 6. Smart Dynamic Load-Balancing Schedule (authoritative match with BuildDailySchedule)
	sort.SliceStable(eligible, func(i, j int) bool {
		if eligible[i].Priority != eligible[j].Priority {
			return eligible[i].Priority < eligible[j].Priority
		}
		return eligible[i].ID < eligible[j].ID
	})

	sched := BuildDailySchedule(pool, servers, now)
	dec.AutoPeakSliceMins = sched.AutoPeakSliceMins
	inPeak := inHourRange(curHour, pool.PeakStartHour, pool.PeakEndHour)
	if inPeak {
		dec.Phase = "peak"
	} else {
		dec.Phase = "normal"
	}

	scheduledID := sched.Hours[curHour].AutoServerID
	var scheduledServer *domain.Server
	if srv, ok := eligibleMap[scheduledID]; ok {
		cp := srv
		scheduledServer = &cp
	}

	var current *domain.Server
	for i := range eligible {
		if eligible[i].ID == pool.CurrentServerID {
			current = &eligible[i]
			break
		}
	}

	needSwitch := false
	urgentStop := false
	reason := ""
	var forcedTarget *domain.Server

	if current == nil {
		needSwitch = true
		if scheduledServer != nil {
			forcedTarget = scheduledServer
			reason = fmt.Sprintf("动态加权排班（%s）由 %s 上岗", sched.BalanceStatus, scheduledServer.Name)
		} else {
			reason = "选择当前最健康机器上岗"
		}
	} else if current.Status == domain.StatusStopped && current.KeepAliveFails >= domain.MaxKeepAliveFailures && len(eligible) > 1 {
		needSwitch = true
		reason = fmt.Sprintf("抢占式保活连续 %d 次拉起失败，自动故障转移至备机", current.KeepAliveFails)
	} else {
		if deltaSwitch, deltaReason := CheckRefreshDelta(*current, inPeak, pool.PeakMaxSliceGB, pool.CurrentSliceStartTrafficGB); deltaSwitch {
			needSwitch = true
			urgentStop = true
			reason = deltaReason
			if inPeak && dec.AutoPeakSliceMins > 0 {
				minsSinceStart := (localNow.Hour()*60 + localNow.Minute()) - pool.PeakStartHour*60
				if minsSinceStart < 0 {
					minsSinceStart += 24 * 60
				}
				curSlot := minsSinceStart / dec.AutoPeakSliceMins
				remMins := (curSlot+1)*dec.AutoPeakSliceMins - minsSinceStart
				if remMins < 5 {
					remMins = dec.AutoPeakSliceMins
				}
				dec.PeakOverrideUntil = now.Add(time.Duration(remMins) * time.Minute)
			}
		} else if scheduledServer != nil && current.ID != scheduledServer.ID && scheduledServer.KeepAliveFails < domain.MaxKeepAliveFailures {
			if inPeak {
				// Clock-aligned dynamic peak handoff (suppress bounce-back during PeakOverrideUntil after burst-cap handoff).
				if !now.Before(pool.PeakOverrideUntil) {
					needSwitch = true
					forcedTarget = scheduledServer
					reason = fmt.Sprintf("高峰动态均衡排班（%s）切换至 %s", sched.BalanceStatus, scheduledServer.Name)
				}
			} else if len(eligible) >= domain.MinSmartRotationInstances && pool.Strategy != domain.StrategyExhaustSequential {
				// During normal hours, require minimum 30-min slice hold (unless severe imbalance >= 20%)
				// so transient spot preemptions or 1% headroom ticks never cause unnecessary cold starts.
				heldEnough := pool.CurrentSliceStartedAt.IsZero() || now.Sub(pool.CurrentSliceStartedAt) >= 30*time.Minute
				severeImbalance := sched.ImbalanceGapPct >= 20
				if heldEnough || severeImbalance {
					needSwitch = true
					forcedTarget = scheduledServer
					reason = fmt.Sprintf("平峰动态均衡排班（%s）切换至 %s", sched.BalanceStatus, scheduledServer.Name)
				}
			}
		}
	}

	var target domain.Server
	if !needSwitch && current != nil {
		target = *current
		if target.Status == domain.StatusStopped && target.KeepAlive {
			reason = "抢占式保活：当班实例被抢占停止，正在自动拉起"
		}
		dec.Summary = fmt.Sprintf("维持 %s 值班（%s）", target.Name, dec.Phase)
	} else if forcedTarget != nil {
		target = *forcedTarget
		dec.ResetSliceTracking = (target.ID != pool.CurrentServerID)
		dec.Summary = fmt.Sprintf("切换至 %s 值班（%s）", target.Name, reason)
	} else {
		excludeID := int64(0)
		if current != nil && len(eligible) > 1 {
			excludeID = current.ID
		}
		target = pickBest(eligible, evals, pool.Strategy, excludeID)
		dec.ResetSliceTracking = (target.ID != pool.CurrentServerID)
		dec.Summary = fmt.Sprintf("切换至 %s 值班（%s）", target.Name, reason)
	}
	dec.TargetServerID = target.ID

	appendStartAndStopOthers(&dec, target, eligible, current, urgentStop, stopMode, pool.MakeBeforeBreak, reason)
	return dec
}

func appendStartAndStopOthers(
	dec *Decision,
	target domain.Server,
	eligible []domain.Server,
	current *domain.Server,
	urgentStop bool,
	stopMode string,
	makeBeforeBreak bool,
	reason string,
) {
	if urgentStop && current != nil && current.ID != target.ID {
		if current.Status == domain.StatusRunning || current.Status == domain.StatusStarting {
			dec.Actions = append(dec.Actions, Action{
				ServerID: current.ID,
				Type:     "stop",
				StopMode: stopMode,
				Reason:   reason,
			})
		}
	}

	if target.Status != domain.StatusRunning && target.Status != domain.StatusStarting {
		startReason := reason
		if startReason == "" {
			if target.KeepAlive {
				startReason = "抢占式保活：检测到当班机器已停止，自动拉起"
			} else {
				startReason = "轮换值班自动开机"
			}
		}
		dec.Actions = append(dec.Actions, Action{
			ServerID: target.ID,
			Type:     "start",
			Reason:   startReason,
		})
	}

	targetRunning := (target.Status == domain.StatusRunning)
	for _, s := range eligible {
		if s.ID == target.ID {
			continue
		}
		if urgentStop && current != nil && s.ID == current.ID {
			continue
		}
		if s.Status == domain.StatusRunning || s.Status == domain.StatusStarting {
			if !makeBeforeBreak || targetRunning {
				dec.Actions = append(dec.Actions, Action{
					ServerID: s.ID,
					Type:     "stop",
					StopMode: stopMode,
					Reason:   fmt.Sprintf("已无感交接至 %s，旧机节省停机", target.Name),
				})
			}
		}
	}
}

func NextBillingCycleReset(now time.Time, tz string) time.Time {
	loc := loadLocation(tz)
	local := now.In(loc)
	y, m, _ := local.Date()
	return time.Date(y, m+1, 1, 0, 5, 0, 0, loc)
}

func WindowDurationHours(start, end int) int {
	if start == end {
		return 24
	}
	if start < end {
		return end - start
	}
	return (24 - start) + end
}

func inHourRange(hour, start, end int) bool {
	if start == end {
		return true
	}
	if start < end {
		return hour >= start && hour < end
	}
	return hour >= start || hour < end
}

func pickBest(eligible []domain.Server, evals map[int64]ServerEval, strategy domain.RotationStrategy, excludeID int64) domain.Server {
	cands := make([]domain.Server, 0, len(eligible))
	for _, s := range eligible {
		if excludeID != 0 && s.ID == excludeID {
			continue
		}
		cands = append(cands, s)
	}
	if len(cands) == 0 {
		cands = eligible
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if strategy == domain.StrategyExhaustSequential {
			if a.Priority != b.Priority {
				return a.Priority < b.Priority
			}
			return a.ID < b.ID
		}
		ha := evals[a.ID].CompositeHeadroom
		hb := evals[b.ID].CompositeHeadroom
		if ha != hb {
			return ha > hb
		}
		if !a.LastActiveAt.Equal(b.LastActiveAt) {
			return a.LastActiveAt.Before(b.LastActiveAt)
		}
		return a.Priority < b.Priority
	})
	return cands[0]
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
