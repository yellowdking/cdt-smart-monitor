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
	CompositeHeadroom   float64
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
	Phase              string
	TargetServerID     int64
	AutoPeakSliceMins  int
	ResetSliceTracking bool
	Actions            []Action
	Summary            string
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
		CompositeHeadroom:   math.Min(tRatio, cRatio),
	}

	if s.LockedUntil != "" {
		if t, err := time.Parse(time.RFC3339, s.LockedUntil); err == nil && now.Before(t) {
			ev.ShouldCutoff = true
			ev.CutoffReason = s.LockReason
			if ev.CutoffReason == "" {
				ev.CutoffReason = "cost_cutoff"
			}
			ev.CompositeHeadroom = 0
			return ev
		}
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

// EvaluatePool evaluates dual-threshold cutoff, idle collective shutdown, spot keep-alive (with 3-fail failover),
// refresh-delta protection, and clock-aligned auto-balanced peak rotation (matching the 24h Gantt preview).
func EvaluatePool(pool domain.PoolConfig, servers []domain.Server, now time.Time) Decision {
	if len(servers) == 0 {
		return Decision{Phase: "disabled", Summary: "暂无服务器"}
	}
	loc, err := time.LoadLocation(pool.Timezone)
	if err != nil {
		loc = time.UTC
	}
	localNow := now.In(loc)
	stopMode := pool.StopMode
	if stopMode == "" {
		stopMode = domain.StopModeStopCharging
	}

	dec := Decision{}
	evals := make(map[int64]ServerEval, len(servers))
	eligible := make([]domain.Server, 0, len(servers))
	standaloneKeepAlive := make([]domain.Server, 0)

	// 1. Dual-threshold safety check across ALL servers (ALWAYS overrides keep-alive & rotation)
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
			if s.LockedUntil == "" {
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

	if !pool.Enabled {
		dec.Phase = "disabled"
		dec.Summary = "智能轮换未启用（单机熔断与抢占式保活正常运行）"
		return dec
	}

	// 2. Idle window -> collective shutdown (overrides keep-alive)
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

	// 3. All exhausted
	if len(eligible) == 0 {
		dec.Phase = "all_exhausted"
		dec.Summary = "池内所有服务器均已达到流量或金额安全线"
		dec.Actions = append(dec.Actions, Action{
			ServerID: 0,
			Type:     "notify",
			Reason:   "全池服务器均已触及流量或金额安全线，已全部熔断停机",
		})
		return dec
	}

	// Sort eligible deterministically by Priority, ID so clock-aligned slots match 24h Gantt preview
	sort.SliceStable(eligible, func(i, j int) bool {
		if eligible[i].Priority != eligible[j].Priority {
			return eligible[i].Priority < eligible[j].Priority
		}
		return eligible[i].ID < eligible[j].ID
	})

	// 4. Peak vs Normal phase & dynamic self-balancing peak slot
	//    - Layer 1 (Headroom Imbalance >= 20%): healthiest machine automatically takes over heavy peak slots until balanced.
	//    - Layer 2 (Balanced): daily slot shift ((day + clockSlot) % N) automatically swaps peak windows each day.
	inPeak := inHourRange(localNow.Hour(), pool.PeakStartHour, pool.PeakEndHour)
	var scheduledPeakServer *domain.Server
	peakReasonTag := ""
	if inPeak {
		dec.Phase = "peak"
		peakHours := WindowDurationHours(pool.PeakStartHour, pool.PeakEndHour)
		dec.AutoPeakSliceMins = int(math.Max(15, math.Round(float64(peakHours*60)/float64(len(eligible)))))
		if len(eligible) >= domain.MinSmartRotationInstances && pool.Strategy != domain.StrategyExhaustSequential {
			maxH, minH := -1.0, 2.0
			bestIdx := 0
			for i, s := range eligible {
				h := evals[s.ID].CompositeHeadroom
				if h > maxH {
					maxH = h
					bestIdx = i
				}
				if h < minH {
					minH = h
				}
			}
			if (maxH - minH) >= 0.20 {
				cand := eligible[bestIdx]
				scheduledPeakServer = &cand
				peakReasonTag = fmt.Sprintf("余量失衡纠偏（余量差 %.0f%%），优先由 %s 顶班", (maxH-minH)*100, cand.Name)
			} else {
				minsSinceStart := (localNow.Hour()*60 + localNow.Minute()) - pool.PeakStartHour*60
				if minsSinceStart < 0 {
					minsSinceStart += 24 * 60
				}
				dayOffset := localNow.Day() % len(eligible)
				slotIdx := (minsSinceStart/dec.AutoPeakSliceMins + dayOffset) % len(eligible)
				cand := eligible[slotIdx]
				scheduledPeakServer = &cand
				peakReasonTag = fmt.Sprintf("按日动态轮转高峰槽位（每台 %d 分钟）切换至 %s", dec.AutoPeakSliceMins, cand.Name)
			}
		}
	} else {
		dec.Phase = "normal"
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
		if scheduledPeakServer != nil {
			forcedTarget = scheduledPeakServer
			reason = peakReasonTag
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
		} else if scheduledPeakServer != nil && current.ID != scheduledPeakServer.ID {
			// Clock-aligned peak handoff: matches the exact 24h Gantt schedule preview!
			// Avoid bouncing back if we just switched away from scheduledPeakServer within this slot due to failover/delta.
			if scheduledPeakServer.KeepAliveFails < domain.MaxKeepAliveFailures {
				needSwitch = true
				forcedTarget = scheduledPeakServer
				reason = peakReasonTag
			}
		} else if !inPeak && len(eligible) >= domain.MinSmartRotationInstances && pool.Strategy != domain.StrategyExhaustSequential {
			normalMins := 360
			if pool.Strategy == domain.StrategyContinuousRoundRobin {
				normalMins = 180
			}
			if !pool.CurrentSliceStartedAt.IsZero() && now.Sub(pool.CurrentSliceStartedAt) >= time.Duration(normalMins)*time.Minute {
				needSwitch = true
				reason = fmt.Sprintf("平峰值班满 %d 分钟，均衡切换下一台", normalMins)
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
			if !pool.MakeBeforeBreak || targetRunning {
				dec.Actions = append(dec.Actions, Action{
					ServerID: s.ID,
					Type:     "stop",
					StopMode: stopMode,
					Reason:   fmt.Sprintf("已无感交接至 %s，旧机节省停机", target.Name),
				})
			}
		}
	}

	return dec
}

func NextBillingCycleReset(now time.Time, tz string) time.Time {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
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
