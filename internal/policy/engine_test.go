package policy

import (
	"testing"
	"time"

	"cdt-smart-monitor/internal/domain"
)

func TestInternal30GBAnd005Buffers(t *testing.T) {
	now := time.Now()
	s := domain.Server{ID: 1, Name: "SG-1", InPool: true, KeepAlive: true, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 170.5, BilledCostUSD: 0.10}
	ev := EvaluateServer(s, now)
	if !ev.ShouldCutoff || ev.CutoffReason != "traffic_cutoff" {
		t.Fatalf("expected 170GB internal traffic cutoff, got %+v", ev)
	}
}

func TestRefreshDeltaPriority(t *testing.T) {
	s := domain.Server{ID: 1, UsedTrafficGB: 95, PrevTrafficGB: 60, BilledCostUSD: 0.12, PrevCostUSD: 0.10}
	if ok, _ := CheckRefreshDelta(s, false, 0, 60); !ok {
		t.Fatalf("expected non-peak 35GB delta to trigger switch")
	}
	if ok, r := CheckRefreshDelta(s, true, 40, 60); ok {
		t.Fatalf("expected peak burst cap to override global 30GB delta, got switch: %s", r)
	}
	s.BilledCostUSD = 0.16
	if ok, _ := CheckRefreshDelta(s, true, 40, 60); !ok {
		t.Fatalf("expected >$0.05 cost delta to trigger switch")
	}
}

func TestTwoMachinePeakAutoSplit(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Date(2026, 11, 20, 21, 0, 0, 0, loc)
	pool := domain.PoolConfig{
		Enabled:               true,
		Timezone:              "Asia/Shanghai",
		ActiveStartHour:       8,
		ActiveEndHour:         24,
		PeakStartHour:         18,
		PeakEndHour:           24,
		PeakMaxSliceGB:        35,
		Strategy:              domain.StrategySmartHybrid,
		StopMode:              domain.StopModeStopCharging,
		MakeBeforeBreak:       true,
		CurrentServerID:       1,
		CurrentSliceStartedAt: now.Add(-180 * time.Minute),
	}
	servers := []domain.Server{
		{ID: 1, Name: "SG-1", InPool: true, KeepAlive: true, Status: domain.StatusRunning, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 20, PrevTrafficGB: 20},
		{ID: 2, Name: "JP-2", InPool: true, KeepAlive: true, Status: domain.StatusStopped, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 10, PrevTrafficGB: 10},
	}
	dec := EvaluatePool(pool, servers, now)
	if dec.AutoPeakSliceMins != 180 || dec.TargetServerID != 2 {
		t.Fatalf("expected 180m slice and handoff to #2, got %+v", dec)
	}
}

func TestSpotKeepAliveAndFailover(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Date(2026, 11, 20, 15, 0, 0, 0, loc)
	pool := domain.PoolConfig{
		Enabled:               true,
		Timezone:              "Asia/Shanghai",
		ActiveStartHour:       8,
		ActiveEndHour:         24,
		PeakStartHour:         18,
		PeakEndHour:           24,
		Strategy:              domain.StrategySmartHybrid,
		StopMode:              domain.StopModeStopCharging,
		CurrentServerID:       1,
		CurrentSliceStartedAt: now.Add(-10 * time.Minute),
	}
	// Preempted duty machine -> should restart via keep-alive
	servers := []domain.Server{
		{ID: 1, Name: "HK-1", InPool: true, KeepAlive: true, KeepAliveFails: 1, Status: domain.StatusStopped, MaxTrafficGB: 200, MaxCostUSD: 0.50},
		{ID: 2, Name: "SG-2", InPool: true, KeepAlive: true, KeepAliveFails: 0, Status: domain.StatusStopped, MaxTrafficGB: 200, MaxCostUSD: 0.50},
	}
	dec1 := EvaluatePool(pool, servers, now)
	if dec1.TargetServerID != 1 || len(dec1.Actions) != 1 || dec1.Actions[0].Type != "start" {
		t.Fatalf("expected keep-alive restart of #1, got %+v", dec1)
	}

	// After 3 consecutive keep-alive failures -> auto failover to #2
	servers[0].KeepAliveFails = 3
	dec2 := EvaluatePool(pool, servers, now)
	if dec2.TargetServerID != 2 {
		t.Fatalf("expected failover to #2 after 3 keep-alive fails, got %+v", dec2)
	}
}

func TestDynamicPeakRebalance(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Date(2026, 11, 20, 22, 0, 0, 0, loc) // Even day (20), 2nd peak slot
	pool := domain.PoolConfig{
		Enabled:         true,
		Timezone:        "Asia/Shanghai",
		ActiveStartHour: 8,
		ActiveEndHour:   24,
		PeakStartHour:   18,
		PeakEndHour:     24,
		Strategy:        domain.StrategySmartHybrid,
		StopMode:        domain.StopModeStopCharging,
		CurrentServerID: 2,
	}
	// hk2 has burned 130GB (low headroom) while hk only burned 10GB (gap > 20%) -> hk must take over!
	servers := []domain.Server{
		{ID: 1, Name: "hk", InPool: true, Priority: 10, Status: domain.StatusStopped, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 10, PrevTrafficGB: 10},
		{ID: 2, Name: "hk2", InPool: true, Priority: 20, Status: domain.StatusRunning, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 130, PrevTrafficGB: 130},
	}
	dec := EvaluatePool(pool, servers, now)
	if dec.TargetServerID != 1 {
		t.Fatalf("expected hk (#1) to take over due to >20%% headroom gap, got target #%d", dec.TargetServerID)
	}
}

func TestPeakBurstCapNoPingPong(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Date(2026, 11, 20, 19, 0, 0, 0, loc) // Even day (20), 1st peak slot -> #1 is scheduled
	pool := domain.PoolConfig{
		Enabled:                    true,
		Timezone:                   "Asia/Shanghai",
		ActiveStartHour:            8,
		ActiveEndHour:              24,
		PeakStartHour:              18,
		PeakEndHour:                24,
		PeakMaxSliceGB:             35,
		Strategy:                   domain.StrategySmartHybrid,
		StopMode:                   domain.StopModeStopCharging,
		MakeBeforeBreak:            true,
		CurrentServerID:            1,
		CurrentSliceStartedAt:      now.Add(-60 * time.Minute),
		CurrentSliceStartTrafficGB: 10,
	}
	// #1 hits 35GB peak burst cap (10 -> 46GB)
	servers := []domain.Server{
		{ID: 1, Name: "hk", InPool: true, Priority: 10, Status: domain.StatusRunning, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 46, PrevTrafficGB: 44},
		{ID: 2, Name: "hk2", InPool: true, Priority: 20, Status: domain.StatusStopped, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 40, PrevTrafficGB: 40},
	}
	dec1 := EvaluatePool(pool, servers, now)
	if dec1.TargetServerID != 2 || !dec1.ResetSliceTracking {
		t.Fatalf("expected burst-cap handoff to #2, got %+v", dec1)
	}
	if !dec1.PeakOverrideUntil.After(now) {
		t.Fatalf("expected PeakOverrideUntil to be set in future, got %v", dec1.PeakOverrideUntil)
	}

	// 1 minute later: #2 is now duty and running; must NOT bounce back to #1 within same slot
	pool.CurrentServerID = 2
	pool.CurrentSliceStartedAt = now
	pool.CurrentSliceStartTrafficGB = 40
	pool.PeakOverrideUntil = dec1.PeakOverrideUntil
	servers[0].Status = domain.StatusStopped
	servers[1].Status = domain.StatusRunning
	dec2 := EvaluatePool(pool, servers, now.Add(1*time.Minute))
	if dec2.TargetServerID != 2 {
		t.Fatalf("expected #2 to stay on duty without ping-ponging to #1, got %+v", dec2)
	}
}

func TestExpiredLockCanReLock(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Date(2026, 12, 5, 12, 0, 0, 0, loc)
	expired := time.Date(2026, 12, 1, 0, 5, 0, 0, loc).Format(time.RFC3339)

	pool := domain.PoolConfig{
		Enabled:         true,
		Timezone:        "Asia/Shanghai",
		ActiveStartHour: 8,
		ActiveEndHour:   24,
		PeakStartHour:   18,
		PeakEndHour:     24,
		Strategy:        domain.StrategySmartHybrid,
	}
	// Server still has stale expired LockedUntil from previous cycle, and now hits traffic cutoff again
	servers := []domain.Server{
		{ID: 1, Name: "hk", InPool: true, Status: domain.StatusRunning, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 175, LockedUntil: expired, LockReason: "cost_cutoff"},
	}
	dec := EvaluatePool(pool, servers, now)
	foundLock := false
	for _, a := range dec.Actions {
		if a.Type == "lock" && a.ServerID == 1 && a.Reason == "traffic_cutoff" {
			foundLock = true
		}
	}
	if !foundLock {
		t.Fatalf("expected expired lock to be replaced by fresh traffic_cutoff lock, got actions: %+v", dec.Actions)
	}
}

func TestWeightedDynamicLoadBalancing(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Date(2026, 11, 20, 19, 0, 0, 0, loc)
	pool := domain.PoolConfig{
		Enabled:         true,
		Timezone:        "Asia/Shanghai",
		ActiveStartHour: 8,
		ActiveEndHour:   24,
		PeakStartHour:   18,
		PeakEndHour:     24,
		Strategy:        domain.StrategySmartHybrid,
	}

	// Moderate imbalance (~18% gap): hk1 has ~90% headroom, hk2 has ~72% headroom
	// Smooth weighted allocation should give hk1 4 peak hours and hk2 2 peak hours (smooth rebalancing, no cliff starvation)
	servers := []domain.Server{
		{ID: 1, Name: "hk1", InPool: true, Priority: 10, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 17},
		{ID: 2, Name: "hk2", InPool: true, Priority: 20, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 48},
	}
	sched := BuildDailySchedule(pool, servers, now)
	if len(sched.ServerPlans) != 2 {
		t.Fatalf("expected 2 server plans, got %d", len(sched.ServerPlans))
	}
	if sched.ServerPlans[0].PeakHours <= sched.ServerPlans[1].PeakHours {
		t.Fatalf("expected healthier hk1 to get more peak hours than hk2, got hk1=%d hk2=%d", sched.ServerPlans[0].PeakHours, sched.ServerPlans[1].PeakHours)
	}
	if sched.ServerPlans[1].PeakHours == 0 {
		t.Fatalf("expected moderate imbalance not to starve hk2 completely, got hk2 peak=%d", sched.ServerPlans[1].PeakHours)
	}
	if sched.ServerPlans[0].ScheduledHours+sched.ServerPlans[1].ScheduledHours != 16 {
		t.Fatalf("expected 16 active hours total, got %d", sched.ServerPlans[0].ScheduledHours+sched.ServerPlans[1].ScheduledHours)
	}
	if sched.BalanceScore <= 0 || sched.BalanceScore >= 100 {
		t.Fatalf("expected realistic balance score between 1 and 99, got %d", sched.BalanceScore)
	}
}

func TestManualSelectionAndAutoRevert(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Date(2026, 11, 20, 19, 15, 0, 0, loc)
	servers := []domain.Server{
		{ID: 1, Name: "hk1", InPool: true, Priority: 10, Status: domain.StatusRunning, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 10, PrevTrafficGB: 10},
		{ID: 2, Name: "hk2", InPool: true, Priority: 20, Status: domain.StatusStopped, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 15, PrevTrafficGB: 15},
	}
	pool := domain.PoolConfig{
		Enabled:                 true,
		Timezone:                "Asia/Shanghai",
		ActiveStartHour:         8,
		ActiveEndHour:           24,
		PeakStartHour:           18,
		PeakEndHour:             24,
		Strategy:                domain.StrategySmartHybrid,
		StopMode:                domain.StopModeStopCharging,
		MakeBeforeBreak:         true,
		CurrentServerID:         1,
		ManualServerID:          2,
		ManualSelectedAt:        now,
		ManualAutoRevertMode:    domain.ManualRevertNextSlot,
		ManualAutoRevertMinutes: 120,
	}

	// Verify next_slot computes 21:00 (when balanced 3h peak slot changes from hk1 to hk2)
	until := ComputeManualUntil(pool, servers, now, domain.ManualRevertNextSlot, 120)
	if until.In(loc).Hour() != 21 || until.In(loc).Minute() != 0 {
		t.Fatalf("expected next_slot revert at 21:00, got %v", until.In(loc))
	}
	pool.ManualUntil = until

	// 1. While manual pin is active (19:30 < 21:00), hk2 must be targeted even though auto schedule assigns hk1
	dec1 := EvaluatePool(pool, servers, now.Add(15*time.Minute))
	if dec1.ScheduleMode != "manual_live" || dec1.TargetServerID != 2 || dec1.ClearManualSelection {
		t.Fatalf("expected manual_live targeting #2, got %+v", dec1)
	}

	// 2. Once ManualUntil passes (21:00), ClearManualSelection must fire to auto-revert to smart scheduling
	dec2 := EvaluatePool(pool, servers, until)
	if !dec2.ClearManualSelection {
		t.Fatalf("expected auto-revert ClearManualSelection at ManualUntil, got %+v", dec2)
	}

	// 3. Safety cutoff ALWAYS overrides manual pin
	servers[1].UsedTrafficGB = 175
	servers[1].Status = domain.StatusRunning
	dec3 := EvaluatePool(pool, servers, now.Add(20*time.Minute))
	if !dec3.ClearManualSelection || dec3.TargetServerID != 1 {
		t.Fatalf("expected safety cutoff to override manual pin #2 and fall back to #1, got %+v", dec3)
	}
}

func TestHourlyManualScheduleOverridesAndDailyReset(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Date(2026, 11, 20, 19, 10, 0, 0, loc)
	servers := []domain.Server{
		{ID: 1, Name: "hk1", InPool: true, Priority: 10, Status: domain.StatusRunning, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 10, PrevTrafficGB: 10},
		{ID: 2, Name: "hk2", InPool: true, Priority: 20, Status: domain.StatusStopped, MaxTrafficGB: 200, MaxCostUSD: 0.50, UsedTrafficGB: 10, PrevTrafficGB: 10},
	}
	pool := domain.PoolConfig{
		Enabled:                       true,
		Timezone:                      "Asia/Shanghai",
		ActiveStartHour:               8,
		ActiveEndHour:                 24,
		PeakStartHour:                 18,
		PeakEndHour:                   24,
		Strategy:                      domain.StrategySmartHybrid,
		StopMode:                      domain.StopModeStopCharging,
		CurrentServerID:               1,
		ManualScheduleDate:            "2026-11-20",
		ManualHourlyOverrides:         map[int]int64{19: 2, 20: domain.ManualSlotForceIdle},
		ManualOverridesAutoResetDaily: true,
	}

	// Hour 19 overridden to #2
	dec19 := EvaluatePool(pool, servers, now)
	if dec19.ScheduleMode != "manual_slot" || dec19.TargetServerID != 2 {
		t.Fatalf("expected manual_slot override #2 at 19:00, got %+v", dec19)
	}

	// Hour 20 overridden to force idle (-1)
	dec20 := EvaluatePool(pool, servers, time.Date(2026, 11, 20, 20, 10, 0, 0, loc))
	if dec20.ScheduleMode != "manual_slot" || dec20.Phase != "idle" || dec20.TargetServerID != 0 {
		t.Fatalf("expected forced idle at 20:00, got %+v", dec20)
	}

	// Next day (2026-11-21 19:10): daily auto-reset clears yesterday's overrides
	decNextDay := EvaluatePool(pool, servers, time.Date(2026, 11, 21, 19, 10, 0, 0, loc))
	if !decNextDay.ResetExpiredOverrides || decNextDay.ScheduleMode != "auto" {
		t.Fatalf("expected expired hourly overrides to auto-reset next day, got %+v", decNextDay)
	}
}
