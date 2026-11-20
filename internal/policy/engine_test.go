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
