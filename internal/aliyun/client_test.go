package aliyun

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"cdt-smart-monitor/internal/domain"
)

func TestBillingCycleMonthBoundaryTimezone(t *testing.T) {
	// 2026-12-01 00:05 Asia/Shanghai is 2026-11-30 16:05 UTC.
	// BillingCycle in Asia/Shanghai MUST be "2026-12" (NOT "2026-11").
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Date(2026, 12, 1, 0, 5, 0, 0, loc)
	if got := BillingCycleForTime(now, "Asia/Shanghai"); got != "2026-12" {
		t.Fatalf("expected 2026-12, got %q", got)
	}
	if got := BillingCycleForTime(now, ""); got != "2026-12" {
		t.Fatalf("expected default Asia/Shanghai 2026-12, got %q", got)
	}
}

func TestDoRPCRetryAndCDTBuckets(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"Code":"ServiceUnavailable","Message":"try again"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"TrafficDetails":[{"BusinessRegionId":"cn-hongkong","Traffic":10737418240},{"BusinessRegionId":"cn-hangzhou","Traffic":21474836480}]}`))
	}))
	defer srv.Close()

	c := NewClient()
	c.cdtEndpoint = srv.URL + "/"
	c.retryBaseDelay = 10 * time.Millisecond

	s := domain.Server{
		Region:          "cn-hongkong",
		AccessKeyID:     "AKID",
		AccessKeySecret: "AKSECRET",
	}
	gb, err := c.GetCDTTrafficGB(context.Background(), s)
	if err != nil {
		t.Fatalf("GetCDTTrafficGB failed: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 1 retry (2 total calls), got %d", calls.Load())
	}
	if gb < 9.99 || gb > 10.01 {
		t.Fatalf("expected 10 GB overseas traffic for cn-hongkong, got %.4f", gb)
	}
}

func TestIsDomesticRegion(t *testing.T) {
	if isDomesticRegion("cn-hongkong") {
		t.Fatal("cn-hongkong must be treated as overseas")
	}
	if isDomesticRegion("ap-southeast-1") {
		t.Fatal("ap-southeast-1 must be treated as overseas")
	}
	if !isDomesticRegion("cn-hangzhou") {
		t.Fatal("cn-hangzhou must be treated as domestic")
	}
}
