package aliyun

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestGetMonthlyBillUSDRejectsHTTP200Failures(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantErr   bool
		wantTotal float64
	}{
		{
			name:      "success_true_with_items",
			body:      `{"Success":true,"Code":"Success","Message":"Successful!","Data":{"Items":{"Item":[{"PretaxAmount":0.12},{"PretaxAmount":0.08}]}}}`,
			wantErr:   false,
			wantTotal: 0.20,
		},
		{
			name:    "http200_success_false",
			body:    `{"Success":false,"Code":"InternalError","Message":"temporary BSS failure"}`,
			wantErr: true,
		},
		{
			name:    "http200_success_false_without_code",
			body:    `{"Success":false}`,
			wantErr: true,
		},
		{
			name:    "http200_non_success_code",
			body:    `{"Code":"InvalidAccessKeyId.NotFound","Message":"Specified access key is not found."}`,
			wantErr: true,
		},
	}

	s := domain.Server{
		Site:            domain.SiteIntl,
		Region:          "cn-hongkong",
		AccessKeyID:     "AKID",
		AccessKeySecret: "AKSECRET",
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c := NewClient()
			c.bssIntlEndpt = srv.URL + "/"
			got, err := c.GetMonthlyBillUSD(context.Background(), s, time.Now(), "Asia/Shanghai")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for body %s, got sum=%f nil err", tc.body, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got < tc.wantTotal-0.0001 || got > tc.wantTotal+0.0001 {
				t.Fatalf("expected bill %.4f, got %.4f", tc.wantTotal, got)
			}
		})
	}
}

func TestDoRPCRetriesHTTP400Throttling(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch n {
		case 1:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"Code":"Throttling.User","Message":"Request was denied due to user flow control."}`))
		case 2:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"Code":"Throttling.API","Message":"Request was denied due to API flow control."}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Success":true,"Code":"Success","Data":{"Items":{"Item":[{"PretaxAmount":0.35}]}}}`))
		}
	}))
	defer srv.Close()

	c := NewClient()
	c.bssIntlEndpt = srv.URL + "/"
	c.maxAttempts = 3
	c.retryBaseDelay = 5 * time.Millisecond

	s := domain.Server{
		Site:            domain.SiteIntl,
		Region:          "cn-hongkong",
		AccessKeyID:     "AKID",
		AccessKeySecret: "AKSECRET",
	}
	bill, err := c.GetMonthlyBillUSD(context.Background(), s, time.Now(), "Asia/Shanghai")
	if err != nil {
		t.Fatalf("expected 400 Throttling to retry and succeed, got err: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 total calls (2 throttling retries), got %d", calls.Load())
	}
	if bill < 0.349 || bill > 0.351 {
		t.Fatalf("expected bill 0.35, got %.4f", bill)
	}

	// Non-throttling HTTP 400 must NOT retry.
	var badCalls atomic.Int32
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		badCalls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"Code":"InvalidParameter","Message":"bad param"}`))
	}))
	defer badSrv.Close()

	c.bssIntlEndpt = badSrv.URL + "/"
	_, err = c.GetMonthlyBillUSD(context.Background(), s, time.Now(), "Asia/Shanghai")
	if err == nil || !strings.Contains(err.Error(), "InvalidParameter") {
		t.Fatalf("expected InvalidParameter error, got %v", err)
	}
	if badCalls.Load() != 1 {
		t.Fatalf("non-throttling 400 must not retry, got %d calls", badCalls.Load())
	}
}

func TestValidateRegionBlocksURLInjection(t *testing.T) {
	c := NewClient()
	s := domain.Server{
		Region:          "cn-hongkong@evil.com/foo#",
		InstanceID:      "i-123",
		AccessKeyID:     "AKID",
		AccessKeySecret: "AKSECRET",
	}
	if _, err := c.DescribeInstance(context.Background(), s); err == nil {
		t.Fatal("expected invalid region to be rejected")
	}
	if err := c.StartInstance(context.Background(), s); err == nil {
		t.Fatal("expected invalid region to be rejected on StartInstance")
	}
	if err := c.StopInstance(context.Background(), s, domain.StopModeStopCharging); err == nil {
		t.Fatal("expected invalid region to be rejected on StopInstance")
	}
}
