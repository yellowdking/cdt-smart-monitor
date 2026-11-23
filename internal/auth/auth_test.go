package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPasswordHashAndVerify(t *testing.T) {
	if _, err := HashPassword("12345"); err == nil {
		t.Fatal("expected short password to be rejected")
	}
	h, err := HashPassword("s3cure-pass!")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if !VerifyPassword("s3cure-pass!", h) {
		t.Fatal("expected correct password to verify")
	}
	if VerifyPassword("wrong-pass!", h) {
		t.Fatal("expected wrong password to fail verification")
	}
	if VerifyPassword("s3cure-pass!", "pbkdf2_sha256$999$abc$def") {
		t.Fatal("expected below-minimum iteration count to be rejected")
	}
}

func TestSessionLifecycleAndInvalidation(t *testing.T) {
	m := NewManager()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://panel.example.com/api/v1/auth/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	token := m.CreateSession(rec, req)
	if token == "" {
		t.Fatal("expected non-empty session token")
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("expected Secure HttpOnly cookie, got %+v", cookies)
	}

	authReq := httptest.NewRequest(http.MethodGet, "https://panel.example.com/api/v1/state", nil)
	authReq.AddCookie(cookies[0])
	if !m.IsAuthenticated(authReq) {
		t.Fatal("expected valid session to be authenticated")
	}

	m.InvalidateAllSessions()
	if m.IsAuthenticated(authReq) {
		t.Fatal("expected session to be invalid after InvalidateAllSessions")
	}
}

func TestRateLimiting(t *testing.T) {
	m := NewManager()
	ip := "203.0.113.10"
	for i := 0; i < maxLoginFailures; i++ {
		if err := m.CheckRateLimit(ip); err != nil {
			t.Fatalf("unexpected rate limit before max failures (iter %d): %v", i, err)
		}
		m.RecordFailure(ip)
	}
	if err := m.CheckRateLimit(ip); err == nil {
		t.Fatal("expected rate limit error after max failures")
	}
	m.ClearFailures(ip)
	if err := m.CheckRateLimit(ip); err != nil {
		t.Fatalf("expected cleared IP to pass rate limit: %v", err)
	}
}

func TestVerifyOrigin(t *testing.T) {
	if err := VerifyOrigin("https://cdt.example.com", "cdt.example.com"); err != nil {
		t.Fatalf("expected exact HTTPS origin match to pass: %v", err)
	}
	if err := VerifyOrigin("https://sub.example.com:8443", "example.com"); err != nil {
		t.Fatalf("expected subdomain HTTPS origin match to pass: %v", err)
	}
	if err := VerifyOrigin("http://localhost:8080", "localhost"); err != nil {
		t.Fatalf("expected localhost HTTP origin to pass: %v", err)
	}
	if err := VerifyOrigin("http://cdt.example.com", "cdt.example.com"); err == nil {
		t.Fatal("expected non-localhost HTTP origin to be rejected")
	}
	if err := VerifyOrigin("https://evil.com", "cdt.example.com"); err == nil {
		t.Fatal("expected mismatched origin host to be rejected")
	}
}
