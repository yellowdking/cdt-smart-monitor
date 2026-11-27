package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cdt-smart-monitor/internal/domain"
)

func TestPasswordHashAndVerify(t *testing.T) {
	if _, err := HashPassword("12345"); err == nil {
		t.Fatal("expected short password to be rejected")
	}
	tooLong := strings.Repeat("a", maxPasswordBytes+1)
	if _, err := HashPassword(tooLong); err == nil {
		t.Fatal("expected over-length password to be rejected by HashPassword")
	}
	exactMax := strings.Repeat("b", maxPasswordBytes)
	hMax, err := HashPassword(exactMax)
	if err != nil {
		t.Fatalf("expected max-length password to succeed: %v", err)
	}
	if !VerifyPassword(exactMax, hMax) {
		t.Fatal("expected max-length password to verify")
	}
	if VerifyPassword(tooLong, hMax) {
		t.Fatal("expected over-length password to fail VerifyPassword")
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

	// Verify 100% compatibility with previously stored PBKDF2-HMAC-SHA256 hashes.
	const legacyVector = "pbkdf2_sha256$10000$MDEyMzQ1Njc4OWFiY2RlZg$7XjWd2HQ0z+zIpVWsuydO3yE/BX+8X0MwU2DMb9pxiI"
	if !VerifyPassword("s3cure-pass!", legacyVector) {
		t.Fatal("expected stdlib crypto/pbkdf2 to match legacy PBKDF2-HMAC-SHA256 hash vector")
	}
	if VerifyPassword("wrong-pass!", legacyVector) {
		t.Fatal("expected wrong password to fail legacy PBKDF2 vector")
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

func TestAttemptsAndChallengesMapCaps(t *testing.T) {
	m := NewManager()

	// Lock one IP first, then flood with single-failure IPs beyond maxRateLimitEntries.
	lockedIP := "198.51.100.1"
	for i := 0; i < maxLoginFailures; i++ {
		m.RecordFailure(lockedIP)
	}
	for i := 0; i < maxRateLimitEntries+150; i++ {
		m.RecordFailure(fmt.Sprintf("203.0.%d.%d", i/250, i%250))
	}
	m.mu.Lock()
	attemptsLen := len(m.attempts)
	m.mu.Unlock()
	if attemptsLen > maxRateLimitEntries {
		t.Fatalf("expected attempts map capped at %d, got %d", maxRateLimitEntries, attemptsLen)
	}
	if err := m.CheckRateLimit(lockedIP); err == nil {
		t.Fatal("expected actively locked IP to remain rate-limited after single-failure flood")
	}

	// Flood challenges beyond maxChallengeEntries.
	for i := 0; i < maxChallengeEntries+50; i++ {
		if _, err := m.NewChallenge("cdt.example.com"); err != nil {
			t.Fatalf("NewChallenge failed at %d: %v", i, err)
		}
	}
	m.mu.Lock()
	challengesLen := len(m.challenges)
	m.mu.Unlock()
	if challengesLen > maxChallengeEntries {
		t.Fatalf("expected challenges map capped at %d, got %d", maxChallengeEntries, challengesLen)
	}
}

func TestProxyHeaderTrust(t *testing.T) {
	t.Run("public_peer_ignores_forwarded_headers_by_default", func(t *testing.T) {
		t.Setenv("CDT_TRUST_PROXY", "")
		req := httptest.NewRequest(http.MethodPost, "http://panel.example.com/api/v1/auth/login", nil)
		req.RemoteAddr = "203.0.113.10:54321"
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		req.Header.Set("X-Forwarded-Host", "evil.example.com")
		req.Header.Set("X-Forwarded-Proto", "https")

		if got := ClientIP(req); got != "203.0.113.10" {
			t.Fatalf("expected peer IP 203.0.113.10, got %q", got)
		}
		if got := RequestRPID(req); got != "panel.example.com" {
			t.Fatalf("expected Host RPID panel.example.com, got %q", got)
		}
		if IsHTTPS(req) {
			t.Fatal("expected spoofed X-Forwarded-Proto from public IP to be ignored")
		}
	})

	t.Run("local_reverse_proxy_trusted_and_uses_rightmost_public_hop", func(t *testing.T) {
		t.Setenv("CDT_TRUST_PROXY", "")
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/auth/login", nil)
		req.RemoteAddr = "127.0.0.1:51234"
		req.Header.Set("X-Forwarded-For", "9.9.9.9, 198.51.100.7")
		req.Header.Set("X-Forwarded-Host", "panel.example.com:8443")
		req.Header.Set("X-Forwarded-Proto", "https")

		if got := ClientIP(req); got != "198.51.100.7" {
			t.Fatalf("expected rightmost public hop 198.51.100.7, got %q", got)
		}
		if got := RequestRPID(req); got != "panel.example.com" {
			t.Fatalf("expected forwarded RPID panel.example.com, got %q", got)
		}
		if !IsHTTPS(req) {
			t.Fatal("expected local reverse proxy X-Forwarded-Proto=https to be trusted")
		}
	})

	t.Run("explicit_env_trust_proxy_enabled", func(t *testing.T) {
		t.Setenv("CDT_TRUST_PROXY", "true")
		req := httptest.NewRequest(http.MethodPost, "http://panel.example.com/api/v1/auth/login", nil)
		req.RemoteAddr = "173.245.48.1:443"
		req.Header.Set("X-Forwarded-For", "1.1.1.1, 198.51.100.42, 10.0.0.5")
		req.Header.Set("X-Forwarded-Proto", "https")

		if got := ClientIP(req); got != "198.51.100.42" {
			t.Fatalf("expected rightmost non-private hop 198.51.100.42, got %q", got)
		}
		if !IsHTTPS(req) {
			t.Fatal("expected X-Forwarded-Proto=https to be trusted when CDT_TRUST_PROXY=true")
		}
	})

	t.Run("explicit_env_trust_proxy_disabled", func(t *testing.T) {
		t.Setenv("CDT_TRUST_PROXY", "false")
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/auth/login", nil)
		req.RemoteAddr = "127.0.0.1:51234"
		req.Header.Set("X-Forwarded-For", "198.51.100.7")
		req.Header.Set("X-Forwarded-Proto", "https")

		if got := ClientIP(req); got != "127.0.0.1" {
			t.Fatalf("expected direct peer 127.0.0.1 when CDT_TRUST_PROXY=false, got %q", got)
		}
		if IsHTTPS(req) {
			t.Fatal("expected X-Forwarded-Proto ignored when CDT_TRUST_PROXY=false")
		}
	})
}

func TestVerifyOrigin(t *testing.T) {
	if err := VerifyOrigin("https://cdt.example.com", "cdt.example.com"); err != nil {
		t.Fatalf("expected exact HTTPS origin match to pass: %v", err)
	}
	if err := VerifyOrigin("https://cdt.example.com:8443", "cdt.example.com"); err != nil {
		t.Fatalf("expected exact HTTPS origin with port to pass: %v", err)
	}
	if err := VerifyOrigin("https://sub.example.com:8443", "example.com"); err == nil {
		t.Fatal("expected subdomain origin mismatch to be rejected")
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

func buildRegAuthData(rpID string, flags byte, signCount uint32, rawCredID []byte) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	buf := make([]byte, 37+16+2+len(rawCredID))
	copy(buf[:32], rpHash[:])
	buf[32] = flags
	binary.BigEndian.PutUint32(buf[33:37], signCount)
	// bytes 37..52: zero AAGUID
	binary.BigEndian.PutUint16(buf[53:55], uint16(len(rawCredID)))
	copy(buf[55:], rawCredID)
	return buf
}

func buildAssertionPayload(t *testing.T, priv *ecdsa.PrivateKey, rpID, challenge, origin string, signCount uint32) (string, string, string) {
	t.Helper()
	cdJSON, err := json.Marshal(clientData{
		Type:      "webauthn.get",
		Challenge: challenge,
		Origin:    origin,
	})
	if err != nil {
		t.Fatalf("marshal clientData: %v", err)
	}
	rpHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 37)
	copy(authData[:32], rpHash[:])
	authData[32] = 0x01 // UP flag
	binary.BigEndian.PutUint32(authData[33:37], signCount)

	cdHash := sha256.Sum256(cdJSON)
	signed := append(append([]byte(nil), authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("SignASN1 failed: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(cdJSON),
		base64.RawURLEncoding.EncodeToString(authData),
		base64.RawURLEncoding.EncodeToString(sig)
}

func TestPasskeyRegistrationAndSignCountReplay(t *testing.T) {
	m := NewManager()
	const rpID = "cdt.example.com"
	const origin = "https://cdt.example.com"

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	p256SPKI, err := x509.MarshalPKIXPublicKey(&p256Key.PublicKey)
	if err != nil {
		t.Fatalf("marshal P-256 SPKI: %v", err)
	}
	p256SPKIB64 := base64.RawURLEncoding.EncodeToString(p256SPKI)

	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	p384SPKI, err := x509.MarshalPKIXPublicKey(&p384Key.PublicKey)
	if err != nil {
		t.Fatalf("marshal P-384 SPKI: %v", err)
	}
	p384SPKIB64 := base64.RawURLEncoding.EncodeToString(p384SPKI)

	rawCredID := []byte("cred-id-0123456789")
	credID := base64.RawURLEncoding.EncodeToString(rawCredID)

	// Missing AT flag (0x40) must be rejected on registration.
	chNoAT, _ := m.NewChallenge(rpID)
	cdNoAT, _ := json.Marshal(clientData{Type: "webauthn.create", Challenge: chNoAT, Origin: origin})
	adNoAT := buildRegAuthData(rpID, 0x01, 5, rawCredID)
	if _, err := m.VerifyPasskeyRegistration(credID, "Key", base64.RawURLEncoding.EncodeToString(cdNoAT), base64.RawURLEncoding.EncodeToString(adNoAT), p256SPKIB64); err == nil {
		t.Fatal("expected registration without AT flag to be rejected")
	}

	// Non-P-256 curve (P-384) must be rejected.
	chP384, _ := m.NewChallenge(rpID)
	cdP384, _ := json.Marshal(clientData{Type: "webauthn.create", Challenge: chP384, Origin: origin})
	adValid := buildRegAuthData(rpID, 0x41, 5, rawCredID)
	if _, err := m.VerifyPasskeyRegistration(credID, "Key", base64.RawURLEncoding.EncodeToString(cdP384), base64.RawURLEncoding.EncodeToString(adValid), p384SPKIB64); err == nil {
		t.Fatal("expected P-384 key to be rejected on registration")
	}

	// Valid P-256 registration with UP|AT flags succeeds.
	chReg, _ := m.NewChallenge(rpID)
	cdReg, _ := json.Marshal(clientData{Type: "webauthn.create", Challenge: chReg, Origin: origin})
	cred, err := m.VerifyPasskeyRegistration(credID, "MacBook", base64.RawURLEncoding.EncodeToString(cdReg), base64.RawURLEncoding.EncodeToString(adValid), p256SPKIB64)
	if err != nil {
		t.Fatalf("expected valid registration to pass: %v", err)
	}
	if cred.SignCount != 5 {
		t.Fatalf("expected SignCount=5, got %d", cred.SignCount)
	}

	creds := []domain.PasskeyCredential{cred}

	// SignCount replay: newCount == 0 when stored SignCount == 5 MUST be rejected!
	chZero, _ := m.NewChallenge(rpID)
	cdB64, adB64, sigB64 := buildAssertionPayload(t, p256Key, rpID, chZero, origin, 0)
	if _, _, err := m.VerifyPasskeyAssertion(creds, credID, cdB64, adB64, sigB64); err == nil {
		t.Fatal("expected SignCount replay (newCount=0 when SignCount=5) to be rejected")
	}

	// SignCount replay: newCount == 5 when stored SignCount == 5 MUST be rejected!
	chEq, _ := m.NewChallenge(rpID)
	cdB64, adB64, sigB64 = buildAssertionPayload(t, p256Key, rpID, chEq, origin, 5)
	if _, _, err := m.VerifyPasskeyAssertion(creds, credID, cdB64, adB64, sigB64); err == nil {
		t.Fatal("expected SignCount replay (newCount=5 when SignCount=5) to be rejected")
	}

	// Valid increment: newCount == 6 when stored SignCount == 5 MUST pass.
	chInc, _ := m.NewChallenge(rpID)
	cdB64, adB64, sigB64 = buildAssertionPayload(t, p256Key, rpID, chInc, origin, 6)
	name, newCount, err := m.VerifyPasskeyAssertion(creds, credID, cdB64, adB64, sigB64)
	if err != nil {
		t.Fatalf("expected valid SignCount increment to pass: %v", err)
	}
	if name != "MacBook" || newCount != 6 {
		t.Fatalf("unexpected assertion result: name=%q newCount=%d", name, newCount)
	}

	// Synced passkey without counter (stored 0, new 0) MUST still pass.
	zeroCred := cred
	zeroCred.SignCount = 0
	chSynced, _ := m.NewChallenge(rpID)
	cdB64, adB64, sigB64 = buildAssertionPayload(t, p256Key, rpID, chSynced, origin, 0)
	if _, cnt, err := m.VerifyPasskeyAssertion([]domain.PasskeyCredential{zeroCred}, credID, cdB64, adB64, sigB64); err != nil || cnt != 0 {
		t.Fatalf("expected 0->0 counter passkey to succeed, got cnt=%d err=%v", cnt, err)
	}
}
