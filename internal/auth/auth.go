package auth

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"cdt-smart-monitor/internal/domain"
)

const (
	SessionCookieName = "cdt_smart_session"
	sessionTTL        = 7 * 24 * time.Hour
	challengeTTL      = 5 * time.Minute
	maxLoginFailures  = 5
	rateLimitWindow   = 15 * time.Minute
	pbkdf2Iterations  = 100000
)

type sessionEntry struct {
	ExpiresAt time.Time
}

type challengeEntry struct {
	Challenge string
	RPID      string
	ExpiresAt time.Time
}

type rateLimitEntry struct {
	Failures  int
	FirstFail time.Time
}

type Manager struct {
	mu         sync.Mutex
	sessions   map[string]sessionEntry
	challenges map[string]challengeEntry
	attempts   map[string]rateLimitEntry
}

func NewManager() *Manager {
	return &Manager{
		sessions:   make(map[string]sessionEntry),
		challenges: make(map[string]challengeEntry),
		attempts:   make(map[string]rateLimitEntry),
	}
}

// --- Password Hashing (PBKDF2-HMAC-SHA256, pure stdlib) ---

func HashPassword(password string) (string, error) {
	if len(password) < 6 {
		return "", fmt.Errorf("密码长度至少需要 6 位")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, 32)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s",
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	), nil
}

func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	expected, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(expected) == 0 {
		return false
	}
	dk := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, len(expected))
	return subtle.ConstantTimeCompare(dk, expected) == 1
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(data []byte) []byte {
		h := hmac.New(sha256.New, password)
		h.Write(data)
		return h.Sum(nil)
	}
	hashLen := 32
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var out []byte
	for block := 1; block <= numBlocks; block++ {
		buf := make([]byte, len(salt)+4)
		copy(buf, salt)
		binary.BigEndian.PutUint32(buf[len(salt):], uint32(block))
		u := prf(buf)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			u = prf(u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// --- Sessions & Rate Limiting ---

func (m *Manager) CheckRateLimit(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ent, ok := m.attempts[ip]
	if !ok {
		return nil
	}
	if time.Since(ent.FirstFail) > rateLimitWindow {
		delete(m.attempts, ip)
		return nil
	}
	if ent.Failures >= maxLoginFailures {
		rem := int(time.Until(ent.FirstFail.Add(rateLimitWindow)).Minutes()) + 1
		return fmt.Errorf("登录失败次数过多，请 %d 分钟后再试", rem)
	}
	return nil
}

func (m *Manager) RecordFailure(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ent, ok := m.attempts[ip]
	if !ok || time.Since(ent.FirstFail) > rateLimitWindow {
		m.attempts[ip] = rateLimitEntry{Failures: 1, FirstFail: time.Now()}
		return
	}
	ent.Failures++
	m.attempts[ip] = ent
}

func (m *Manager) ClearFailures(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.attempts, ip)
}

func (m *Manager) CreateSession(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)

	m.mu.Lock()
	m.sessions[token] = sessionEntry{ExpiresAt: time.Now().Add(sessionTTL)}
	m.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   IsHTTPS(r),
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func (m *Manager) DestroySession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookieName); err == nil {
		m.mu.Lock()
		delete(m.sessions, c.Value)
		m.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

func (m *Manager) IsAuthenticated(r *http.Request) bool {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ent, ok := m.sessions[c.Value]
	if !ok {
		return false
	}
	if time.Now().After(ent.ExpiresAt) {
		delete(m.sessions, c.Value)
		return false
	}
	return true
}

// --- WebAuthn Passkey (ES256 / P-256 ECDSA, pure stdlib) ---

func (m *Manager) NewChallenge(rpID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	ch := base64.RawURLEncoding.EncodeToString(b)
	m.mu.Lock()
	now := time.Now()
	for k, v := range m.challenges {
		if now.After(v.ExpiresAt) {
			delete(m.challenges, k)
		}
	}
	m.challenges[ch] = challengeEntry{
		Challenge: ch,
		RPID:      rpID,
		ExpiresAt: now.Add(challengeTTL),
	}
	m.mu.Unlock()
	return ch, nil
}

func (m *Manager) consumeChallenge(ch string) (challengeEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ent, ok := m.challenges[ch]
	if !ok {
		return challengeEntry{}, false
	}
	delete(m.challenges, ch)
	if time.Now().After(ent.ExpiresAt) {
		return challengeEntry{}, false
	}
	return ent, true
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// VerifyPasskeyRegistration verifies clientDataJSON, rpIdHash, and parses SPKI ECDSA P-256 public key.
func (m *Manager) VerifyPasskeyRegistration(credID, name, clientDataB64, authDataB64, pubKeySPKIB64 string) (domain.PasskeyCredential, error) {
	cdBytes, err := decodeB64URL(clientDataB64)
	if err != nil {
		return domain.PasskeyCredential{}, fmt.Errorf("无效的 clientDataJSON")
	}
	var cd clientData
	if err := json.Unmarshal(cdBytes, &cd); err != nil {
		return domain.PasskeyCredential{}, fmt.Errorf("解析 clientDataJSON 失败")
	}
	if cd.Type != "webauthn.create" {
		return domain.PasskeyCredential{}, fmt.Errorf("无效的 WebAuthn 类型: %s", cd.Type)
	}
	ent, ok := m.consumeChallenge(cd.Challenge)
	if !ok {
		return domain.PasskeyCredential{}, fmt.Errorf("Passkey Challenge 已过期或无效，请重试")
	}

	authData, err := decodeB64URL(authDataB64)
	if err != nil || len(authData) < 37 {
		return domain.PasskeyCredential{}, fmt.Errorf("无效的 authenticatorData")
	}
	expectedRP := sha256.Sum256([]byte(ent.RPID))
	if subtle.ConstantTimeCompare(authData[:32], expectedRP[:]) != 1 {
		return domain.PasskeyCredential{}, fmt.Errorf("RP ID 校验不匹配（请确认域名与 HTTPS 配置）")
	}
	if authData[32]&0x01 == 0 {
		return domain.PasskeyCredential{}, fmt.Errorf("未检测到用户确认（UP flag）")
	}

	spkiBytes, err := decodeB64URL(pubKeySPKIB64)
	if err != nil {
		return domain.PasskeyCredential{}, fmt.Errorf("无效的公钥数据")
	}
	pub, err := x509.ParsePKIXPublicKey(spkiBytes)
	if err != nil {
		return domain.PasskeyCredential{}, fmt.Errorf("解析 Passkey 公钥失败: %w", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		return domain.PasskeyCredential{}, fmt.Errorf("仅支持 ES256 (ECDSA P-256) Passkey 算法")
	}

	if strings.TrimSpace(name) == "" {
		name = "Passkey " + time.Now().Format("01-02 15:04")
	}
	return domain.PasskeyCredential{
		ID:           credID,
		Name:         strings.TrimSpace(name),
		PublicKeyB64: base64.RawURLEncoding.EncodeToString(spkiBytes),
		SignCount:    binary.BigEndian.Uint32(authData[33:37]),
		CreatedAt:    time.Now().Format("2006-01-02 15:04:05"),
	}, nil
}

// VerifyPasskeyAssertion verifies a WebAuthn login assertion against stored ECDSA P-256 public keys.
func (m *Manager) VerifyPasskeyAssertion(creds []domain.PasskeyCredential, credID, clientDataB64, authDataB64, sigB64 string) (string, uint32, error) {
	var matched *domain.PasskeyCredential
	for i := range creds {
		if creds[i].ID == credID {
			c := creds[i]
			matched = &c
			break
		}
	}
	if matched == nil {
		return "", 0, fmt.Errorf("未找到匹配的 Passkey 凭据")
	}

	cdBytes, err := decodeB64URL(clientDataB64)
	if err != nil {
		return "", 0, fmt.Errorf("无效的 clientDataJSON")
	}
	var cd clientData
	if err := json.Unmarshal(cdBytes, &cd); err != nil {
		return "", 0, fmt.Errorf("解析 clientDataJSON 失败")
	}
	if cd.Type != "webauthn.get" {
		return "", 0, fmt.Errorf("无效的 WebAuthn 登录类型")
	}
	ent, ok := m.consumeChallenge(cd.Challenge)
	if !ok {
		return "", 0, fmt.Errorf("登录 Challenge 已过期，请重新点击 Passkey 登录")
	}

	authData, err := decodeB64URL(authDataB64)
	if err != nil || len(authData) < 37 {
		return "", 0, fmt.Errorf("无效的 authenticatorData")
	}
	expectedRP := sha256.Sum256([]byte(ent.RPID))
	if subtle.ConstantTimeCompare(authData[:32], expectedRP[:]) != 1 {
		return "", 0, fmt.Errorf("域名 RP ID 不匹配")
	}
	if authData[32]&0x01 == 0 {
		return "", 0, fmt.Errorf("未检测到用户验证")
	}

	spkiBytes, err := decodeB64URL(matched.PublicKeyB64)
	if err != nil {
		return "", 0, fmt.Errorf("已保存的公钥损坏")
	}
	pubAny, err := x509.ParsePKIXPublicKey(spkiBytes)
	if err != nil {
		return "", 0, fmt.Errorf("解析公钥失败")
	}
	pubKey, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return "", 0, fmt.Errorf("不支持的公钥类型")
	}

	sigBytes, err := decodeB64URL(sigB64)
	if err != nil {
		return "", 0, fmt.Errorf("无效的签名数据")
	}
	cdHash := sha256.Sum256(cdBytes)
	signedPayload := append(append([]byte(nil), authData...), cdHash[:]...)
	digest := sha256.Sum256(signedPayload)

	if !ecdsa.VerifyASN1(pubKey, digest[:], sigBytes) {
		return "", 0, fmt.Errorf("Passkey 签名校验失败")
	}

	newCount := binary.BigEndian.Uint32(authData[33:37])
	if matched.SignCount > 0 && newCount > 0 && newCount <= matched.SignCount {
		return "", 0, fmt.Errorf("检测到异常签名计数（疑似克隆密钥）")
	}
	return matched.Name, newCount, nil
}

func RequestRPID(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if strings.Contains(host, ",") {
		host = strings.TrimSpace(strings.Split(host, ",")[0])
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func IsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func decodeB64URL(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	return base64.RawURLEncoding.DecodeString(s)
}
