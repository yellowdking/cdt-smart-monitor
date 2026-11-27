package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pbkdf2"
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
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"cdt-smart-monitor/internal/domain"
)

const (
	SessionCookieName   = "cdt_smart_session"
	sessionTTL          = 7 * 24 * time.Hour
	challengeTTL        = 5 * time.Minute
	maxLoginFailures    = 5
	rateLimitWindow     = 15 * time.Minute
	pbkdf2Iterations    = 100000
	minPBKDF2Iter       = 10000
	maxPBKDF2Iter       = 2000000
	maxPasswordBytes    = 256
	maxRateLimitEntries = 2048
	maxChallengeEntries = 256
	maxSessionEntries   = 256
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

// --- Password Hashing (PBKDF2-HMAC-SHA256, Go 1.24 stdlib crypto/pbkdf2) ---

func HashPassword(password string) (string, error) {
	if len(password) < 6 {
		return "", fmt.Errorf("密码长度至少需要 6 位")
	}
	if len(password) > maxPasswordBytes {
		return "", fmt.Errorf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s",
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	), nil
}

func VerifyPassword(password, encoded string) bool {
	if len(password) == 0 || len(password) > maxPasswordBytes {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < minPBKDF2Iter || iter > maxPBKDF2Iter {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	expected, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(salt) == 0 || len(expected) == 0 || len(expected) > 64 {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, iter, len(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(dk, expected) == 1
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
	now := time.Now()
	if ent, ok := m.attempts[ip]; ok {
		if now.Sub(ent.FirstFail) > rateLimitWindow {
			m.attempts[ip] = rateLimitEntry{Failures: 1, FirstFail: now}
			return
		}
		ent.Failures++
		m.attempts[ip] = ent
		return
	}

	if len(m.attempts) >= maxRateLimitEntries || len(m.attempts) > 128 {
		for k, v := range m.attempts {
			if now.Sub(v.FirstFail) > rateLimitWindow {
				delete(m.attempts, k)
			}
		}
	}
	for len(m.attempts) >= maxRateLimitEntries {
		var evictKey string
		var evictTime time.Time
		// Prefer evicting the oldest non-locked entry so active lockouts remain enforced.
		for k, v := range m.attempts {
			if v.Failures < maxLoginFailures && (evictKey == "" || v.FirstFail.Before(evictTime)) {
				evictKey = k
				evictTime = v.FirstFail
			}
		}
		if evictKey == "" {
			for k, v := range m.attempts {
				if evictKey == "" || v.FirstFail.Before(evictTime) {
					evictKey = k
					evictTime = v.FirstFail
				}
			}
		}
		if evictKey == "" {
			break
		}
		delete(m.attempts, evictKey)
	}
	m.attempts[ip] = rateLimitEntry{Failures: 1, FirstFail: now}
}

func (m *Manager) ClearFailures(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.attempts, ip)
}

func (m *Manager) CreateSession(w http.ResponseWriter, r *http.Request) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)

	now := time.Now()
	m.mu.Lock()
	if len(m.sessions) > 64 {
		for k, v := range m.sessions {
			if now.After(v.ExpiresAt) {
				delete(m.sessions, k)
			}
		}
	}
	for len(m.sessions) >= maxSessionEntries {
		var oldestKey string
		var oldestExp time.Time
		for k, v := range m.sessions {
			if oldestKey == "" || v.ExpiresAt.Before(oldestExp) {
				oldestKey = k
				oldestExp = v.ExpiresAt
			}
		}
		if oldestKey == "" {
			break
		}
		delete(m.sessions, oldestKey)
	}
	m.sessions[token] = sessionEntry{ExpiresAt: now.Add(sessionTTL)}
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
	return token
}

func (m *Manager) InvalidateAllSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions = make(map[string]sessionEntry)
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
		SameSite: http.SameSiteLaxMode,
		Secure:   IsHTTPS(r),
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
	for len(m.challenges) >= maxChallengeEntries {
		var oldestKey string
		var oldestExp time.Time
		for k, v := range m.challenges {
			if oldestKey == "" || v.ExpiresAt.Before(oldestExp) {
				oldestKey = k
				oldestExp = v.ExpiresAt
			}
		}
		if oldestKey == "" {
			break
		}
		delete(m.challenges, oldestKey)
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

func VerifyOrigin(origin, rpID string) error {
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("无效的 WebAuthn Origin")
	}
	host := strings.ToLower(u.Hostname())
	rp := strings.ToLower(strings.TrimSpace(rpID))
	isLocal := host == "localhost" || host == "127.0.0.1"
	if u.Scheme != "https" && !(u.Scheme == "http" && isLocal) {
		return fmt.Errorf("WebAuthn Origin 必须使用 HTTPS")
	}
	if host != rp {
		return fmt.Errorf("WebAuthn Origin 域名与 RP ID 不匹配")
	}
	return nil
}

// VerifyPasskeyRegistration verifies clientDataJSON, origin, rpIdHash, AT flag, and parses SPKI ECDSA P-256 public key.
func (m *Manager) VerifyPasskeyRegistration(credID, name, clientDataB64, authDataB64, pubKeySPKIB64 string) (domain.PasskeyCredential, error) {
	if strings.TrimSpace(credID) == "" {
		return domain.PasskeyCredential{}, fmt.Errorf("缺少 Passkey 凭据 ID")
	}
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
	if err := VerifyOrigin(cd.Origin, ent.RPID); err != nil {
		return domain.PasskeyCredential{}, err
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
	if authData[32]&0x40 == 0 {
		return domain.PasskeyCredential{}, fmt.Errorf("注册数据缺少有效凭据标志（AT flag）")
	}
	if len(authData) < 55 {
		return domain.PasskeyCredential{}, fmt.Errorf("authenticatorData 缺少 attestedCredentialData")
	}
	idLen := int(binary.BigEndian.Uint16(authData[53:55]))
	if idLen == 0 || 55+idLen > len(authData) {
		return domain.PasskeyCredential{}, fmt.Errorf("authenticatorData 凭据 ID 长度无效")
	}
	embeddedCredID := base64.RawURLEncoding.EncodeToString(authData[55 : 55+idLen])
	normalizedCredID := strings.TrimRight(strings.TrimSpace(credID), "=")
	if subtle.ConstantTimeCompare([]byte(normalizedCredID), []byte(embeddedCredID)) != 1 {
		return domain.PasskeyCredential{}, fmt.Errorf("Passkey 凭据 ID 与 authenticatorData 不一致")
	}

	spkiBytes, err := decodeB64URL(pubKeySPKIB64)
	if err != nil {
		return domain.PasskeyCredential{}, fmt.Errorf("无效的公钥数据")
	}
	pub, err := x509.ParsePKIXPublicKey(spkiBytes)
	if err != nil {
		return domain.PasskeyCredential{}, fmt.Errorf("解析 Passkey 公钥失败: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || ecPub.Curve != elliptic.P256() {
		return domain.PasskeyCredential{}, fmt.Errorf("仅支持 ES256 (ECDSA P-256) Passkey 算法")
	}

	if strings.TrimSpace(name) == "" {
		name = "Passkey " + time.Now().Format("01-02 15:04")
	}
	return domain.PasskeyCredential{
		ID:           normalizedCredID,
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
	if err := VerifyOrigin(cd.Origin, ent.RPID); err != nil {
		return "", 0, err
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
	if !ok || pubKey.Curve != elliptic.P256() {
		return "", 0, fmt.Errorf("不支持的公钥类型（仅支持 ES256 / P-256）")
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
	if (matched.SignCount > 0 || newCount > 0) && newCount <= matched.SignCount {
		return "", 0, fmt.Errorf("检测到异常签名计数（疑似克隆密钥）")
	}
	return matched.Name, newCount, nil
}

func remotePeerIP(remoteAddr string) string {
	addr := strings.TrimSpace(remoteAddr)
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return strings.Trim(addr, "[]")
}

func isPrivateOrLoopback(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate()
}

func trustsForwardedHeaders(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CDT_TRUST_PROXY"))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	addr, err := netip.ParseAddr(remotePeerIP(r.RemoteAddr))
	if err != nil {
		return false
	}
	return isPrivateOrLoopback(addr)
}

func parseForwardedAddr(raw string) (netip.Addr, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Addr{}, false
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(s, "[]")
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func RequestRPID(r *http.Request) string {
	host := r.Host
	if trustsForwardedHeaders(r) {
		if xfh := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); xfh != "" {
			host = xfh
		}
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
	if !trustsForwardedHeaders(r) {
		return false
	}
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if strings.Contains(proto, ",") {
		proto = strings.TrimSpace(strings.Split(proto, ",")[0])
	}
	return strings.EqualFold(proto, "https")
}

func ClientIP(r *http.Request) string {
	peer := remotePeerIP(r.RemoteAddr)
	if !trustsForwardedHeaders(r) {
		return peer
	}
	xffHeaders := r.Header.Values("X-Forwarded-For")
	if len(xffHeaders) == 0 {
		return peer
	}
	parts := strings.Split(strings.Join(xffHeaders, ","), ",")
	var rightmostValid string
	for i := len(parts) - 1; i >= 0; i-- {
		addr, ok := parseForwardedAddr(parts[i])
		if !ok {
			continue
		}
		if rightmostValid == "" {
			rightmostValid = addr.String()
		}
		if !isPrivateOrLoopback(addr) {
			return addr.String()
		}
	}
	if rightmostValid != "" {
		return rightmostValid
	}
	return peer
}

func decodeB64URL(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	return base64.RawURLEncoding.DecodeString(s)
}
