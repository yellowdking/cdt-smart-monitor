package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"cdt-smart-monitor/internal/domain"
)

func allowLoopbackInTest(t *testing.T) {
	t.Helper()
	allowLoopbackForTest.Store(true)
	t.Cleanup(func() {
		allowLoopbackForTest.Store(false)
	})
}

func TestTelegramHTMLFormattingEscapesSpecialChars(t *testing.T) {
	allowLoopbackInTest(t)

	var received map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	n := New()
	cfg := domain.NotifyConfig{
		TelegramEnabled:  true,
		TelegramAPIBase:  srv.URL,
		TelegramBotToken: "123:abc",
		TelegramChatID:   "999",
	}
	sent, err := n.SendSync(context.Background(), cfg, "Alert <hk_01>", "reason: traffic_cutoff & >30GB")
	if err != nil {
		t.Fatalf("SendSync failed: %v", err)
	}
	if len(sent) != 1 || sent[0] != "Telegram" {
		t.Fatalf("expected Telegram sent, got %v", sent)
	}
	if received["parse_mode"] != "HTML" {
		t.Fatalf("expected HTML parse_mode, got %q", received["parse_mode"])
	}
	if !strings.Contains(received["text"], "<b>Alert &lt;hk_01&gt;</b>") || !strings.Contains(received["text"], "traffic_cutoff &amp; &gt;30GB") {
		t.Fatalf("unexpected escaped HTML text: %q", received["text"])
	}
}

func TestWebhookAndValidation(t *testing.T) {
	allowLoopbackInTest(t)

	var gotTitle, gotMsg string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotTitle = body["title"]
		gotMsg = body["message"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New()
	cfg := domain.NotifyConfig{
		WebhookEnabled: true,
		WebhookURL:     srv.URL,
	}
	sent, err := n.SendSync(context.Background(), cfg, "Test", "Hello")
	if err != nil || len(sent) != 1 || sent[0] != "Webhook" {
		t.Fatalf("expected Webhook sent, got sent=%v err=%v", sent, err)
	}
	if gotTitle != "Test" || gotMsg != "Hello" {
		t.Fatalf("unexpected webhook body: title=%q msg=%q", gotTitle, gotMsg)
	}

	// Invalid proxy scheme rejected
	cfg.ProxyURL = "ftp://127.0.0.1:21"
	if _, err := n.SendSync(context.Background(), cfg, "Test", "Hello"); err == nil {
		t.Fatal("expected unsupported proxy scheme to fail")
	}
}

func TestTelegramTokenAndProxyCredentialsRedactedOnNetworkError(t *testing.T) {
	allowLoopbackInTest(t)

	// Start and immediately close a test server to trigger a deterministic network error.
	closedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := closedSrv.URL
	closedSrv.Close()

	const secretToken = "987654321:SUPER_SECRET_TG_TOKEN_XYZ"
	const proxyPass = "UltraSecretProxyPass99"

	n := New()
	cfg := domain.NotifyConfig{
		TelegramEnabled:  true,
		TelegramAPIBase:  closedURL,
		TelegramBotToken: secretToken,
		TelegramChatID:   "999",
	}
	_, err := n.SendSync(context.Background(), cfg, "Alert", "Body")
	if err == nil {
		t.Fatal("expected network error against closed server")
	}
	if strings.Contains(err.Error(), secretToken) || strings.Contains(err.Error(), "SUPER_SECRET_TG_TOKEN_XYZ") {
		t.Fatalf("telegram bot token leaked in network error: %q", err.Error())
	}

	// Proxy credentials must never leak on proxy failure or invalid proxy URL.
	cfgProxy := domain.NotifyConfig{
		ProxyURL:         "http://alice:" + proxyPass + "@" + strings.TrimPrefix(closedURL, "http://"),
		TelegramEnabled:  true,
		TelegramAPIBase:  "https://api.telegram.org",
		TelegramBotToken: secretToken,
		TelegramChatID:   "999",
	}
	_, err = n.SendSync(context.Background(), cfgProxy, "Alert", "Body")
	if err == nil {
		t.Fatal("expected error against closed proxy")
	}
	if strings.Contains(err.Error(), proxyPass) || strings.Contains(err.Error(), secretToken) {
		t.Fatalf("proxy password or bot token leaked in error: %q", err.Error())
	}

	// Webhook query token must not leak on network error.
	const webhookSecret = "ding_secret_token_999"
	cfgWebhook := domain.NotifyConfig{
		WebhookEnabled: true,
		WebhookURL:     closedURL + "/hook?access_token=" + webhookSecret,
	}
	_, err = n.SendSync(context.Background(), cfgWebhook, "Alert", "Body")
	if err == nil {
		t.Fatal("expected error against closed webhook")
	}
	if strings.Contains(err.Error(), webhookSecret) {
		t.Fatalf("webhook access_token leaked in error: %q", err.Error())
	}
}

func TestRedirectsAreRefusedAndNeverLeakToken(t *testing.T) {
	allowLoopbackInTest(t)

	var targetHits atomic.Int32
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetSrv.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirectSrv.Close()

	const secretToken = "111222333:REDIRECT_SECRET_TOKEN"
	n := New()
	_, err := n.SendSync(context.Background(), domain.NotifyConfig{
		TelegramEnabled:  true,
		TelegramAPIBase:  redirectSrv.URL,
		TelegramBotToken: secretToken,
		TelegramChatID:   "999",
	}, "Alert", "Body")
	if err == nil {
		t.Fatal("expected 307 redirect to be refused")
	}
	if targetHits.Load() != 0 {
		t.Fatalf("redirect target must never be contacted, got %d hits", targetHits.Load())
	}
	if strings.Contains(err.Error(), secretToken) {
		t.Fatalf("bot token leaked in redirect error: %q", err.Error())
	}
}

func TestSSRFGuardBlocksMetadataAndLoopback(t *testing.T) {
	allowLoopbackForTest.Store(false)
	n := New()

	blockedURLs := []string{
		"http://100.100.100.200/latest/meta-data/",
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.12.34/hook",
		"http://127.0.0.1:8080/hook",
		"http://localhost:8080/hook",
		"http://[::1]:8080/hook",
		"http://[::ffff:169.254.169.254]/latest/meta-data/",
		"http://[::ffff:100.100.100.200]/latest/meta-data/",
		"http://0.0.0.0:8080/hook",
		"http://metadata.google.internal/computeMetadata/v1/",
	}

	for _, target := range blockedURLs {
		if _, err := n.SendSync(context.Background(), domain.NotifyConfig{
			WebhookEnabled: true,
			WebhookURL:     target,
		}, "Test", "Body"); err == nil {
			t.Errorf("expected SSRF guard to block webhook target %q", target)
		}
		if _, err := n.SendSync(context.Background(), domain.NotifyConfig{
			TelegramEnabled:  true,
			TelegramAPIBase:  target,
			TelegramBotToken: "123:abc",
			TelegramChatID:   "999",
		}, "Test", "Body"); err == nil {
			t.Errorf("expected SSRF guard to block telegram api base %q", target)
		}
	}
}
