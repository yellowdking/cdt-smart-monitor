package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cdt-smart-monitor/internal/domain"
)

func TestTelegramHTMLFormattingEscapesSpecialChars(t *testing.T) {
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
