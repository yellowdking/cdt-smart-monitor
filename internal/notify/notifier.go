package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cdt-smart-monitor/internal/domain"
)

type Notifier struct{}

func New() *Notifier {
	return &Notifier{}
}

func (n *Notifier) buildClient(proxyURL string) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("代理地址格式错误: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h" {
			return nil, fmt.Errorf("不支持的代理协议 %q（仅支持 http / https / socks5）", u.Scheme)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	return &http.Client{
		Transport: tr,
		Timeout:   12 * time.Second,
	}, nil
}

// Send dispatches notifications asynchronously during background scheduling.
func (n *Notifier) Send(ctx context.Context, cfg domain.NotifyConfig, title, message string) {
	client, err := n.buildClient(cfg.ProxyURL)
	if err != nil {
		return
	}
	if cfg.TelegramEnabled && cfg.TelegramBotToken != "" && cfg.TelegramChatID != "" {
		go func() {
			_ = n.sendTelegram(context.Background(), client, cfg.TelegramAPIBase, cfg.TelegramBotToken, cfg.TelegramChatID, fmt.Sprintf("*%s*\n%s", title, message))
		}()
	}
	if cfg.WebhookEnabled && cfg.WebhookURL != "" {
		go func() {
			_ = n.sendWebhook(context.Background(), client, cfg.WebhookURL, title, message)
		}()
	}
}

// SendSync sends a test notification synchronously and reports exact channel results/errors.
func (n *Notifier) SendSync(ctx context.Context, cfg domain.NotifyConfig, title, message string) ([]string, error) {
	client, err := n.buildClient(cfg.ProxyURL)
	if err != nil {
		return nil, err
	}

	var sent []string
	var errs []string

	if cfg.TelegramEnabled {
		if cfg.TelegramBotToken == "" || cfg.TelegramChatID == "" {
			errs = append(errs, "Telegram: 缺少 Bot Token 或 Chat ID")
		} else if err := n.sendTelegram(ctx, client, cfg.TelegramAPIBase, cfg.TelegramBotToken, cfg.TelegramChatID, fmt.Sprintf("*%s*\n%s", title, message)); err != nil {
			errs = append(errs, "Telegram: "+err.Error())
		} else {
			sent = append(sent, "Telegram")
		}
	}

	if cfg.WebhookEnabled {
		if cfg.WebhookURL == "" {
			errs = append(errs, "Webhook: 缺少 Webhook URL")
		} else if err := n.sendWebhook(ctx, client, cfg.WebhookURL, title, message); err != nil {
			errs = append(errs, "Webhook: "+err.Error())
		} else {
			sent = append(sent, "Webhook")
		}
	}

	if !cfg.TelegramEnabled && !cfg.WebhookEnabled {
		return nil, fmt.Errorf("请先勾选启用 Telegram 或 Webhook 至少一个通知渠道")
	}
	if len(errs) > 0 {
		return sent, fmt.Errorf("%s", strings.Join(errs, " ; "))
	}
	return sent, nil
}

func (n *Notifier) sendTelegram(ctx context.Context, client *http.Client, apiBase, token, chatID, text string) error {
	base := strings.TrimRight(strings.TrimSpace(apiBase), "/")
	if base == "" {
		base = "https://api.telegram.org"
	}
	payload, _ := json.Marshal(map[string]string{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	})
	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", base, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

func (n *Notifier) sendWebhook(ctx context.Context, client *http.Client, targetURL, title, message string) error {
	payload, _ := json.Marshal(map[string]string{
		"title":   title,
		"message": message,
		"time":    time.Now().Format(time.RFC3339),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}
