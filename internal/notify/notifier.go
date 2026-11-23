package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cdt-smart-monitor/internal/domain"
)

type Notifier struct {
	logger *slog.Logger
}

func New() *Notifier {
	return &Notifier{logger: slog.Default()}
}

func NewWithLogger(logger *slog.Logger) *Notifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &Notifier{logger: logger}
}

func (n *Notifier) buildClient(proxyURL string) (*http.Client, func(), error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, nil, fmt.Errorf("代理地址格式错误: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h" {
			return nil, nil, fmt.Errorf("不支持的代理协议 %q（仅支持 http / https / socks5）", u.Scheme)
		}
		if u.Host == "" {
			return nil, nil, fmt.Errorf("代理地址缺少主机名")
		}
		tr.Proxy = http.ProxyURL(u)
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   12 * time.Second,
	}
	return client, tr.CloseIdleConnections, nil
}

func validateHTTPURL(raw, field string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%s 必须是有效的 http:// 或 https:// 地址", field)
	}
	return nil
}

func formatTelegramHTML(title, message string) string {
	return fmt.Sprintf("<b>%s</b>\n%s", html.EscapeString(title), html.EscapeString(message))
}

// Send dispatches notifications asynchronously during background scheduling.
func (n *Notifier) Send(ctx context.Context, cfg domain.NotifyConfig, title, message string) {
	_ = ctx
	if cfg.TelegramEnabled && cfg.TelegramBotToken != "" && cfg.TelegramChatID != "" {
		go func() {
			client, cleanup, err := n.buildClient(cfg.ProxyURL)
			if err != nil {
				n.logger.Warn("notify telegram client error", "err", err)
				return
			}
			defer cleanup()
			reqCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := n.sendTelegram(reqCtx, client, cfg.TelegramAPIBase, cfg.TelegramBotToken, cfg.TelegramChatID, formatTelegramHTML(title, message)); err != nil {
				n.logger.Warn("notify telegram failed", "title", title, "err", err)
			}
		}()
	}
	if cfg.WebhookEnabled && cfg.WebhookURL != "" {
		go func() {
			client, cleanup, err := n.buildClient(cfg.ProxyURL)
			if err != nil {
				n.logger.Warn("notify webhook client error", "err", err)
				return
			}
			defer cleanup()
			reqCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := n.sendWebhook(reqCtx, client, cfg.WebhookURL, title, message); err != nil {
				n.logger.Warn("notify webhook failed", "title", title, "err", err)
			}
		}()
	}
}

// SendSync sends a test notification synchronously and reports exact channel results/errors.
func (n *Notifier) SendSync(ctx context.Context, cfg domain.NotifyConfig, title, message string) ([]string, error) {
	client, cleanup, err := n.buildClient(cfg.ProxyURL)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var sent []string
	var errs []string

	if cfg.TelegramEnabled {
		if cfg.TelegramBotToken == "" || cfg.TelegramChatID == "" {
			errs = append(errs, "Telegram: 缺少 Bot Token 或 Chat ID")
		} else if err := n.sendTelegram(ctx, client, cfg.TelegramAPIBase, cfg.TelegramBotToken, cfg.TelegramChatID, formatTelegramHTML(title, message)); err != nil {
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

func (n *Notifier) sendTelegram(ctx context.Context, client *http.Client, apiBase, token, chatID, htmlText string) error {
	base := strings.TrimRight(strings.TrimSpace(apiBase), "/")
	if base == "" {
		base = "https://api.telegram.org"
	} else if err := validateHTTPURL(base, "Telegram API 反代地址"); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"chat_id":    chatID,
		"text":       htmlText,
		"parse_mode": "HTML",
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
	if err := validateHTTPURL(targetURL, "Webhook URL"); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"title":   title,
		"message": message,
		"time":    time.Now().Format(time.RFC3339),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(targetURL), bytes.NewReader(payload))
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
