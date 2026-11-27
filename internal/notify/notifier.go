package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"cdt-smart-monitor/internal/domain"
)

var (
	// allowLoopbackForTest permits loopback targets exclusively in package unit tests (httptest.NewServer).
	allowLoopbackForTest atomic.Bool

	aliyunMetadataIP = netip.MustParseAddr("100.100.100.200")
	awsIMDSv6IP      = netip.MustParseAddr("fd00:ec2::254")

	tgBotTokenRe  = regexp.MustCompile(`/bot[^\s/"'<>]+`)
	urlUserInfoRe = regexp.MustCompile(`(https?|socks5h?)://[^/\s@"']+?:[^/\s@"']*@`)
	querySecretRe = regexp.MustCompile(`(?i)([?&](?:access_token|token|secret|key|apikey|api_key|webhook_key)=)[^&\s"'<>]+`)
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

func isBlockedSSRFAddr(addr netip.Addr, allowLoopback bool) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return true
	}
	if addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return true
	}
	if addr == aliyunMetadataIP || addr == awsIMDSv6IP {
		return true
	}
	if addr.IsLoopback() && !allowLoopback {
		return true
	}
	return false
}

func checkSSRFHost(host string, allowLoopback bool) error {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return fmt.Errorf("缺少主机名")
	}
	if h == "metadata.google.internal" || h == "metadata.goog" || h == "metadata" {
		return fmt.Errorf("禁止访问云元数据地址")
	}
	if !allowLoopback && (h == "localhost" || strings.HasSuffix(h, ".localhost")) {
		return fmt.Errorf("禁止访问本机回环地址")
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		if isBlockedSSRFAddr(addr, allowLoopback) {
			return fmt.Errorf("禁止访问云元数据、链路本地或回环地址")
		}
	}
	return nil
}

func unwrapURLError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		inner := unwrapURLError(ue.Err)
		if ue.Op != "" {
			return fmt.Sprintf("%s 失败: %s", ue.Op, inner)
		}
		return inner
	}
	return err.Error()
}

func sanitizeMessage(msg string, secrets ...string) string {
	out := msg
	for _, s := range secrets {
		if s == "" {
			continue
		}
		out = strings.ReplaceAll(out, s, "[REDACTED]")
		if esc := url.PathEscape(s); esc != "" && esc != s {
			out = strings.ReplaceAll(out, esc, "[REDACTED]")
		}
		if qesc := url.QueryEscape(s); qesc != "" && qesc != s {
			out = strings.ReplaceAll(out, qesc, "[REDACTED]")
		}
	}
	out = tgBotTokenRe.ReplaceAllString(out, "/bot[REDACTED]")
	out = urlUserInfoRe.ReplaceAllString(out, "${1}://[REDACTED]@")
	out = querySecretRe.ReplaceAllString(out, "${1}[REDACTED]")
	return out
}

func sanitizeError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", sanitizeMessage(unwrapURLError(err), secrets...))
}

func (n *Notifier) buildClient(proxyURL string) (*http.Client, func(), []string, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	var proxySecrets []string
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("代理地址格式错误，请检查协议与主机格式")
		}
		if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h" {
			return nil, nil, nil, fmt.Errorf("不支持的代理协议 %q（仅支持 http / https / socks5）", u.Scheme)
		}
		if u.Hostname() == "" {
			return nil, nil, nil, fmt.Errorf("代理地址缺少主机名")
		}
		// Allow local proxies (e.g. 127.0.0.1:7890) while still blocking cloud metadata / link-local hosts.
		if err := checkSSRFHost(u.Hostname(), true); err != nil {
			return nil, nil, nil, fmt.Errorf("代理地址已被安全策略拦截: %w", err)
		}
		if u.User != nil {
			if pass, ok := u.User.Password(); ok && pass != "" {
				proxySecrets = append(proxySecrets, pass)
			}
		}
		tr.Proxy = http.ProxyURL(u)
	} else {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			allowLoopback := allowLoopbackForTest.Load()
			if err := checkSSRFHost(host, allowLoopback); err != nil {
				return nil, err
			}
			if ip, err := netip.ParseAddr(host); err == nil {
				if isBlockedSSRFAddr(ip, allowLoopback) {
					return nil, fmt.Errorf("禁止访问云元数据、链路本地或回环地址")
				}
				return dialer.DialContext(ctx, network, addr)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("无法解析目标主机: %s", host)
			}
			for _, ipAddr := range ips {
				if parsed, ok := netip.AddrFromSlice(ipAddr.IP); ok && isBlockedSSRFAddr(parsed, allowLoopback) {
					return nil, fmt.Errorf("目标地址解析到受限 IP，已被安全策略拦截")
				}
			}
			var firstErr error
			for _, ipAddr := range ips {
				conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ipAddr.String(), port))
				if derr == nil {
					return conn, nil
				}
				if firstErr == nil {
					firstErr = derr
				}
			}
			return nil, firstErr
		}
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, tr.CloseIdleConnections, proxySecrets, nil
}

func validateHTTPURL(raw, field string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("%s 必须是有效的 http:// 或 https:// 地址", field)
	}
	if err := checkSSRFHost(u.Hostname(), allowLoopbackForTest.Load()); err != nil {
		return nil, fmt.Errorf("%s 已被安全策略拦截: %w", field, err)
	}
	return u, nil
}

func formatTelegramHTML(title, message string) string {
	return fmt.Sprintf("<b>%s</b>\n%s", html.EscapeString(title), html.EscapeString(message))
}

// Send dispatches notifications asynchronously during background scheduling.
func (n *Notifier) Send(ctx context.Context, cfg domain.NotifyConfig, title, message string) {
	_ = ctx
	if cfg.TelegramEnabled && cfg.TelegramBotToken != "" && cfg.TelegramChatID != "" {
		go func() {
			client, cleanup, proxySecrets, err := n.buildClient(cfg.ProxyURL)
			if err != nil {
				n.logger.Warn("notify telegram client error", "err", err)
				return
			}
			defer cleanup()
			reqCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := n.sendTelegram(reqCtx, client, cfg.TelegramAPIBase, cfg.TelegramBotToken, cfg.TelegramChatID, formatTelegramHTML(title, message), proxySecrets); err != nil {
				n.logger.Warn("notify telegram failed", "title", title, "err", err)
			}
		}()
	}
	if cfg.WebhookEnabled && cfg.WebhookURL != "" {
		go func() {
			client, cleanup, proxySecrets, err := n.buildClient(cfg.ProxyURL)
			if err != nil {
				n.logger.Warn("notify webhook client error", "err", err)
				return
			}
			defer cleanup()
			reqCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := n.sendWebhook(reqCtx, client, cfg.WebhookURL, title, message, proxySecrets); err != nil {
				n.logger.Warn("notify webhook failed", "title", title, "err", err)
			}
		}()
	}
}

// SendSync sends a test notification synchronously and reports exact channel results/errors.
func (n *Notifier) SendSync(ctx context.Context, cfg domain.NotifyConfig, title, message string) ([]string, error) {
	client, cleanup, proxySecrets, err := n.buildClient(cfg.ProxyURL)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var sent []string
	var errs []string

	if cfg.TelegramEnabled {
		if cfg.TelegramBotToken == "" || cfg.TelegramChatID == "" {
			errs = append(errs, "Telegram: 缺少 Bot Token 或 Chat ID")
		} else if err := n.sendTelegram(ctx, client, cfg.TelegramAPIBase, cfg.TelegramBotToken, cfg.TelegramChatID, formatTelegramHTML(title, message), proxySecrets); err != nil {
			errs = append(errs, "Telegram: "+err.Error())
		} else {
			sent = append(sent, "Telegram")
		}
	}

	if cfg.WebhookEnabled {
		if cfg.WebhookURL == "" {
			errs = append(errs, "Webhook: 缺少 Webhook URL")
		} else if err := n.sendWebhook(ctx, client, cfg.WebhookURL, title, message, proxySecrets); err != nil {
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

func (n *Notifier) sendTelegram(ctx context.Context, client *http.Client, apiBase, token, chatID, htmlText string, proxySecrets []string) error {
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, " \t\r\n/?#@\\") {
		return fmt.Errorf("Telegram Bot Token 格式无效")
	}
	base := strings.TrimRight(strings.TrimSpace(apiBase), "/")
	if base == "" {
		base = "https://api.telegram.org"
	} else if _, err := validateHTTPURL(base, "Telegram API 反代地址"); err != nil {
		return err
	}

	secrets := make([]string, 0, 1+len(proxySecrets))
	secrets = append(secrets, token)
	secrets = append(secrets, proxySecrets...)

	payload, _ := json.Marshal(map[string]string{
		"chat_id":    chatID,
		"text":       htmlText,
		"parse_mode": "HTML",
	})
	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", base, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return sanitizeError(err, secrets...)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return sanitizeError(err, secrets...)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("HTTP %d: 重定向已被安全策略拒绝", resp.StatusCode)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, sanitizeMessage(strings.TrimSpace(string(raw)), secrets...))
	}
	return nil
}

func (n *Notifier) sendWebhook(ctx context.Context, client *http.Client, targetURL, title, message string, proxySecrets []string) error {
	u, err := validateHTTPURL(targetURL, "Webhook URL")
	if err != nil {
		return err
	}
	secrets := make([]string, 0, len(proxySecrets)+2)
	secrets = append(secrets, proxySecrets...)
	if u.User != nil {
		if pass, ok := u.User.Password(); ok && pass != "" {
			secrets = append(secrets, pass)
		}
	}
	if u.RawQuery != "" {
		secrets = append(secrets, u.RawQuery)
	}

	payload, _ := json.Marshal(map[string]string{
		"title":   title,
		"message": message,
		"time":    time.Now().Format(time.RFC3339),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(targetURL), bytes.NewReader(payload))
	if err != nil {
		return sanitizeError(err, secrets...)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return sanitizeError(err, secrets...)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("HTTP %d: 重定向已被安全策略拒绝", resp.StatusCode)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, sanitizeMessage(strings.TrimSpace(string(raw)), secrets...))
	}
	return nil
}
