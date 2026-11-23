package domain

import "time"

// Built-in internal safety margins & refresh-delta circuit breakers.
const (
	// InternalTrafficBufferGB reserves 30GB internally to absorb Aliyun CDT API delay.
	InternalTrafficBufferGB = 30.0
	// InternalCostBufferUSD reserves $0.05 internally to absorb Aliyun BSS billing delay.
	InternalCostBufferUSD = 0.05
	// GlobalRefreshTrafficDeltaGB triggers immediate stop+switch when traffic jumps >30GB between two refreshes
	// (overridden during peak hours when PeakMaxSliceGB > 0).
	GlobalRefreshTrafficDeltaGB = 30.0
	// GlobalRefreshCostDeltaUSD triggers immediate stop+switch when cost jumps >$0.05 between two refreshes.
	GlobalRefreshCostDeltaUSD = 0.05
	// MinSmartRotationInstances is the minimum healthy machine count for multi-machine rotation.
	MinSmartRotationInstances = 2
	// MaxKeepAliveFailures before a preempted duty instance triggers pool failover.
	MaxKeepAliveFailures = 3
)

type RotationStrategy string

const (
	StrategySmartHybrid          RotationStrategy = "smart_hybrid"
	StrategyExhaustSequential    RotationStrategy = "exhaust_sequential"
	StrategyContinuousRoundRobin RotationStrategy = "continuous_round_robin"
)

const (
	StatusRunning  = "Running"
	StatusStarting = "Starting"
	StatusStopping = "Stopping"
	StatusStopped  = "Stopped"
	StatusUnknown  = "Unknown"
)

const (
	StopModeStopCharging = "StopCharging"
	StopModeKeepCharging = "KeepCharging"
)

const (
	SiteIntl  = "intl"
	SiteChina = "china"
)

// Server represents one Aliyun ECS instance managed in the smart rotation pool.
type Server struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Site            string    `json:"site"` // "intl" | "china"
	Region          string    `json:"region"`
	InstanceID      string    `json:"instance_id"`
	AccessKeyID     string    `json:"access_key_id"`
	AccessKeySecret string    `json:"access_key_secret,omitempty"`
	InPool          bool      `json:"in_pool"`
	KeepAlive       bool      `json:"keep_alive"`       // 抢占式实例保活开关（阈值熔断与闲时关机优先于保活）
	KeepAliveFails  int       `json:"keep_alive_fails"` // 连续抢占拉起失败次数，满 3 次自动故障转移
	Priority        int       `json:"priority"`
	MaxTrafficGB    float64   `json:"max_traffic_gb"` // Default 200
	MaxCostUSD      float64   `json:"max_cost_usd"`   // Default 0.50
	Status          string    `json:"status"`
	PublicIP        string    `json:"public_ip"`
	UsedTrafficGB   float64   `json:"used_traffic_gb"`
	PrevTrafficGB   float64   `json:"prev_traffic_gb"`
	BilledCostUSD   float64   `json:"billed_cost_usd"`
	PrevCostUSD     float64   `json:"prev_cost_usd"`
	LockedUntil     string    `json:"locked_until,omitempty"`
	LockReason      string    `json:"lock_reason,omitempty"`
	LastSyncAt      string    `json:"last_sync_at,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	LastActiveAt    time.Time `json:"last_active_at"`
}

// PoolConfig stores the streamlined 4-part smart rotation configuration.
type PoolConfig struct {
	Enabled             bool             `json:"enabled"`
	Timezone            string           `json:"timezone"`
	ActiveStartHour     int              `json:"active_start_hour"`
	ActiveEndHour       int              `json:"active_end_hour"`
	PeakStartHour       int              `json:"peak_start_hour"`
	PeakEndHour         int              `json:"peak_end_hour"`
	PeakMaxSliceGB      float64          `json:"peak_max_slice_gb"`
	Strategy            RotationStrategy `json:"strategy"`
	DefaultMaxTrafficGB float64          `json:"default_max_traffic_gb"`
	DefaultMaxCostUSD   float64          `json:"default_max_cost_usd"`
	StopMode            string           `json:"stop_mode"`
	MakeBeforeBreak     bool             `json:"make_before_break"`
	PollIntervalMinutes int              `json:"poll_interval_minutes"`
	// Active duty tracking
	CurrentServerID            int64     `json:"current_server_id"`
	CurrentSliceStartedAt      time.Time `json:"current_slice_started_at"`
	CurrentSliceStartTrafficGB float64   `json:"current_slice_start_traffic_gb"`
	// PeakOverrideUntil suppresses clock-aligned bounce-back after a burst-cap/delta handoff within the current slot.
	PeakOverrideUntil time.Time `json:"peak_override_until,omitempty"`
	// LastAllExhaustedAlertAt throttles repeated all-exhausted notifications.
	LastAllExhaustedAlertAt time.Time `json:"last_all_exhausted_alert_at,omitempty"`
}

// NotifyConfig stores optional Telegram / Webhook notification settings.
type NotifyConfig struct {
	ProxyURL             string `json:"proxy_url"`         // 可选：http://、https://、socks5:// 代理地址
	TelegramEnabled      bool   `json:"telegram_enabled"`
	TelegramAPIBase      string `json:"telegram_api_base"` // 可选：自定义 Telegram 反代地址，留空默认 https://api.telegram.org
	TelegramBotToken     string `json:"telegram_bot_token,omitempty"`
	TelegramChatID       string `json:"telegram_chat_id"`
	WebhookEnabled       bool   `json:"webhook_enabled"`
	WebhookURL           string `json:"webhook_url"`
	WeeklyReportEnabled  bool   `json:"weekly_report_enabled"`   // 每周一 08:00 定时发送流量与费用周报
	LastWeeklyReportDate string `json:"last_weekly_report_date"` // YYYY-MM-DD 防止同一天重复推送
}

// EventLog records every automated or manual action.
type EventLog struct {
	ID      int64  `json:"id"`
	Time    string `json:"time"`
	Level   string `json:"level"`
	Server  string `json:"server"`
	Action  string `json:"action"`
	Message string `json:"message"`
}

// PasskeyCredential stores a registered WebAuthn ES256 Passkey for HTTPS passwordless login.
type PasskeyCredential struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	PublicKeyB64 string `json:"public_key_b64,omitempty"`
	SignCount    uint32 `json:"sign_count"`
	CreatedAt    string `json:"created_at"`
}

// AuthConfig stores the admin password hash and registered Passkeys.
type AuthConfig struct {
	PasswordHash string              `json:"password_hash,omitempty"`
	Passkeys     []PasskeyCredential `json:"passkeys"`
}

// AppState is the persisted root state saved atomically to /data/state.json.
type AppState struct {
	NextServerID int64        `json:"next_server_id"`
	NextEventID  int64        `json:"next_event_id"`
	Auth         AuthConfig   `json:"auth"`
	Pool         PoolConfig   `json:"pool"`
	Notify       NotifyConfig `json:"notify"`
	Servers      []Server     `json:"servers"`
	Events       []EventLog   `json:"events"`
}

func DefaultState() AppState {
	return AppState{
		NextServerID: 1,
		NextEventID:  1,
		Auth: AuthConfig{
			Passkeys: []PasskeyCredential{},
		},
		Pool: PoolConfig{
			Enabled:             true,
			Timezone:            "Asia/Shanghai",
			ActiveStartHour:     8,
			ActiveEndHour:       24,
			PeakStartHour:       18,
			PeakEndHour:         24,
			PeakMaxSliceGB:      35,
			Strategy:            StrategySmartHybrid,
			DefaultMaxTrafficGB: 200,
			DefaultMaxCostUSD:   0.50,
			StopMode:            StopModeStopCharging,
			MakeBeforeBreak:     true,
			PollIntervalMinutes: 5,
		},
		Notify: NotifyConfig{
			WeeklyReportEnabled: true,
		},
		Servers: []Server{},
		Events:  []EventLog{},
	}
}
