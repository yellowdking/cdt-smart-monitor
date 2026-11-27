package aliyun

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"cdt-smart-monitor/internal/domain"
)

var validRegionRe = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

type aliyunAPIError struct {
	Status  int
	Code    string
	Message string
	Raw     string
}

func (e *aliyunAPIError) Error() string {
	if e.Code != "" || e.Message != "" {
		return fmt.Sprintf("aliyun API HTTP %d (%s): %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("aliyun API HTTP %d: %s", e.Status, e.Raw)
}

func validateRegion(region string) error {
	if !validRegionRe.MatchString(region) {
		return fmt.Errorf("invalid aliyun region %q", region)
	}
	return nil
}

func isThrottlingCode(code string) bool {
	c := strings.TrimSpace(code)
	return c == "Throttling" ||
		c == "Throttling.User" ||
		c == "Throttling.API" ||
		strings.HasPrefix(c, "Throttling.") ||
		c == "FlowControl"
}

func isRetryableAliyunError(status int, err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if status == 0 || status == http.StatusTooManyRequests || status >= 500 {
		return true
	}
	if status == http.StatusBadRequest || status == http.StatusForbidden {
		var apiErr *aliyunAPIError
		if errors.As(err, &apiErr) && isThrottlingCode(apiErr.Code) {
			return true
		}
	}
	return false
}

type Client struct {
	httpClient     *http.Client
	ecsEndpointFn  func(region string) string
	cdtEndpoint    string
	bssIntlEndpt   string
	bssChinaEndpt  string
	maxAttempts    int
	retryBaseDelay time.Duration
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		ecsEndpointFn: func(region string) string {
			return fmt.Sprintf("https://ecs.%s.aliyuncs.com/", region)
		},
		cdtEndpoint:    "https://cdt.aliyuncs.com/",
		bssIntlEndpt:   "https://business.ap-southeast-1.aliyuncs.com/",
		bssChinaEndpt:  "https://business.aliyuncs.com/",
		maxAttempts:    3,
		retryBaseDelay: 300 * time.Millisecond,
	}
}

type InstanceSnapshot struct {
	Status   string
	PublicIP string
}

// DescribeInstance fetches ECS instance status and primary public IPv4.
func (c *Client) DescribeInstance(ctx context.Context, s domain.Server) (InstanceSnapshot, error) {
	if err := validateRegion(s.Region); err != nil {
		return InstanceSnapshot{Status: domain.StatusUnknown}, err
	}
	endpoint := c.ecsEndpointFn(s.Region)
	idsJSON, err := json.Marshal([]string{s.InstanceID})
	if err != nil {
		return InstanceSnapshot{Status: domain.StatusUnknown}, err
	}
	params := map[string]string{
		"Action":      "DescribeInstances",
		"Version":     "2014-05-26",
		"RegionId":    s.Region,
		"InstanceIds": string(idsJSON),
	}
	body, err := c.doRPC(ctx, endpoint, s.AccessKeyID, s.AccessKeySecret, params)
	if err != nil {
		return InstanceSnapshot{Status: domain.StatusUnknown}, err
	}

	var resp struct {
		Instances struct {
			Instance []struct {
				Status          string `json:"Status"`
				PublicIpAddress struct {
					IpAddress []string `json:"IpAddress"`
				} `json:"PublicIpAddress"`
				EipAddress struct {
					IpAddress string `json:"IpAddress"`
				} `json:"EipAddress"`
			} `json:"Instance"`
		} `json:"Instances"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return InstanceSnapshot{Status: domain.StatusUnknown}, err
	}
	if len(resp.Instances.Instance) == 0 {
		return InstanceSnapshot{Status: domain.StatusUnknown}, fmt.Errorf("instance %s not found in %s", s.InstanceID, s.Region)
	}
	inst := resp.Instances.Instance[0]
	ip := inst.EipAddress.IpAddress
	if ip == "" && len(inst.PublicIpAddress.IpAddress) > 0 {
		ip = inst.PublicIpAddress.IpAddress[0]
	}
	return InstanceSnapshot{Status: inst.Status, PublicIP: ip}, nil
}

func (c *Client) StartInstance(ctx context.Context, s domain.Server) error {
	if err := validateRegion(s.Region); err != nil {
		return err
	}
	endpoint := c.ecsEndpointFn(s.Region)
	params := map[string]string{
		"Action":     "StartInstance",
		"Version":    "2014-05-26",
		"RegionId":   s.Region,
		"InstanceId": s.InstanceID,
	}
	_, err := c.doRPC(ctx, endpoint, s.AccessKeyID, s.AccessKeySecret, params)
	return err
}

func (c *Client) StopInstance(ctx context.Context, s domain.Server, stopMode string) error {
	if err := validateRegion(s.Region); err != nil {
		return err
	}
	if stopMode == "" {
		stopMode = domain.StopModeStopCharging
	}
	endpoint := c.ecsEndpointFn(s.Region)
	params := map[string]string{
		"Action":      "StopInstance",
		"Version":     "2014-05-26",
		"RegionId":    s.Region,
		"InstanceId":  s.InstanceID,
		"StoppedMode": stopMode,
	}
	_, err := c.doRPC(ctx, endpoint, s.AccessKeyID, s.AccessKeySecret, params)
	return err
}

// isDomesticRegion distinguishes China Mainland CDT bucket from overseas/HK/MO/TW buckets.
func isDomesticRegion(region string) bool {
	if !strings.HasPrefix(region, "cn-") {
		return false
	}
	return region != "cn-hongkong" && region != "cn-macao" && region != "cn-taiwan"
}

// GetCDTTrafficGB queries current-month Aliyun CDT internet traffic in GB.
func (c *Client) GetCDTTrafficGB(ctx context.Context, s domain.Server) (float64, error) {
	params := map[string]string{
		"Action":  "ListCdtInternetTraffic",
		"Version": "2021-08-13",
	}
	body, err := c.doRPC(ctx, c.cdtEndpoint, s.AccessKeyID, s.AccessKeySecret, params)
	if err != nil {
		return 0, err
	}
	var resp struct {
		TrafficDetails []struct {
			BusinessRegionId string  `json:"BusinessRegionId"`
			Traffic          float64 `json:"Traffic"`
		} `json:"TrafficDetails"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, err
	}

	wantDomestic := isDomesticRegion(s.Region)
	var totalBytes float64
	for _, d := range resp.TrafficDetails {
		if isDomesticRegion(d.BusinessRegionId) == wantDomestic {
			totalBytes += d.Traffic
		}
	}
	return totalBytes / (1024 * 1024 * 1024), nil
}

// BillingCycleForTime computes YYYY-MM in the configured timezone (default Asia/Shanghai)
// so month-boundary unlocks at 00:05 local time never query the previous month's UTC bill.
func BillingCycleForTime(now time.Time, tz string) string {
	if strings.TrimSpace(tz) == "" {
		tz = "Asia/Shanghai"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.FixedZone("CST", 8*3600)
	}
	return now.In(loc).Format("2006-01")
}

// GetMonthlyBillUSD queries current-month Aliyun BSS bill overview.
// Uses business.ap-southeast-1.aliyuncs.com for International site and business.aliyuncs.com for China site.
func (c *Client) GetMonthlyBillUSD(ctx context.Context, s domain.Server, now time.Time, tz string) (float64, error) {
	endpoint := c.bssIntlEndpt
	if s.Site == domain.SiteChina {
		endpoint = c.bssChinaEndpt
	}
	params := map[string]string{
		"Action":       "QueryBillOverview",
		"Version":      "2017-12-14",
		"BillingCycle": BillingCycleForTime(now, tz),
	}
	body, err := c.doRPC(ctx, endpoint, s.AccessKeyID, s.AccessKeySecret, params)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Success *bool  `json:"Success"`
		Code    string `json:"Code"`
		Message string `json:"Message"`
		Data    struct {
			Items struct {
				Item []struct {
					PretaxAmount float64 `json:"PretaxAmount"`
				} `json:"Item"`
			} `json:"Items"`
		} `json:"Data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, err
	}
	if (resp.Success != nil && !*resp.Success) || (resp.Code != "" && !strings.EqualFold(resp.Code, "Success")) {
		code := strings.TrimSpace(resp.Code)
		if code == "" {
			code = "UnknownError"
		}
		msg := strings.TrimSpace(resp.Message)
		if msg == "" {
			msg = "BSS API reported unsuccessful"
		}
		return 0, fmt.Errorf("aliyun BSS API error (%s): %s", code, msg)
	}
	var sum float64
	for _, item := range resp.Data.Items.Item {
		sum += item.PretaxAmount
	}
	return sum, nil
}

// doRPC signs and executes a standard Alibaba Cloud RPC v1 (HMAC-SHA1) GET request with transient retry.
func (c *Client) doRPC(ctx context.Context, endpoint, akID, akSecret string, extra map[string]string) ([]byte, error) {
	if akID == "" || akSecret == "" {
		return nil, fmt.Errorf("missing AccessKeyID or AccessKeySecret")
	}

	attempts := c.maxAttempts
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		raw, status, err := c.doRPCOnce(ctx, endpoint, akID, akSecret, extra)
		if err == nil {
			return raw, nil
		}
		lastErr = err

		if !isRetryableAliyunError(status, err) || attempt == attempts {
			return nil, lastErr
		}

		backoff := c.retryBaseDelay * time.Duration(attempt)
		if backoff <= 0 {
			backoff = 200 * time.Millisecond
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func (c *Client) doRPCOnce(ctx context.Context, endpoint, akID, akSecret string, extra map[string]string) ([]byte, int, error) {
	params := map[string]string{
		"Format":           "JSON",
		"AccessKeyId":      akID,
		"SignatureMethod":  "HMAC-SHA1",
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"SignatureVersion": "1.0",
		"SignatureNonce":   randomNonce(),
	}
	for k, v := range extra {
		params[k] = v
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, percentEncode(k)+"="+percentEncode(params[k]))
	}
	canonicalQuery := strings.Join(parts, "&")
	stringToSign := "GET&%2F&" + percentEncode(canonicalQuery)

	mac := hmac.New(sha1.New, []byte(akSecret+"&"))
	mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	fullURL := endpoint + "?" + canonicalQuery + "&Signature=" + percentEncode(signature)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, 0, err
	}
	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return nil, res.StatusCode, err
	}
	if res.StatusCode >= 400 {
		return nil, res.StatusCode, formatAliyunError(res.StatusCode, raw)
	}
	return raw, res.StatusCode, nil
}

func formatAliyunError(status int, raw []byte) error {
	var apiErr struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal(raw, &apiErr); err == nil && (apiErr.Code != "" || apiErr.Message != "") {
		return &aliyunAPIError{
			Status:  status,
			Code:    apiErr.Code,
			Message: apiErr.Message,
		}
	}
	return &aliyunAPIError{
		Status: status,
		Raw:    strings.TrimSpace(string(raw)),
	}
}

func percentEncode(s string) string {
	esc := url.QueryEscape(s)
	esc = strings.ReplaceAll(esc, "+", "%20")
	esc = strings.ReplaceAll(esc, "*", "%2A")
	esc = strings.ReplaceAll(esc, "%7E", "~")
	return esc
}

func randomNonce() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
