package aliyun

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"cdt-smart-monitor/internal/domain"
)

type Client struct {
	httpClient *http.Client
}

func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

type InstanceSnapshot struct {
	Status   string
	PublicIP string
}

// DescribeInstance fetches ECS instance status and primary public IPv4.
func (c *Client) DescribeInstance(ctx context.Context, s domain.Server) (InstanceSnapshot, error) {
	endpoint := fmt.Sprintf("https://ecs.%s.aliyuncs.com/", s.Region)
	params := map[string]string{
		"Action":      "DescribeInstances",
		"Version":     "2014-05-26",
		"RegionId":    s.Region,
		"InstanceIds": fmt.Sprintf(`["%s"]`, s.InstanceID),
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
	endpoint := fmt.Sprintf("https://ecs.%s.aliyuncs.com/", s.Region)
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
	if stopMode == "" {
		stopMode = domain.StopModeStopCharging
	}
	endpoint := fmt.Sprintf("https://ecs.%s.aliyuncs.com/", s.Region)
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

// GetCDTTrafficGB queries current-month Aliyun CDT internet traffic in GB.
func (c *Client) GetCDTTrafficGB(ctx context.Context, s domain.Server) (float64, error) {
	params := map[string]string{
		"Action":  "ListCdtInternetTraffic",
		"Version": "2021-08-13",
	}
	body, err := c.doRPC(ctx, "https://cdt.aliyuncs.com/", s.AccessKeyID, s.AccessKeySecret, params)
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

	// Match domestic vs overseas bucket following CDT-Monitor convention: cn-* except cn-hongkong is domestic.
	wantDomestic := strings.HasPrefix(s.Region, "cn-") && s.Region != "cn-hongkong"
	var totalBytes float64
	for _, d := range resp.TrafficDetails {
		isDom := strings.HasPrefix(d.BusinessRegionId, "cn-") && d.BusinessRegionId != "cn-hongkong"
		if isDom == wantDomestic {
			totalBytes += d.Traffic
		}
	}
	return totalBytes / (1024 * 1024 * 1024), nil
}

// GetMonthlyBillUSD queries current-month Aliyun BSS bill overview.
// Uses business.ap-southeast-1.aliyuncs.com for International site and business.aliyuncs.com for China site.
func (c *Client) GetMonthlyBillUSD(ctx context.Context, s domain.Server, now time.Time) (float64, error) {
	endpoint := "https://business.ap-southeast-1.aliyuncs.com/"
	if s.Site == domain.SiteChina {
		endpoint = "https://business.aliyuncs.com/"
	}
	params := map[string]string{
		"Action":       "QueryBillOverview",
		"Version":      "2017-12-14",
		"BillingCycle": now.UTC().Format("2006-01"),
	}
	body, err := c.doRPC(ctx, endpoint, s.AccessKeyID, s.AccessKeySecret, params)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Data struct {
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
	var sum float64
	for _, item := range resp.Data.Items.Item {
		sum += item.PretaxAmount
	}
	return sum, nil
}

// doRPC signs and executes a standard Alibaba Cloud RPC v1 (HMAC-SHA1) GET request.
func (c *Client) doRPC(ctx context.Context, endpoint, akID, akSecret string, extra map[string]string) ([]byte, error) {
	if akID == "" || akSecret == "" {
		return nil, fmt.Errorf("missing AccessKeyID or AccessKeySecret")
	}
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

	var parts []string
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
		return nil, err
	}
	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("aliyun API HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
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
