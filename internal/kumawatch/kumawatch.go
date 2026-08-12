// Package kumawatch polls Uptime Kuma's Prometheus endpoint and turns an
// explicitly bound UP -> DOWN transition into a DNS watcher failure anchor.
package kumawatch

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

const (
	MetaURL      = "kuma_metrics_url"
	MetaAPIKey   = "kuma_metrics_api_key"
	MetaEnabled  = "kuma_metrics_enabled"
	MetaInterval = "kuma_metrics_interval_seconds"
)

type Monitor struct {
	Key      string `json:"key"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Hostname string `json:"hostname"`
	Port     string `json:"port"`
	Status   int    `json:"status"`
}

func (m Monitor) fingerprint() string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join([]string{m.ID, m.Name, m.Hostname, m.Port}, "\x1f")))
}

type Client struct {
	HTTP *http.Client
}

func (c Client) Fetch(ctx context.Context, endpoint, apiKey string) ([]Monitor, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid Kuma metrics URL")
	}
	if !strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/metrics") {
		u.Path = strings.TrimRight(u.Path, "/") + "/metrics"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain")
	if apiKey != "" {
		req.SetBasicAuth("", apiKey)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("Kuma metrics returned HTTP %d", resp.StatusCode)
	}
	return Parse(resp.Body)
}

func Parse(r io.Reader) ([]Monitor, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, 8<<20))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	monitors := make([]Monitor, 0)
	seen := make(map[string]bool)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "monitor_status{") {
			continue
		}
		closeAt := strings.LastIndex(line, "}")
		if closeAt < len("monitor_status{") {
			continue
		}
		labels, err := parseLabels(line[len("monitor_status{"):closeAt])
		if err != nil {
			return nil, err
		}
		value := strings.TrimSpace(line[closeAt+1:])
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		status64, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		m := Monitor{ID: labels["monitor_id"], Name: labels["monitor_name"], Type: labels["monitor_type"], Hostname: strings.ToLower(strings.TrimSuffix(labels["monitor_hostname"], ".")), Port: labels["monitor_port"], Status: int(status64)}
		m.Key = m.fingerprint()
		if m.ID == "" || seen[m.Key] {
			continue
		}
		seen[m.Key] = true
		monitors = append(monitors, m)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return monitors, nil
}

func parseLabels(raw string) (map[string]string, error) {
	out := make(map[string]string)
	for len(strings.TrimSpace(raw)) > 0 {
		raw = strings.TrimSpace(raw)
		eq := strings.IndexByte(raw, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("invalid Prometheus labels")
		}
		key := strings.TrimSpace(raw[:eq])
		raw = strings.TrimSpace(raw[eq+1:])
		if len(raw) == 0 || raw[0] != '"' {
			return nil, fmt.Errorf("invalid Prometheus label value")
		}
		var value strings.Builder
		escaped := false
		end := -1
		for i := 1; i < len(raw); i++ {
			ch := raw[i]
			if escaped {
				switch ch {
				case 'n':
					value.WriteByte('\n')
				case '\\', '"':
					value.WriteByte(ch)
				default:
					value.WriteByte(ch)
				}
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				end = i
				break
			}
			value.WriteByte(ch)
		}
		if end < 0 {
			return nil, fmt.Errorf("unterminated Prometheus label")
		}
		out[key] = value.String()
		raw = strings.TrimSpace(raw[end+1:])
		if raw == "" {
			break
		}
		if raw[0] != ',' {
			return nil, fmt.Errorf("invalid Prometheus label separator")
		}
		raw = raw[1:]
	}
	return out, nil
}

type Manager struct {
	store  *store.Store
	logger *slog.Logger
	client Client
}

func New(st *store.Store, logger *slog.Logger) *Manager {
	return &Manager{store: st, logger: logger, client: Client{HTTP: &http.Client{Timeout: 15 * time.Second}}}
}

func (m *Manager) Run(ctx context.Context) {
	go func() {
		for {
			interval := m.poll(ctx)
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func (m *Manager) poll(ctx context.Context) time.Duration {
	interval := 30 * time.Second
	if raw, _ := m.store.GetMeta(MetaInterval); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 15 && seconds <= 300 {
			interval = time.Duration(seconds) * time.Second
		}
	}
	if enabled, _ := m.store.GetMeta(MetaEnabled); enabled != "true" {
		return interval
	}
	endpoint, _ := m.store.GetMeta(MetaURL)
	apiKey, _ := m.store.GetMeta(MetaAPIKey)
	monitors, err := m.client.Fetch(ctx, endpoint, apiKey)
	if err != nil {
		m.logger.Warn("读取 Uptime Kuma metrics 失败", "err", err)
		_ = m.store.SetMeta("kuma_metrics_last_error", err.Error())
		return interval
	}
	_ = m.store.SetMeta("kuma_metrics_last_error", "")
	_ = m.store.SetMeta("kuma_metrics_last_checked_ts", strconv.FormatInt(time.Now().UnixMilli(), 10))
	byKey := make(map[string]Monitor, len(monitors))
	for _, monitor := range monitors {
		byKey[monitor.Key] = monitor
	}
	bindings, err := m.store.ListKumaBindings(ctx)
	if err != nil {
		m.logger.Warn("读取 Kuma 绑定失败", "err", err)
		return interval
	}
	for _, binding := range bindings {
		monitor, ok := byKey[binding.MonitorKey]
		now := time.Now().UnixMilli()
		if !ok {
			_ = m.store.UpdateKumaBindingState(ctx, binding.WatcherID, binding.LastStatus, now, "bound monitor is missing from /metrics")
			continue
		}
		if binding.LastStatus == 1 && monitor.Status == 0 {
			watcher, watcherErr := m.store.GetDNSWatcher(ctx, binding.WatcherID)
			if watcherErr == nil && watcher.Enabled {
				ip := firstCSV(watcher.LastIPs)
				if ip != "" {
					if _, markErr := m.store.MarkDNSWatcherFailure(ctx, watcher.DNSName, watcher.Tenant, ip, now); markErr != nil {
						m.logger.Warn("Kuma DOWN 写入 AWS 失联锚点失败", "dns", watcher.DNSName, "monitor", monitor.Name, "err", markErr)
					} else {
						m.logger.Warn("Kuma 检测到 AWS 入口失联", "dns", watcher.DNSName, "monitor", monitor.Name, "ip", ip)
					}
				}
			}
		}
		_ = m.store.UpdateKumaBindingState(ctx, binding.WatcherID, monitor.Status, now, "")
	}
	return interval
}

func firstCSV(values string) string {
	for _, value := range strings.Split(values, ",") {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
