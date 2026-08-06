// Package dnswatch 监控入口 DNS 的 IPv4 解析变化，并冻结变化前的订阅记录。
package dnswatch

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

// NormalizeName 清理用户输入的 DNS 主机名。
func NormalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// ResolveIPv4 返回排序、去重后的 A 记录列表。
func ResolveIPv4(ctx context.Context, name string) ([]string, error) {
	name = NormalizeName(name)
	if name == "" || strings.ContainsAny(name, "/: ") {
		return nil, fmt.Errorf("invalid DNS name")
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, addr := range addrs {
		if ip := addr.IP.To4(); ip != nil {
			set[ip.String()] = true
		}
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("DNS has no IPv4 A record")
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out, nil
}

type Manager struct {
	store    *store.Store
	logger   *slog.Logger
	interval time.Duration
	resolve  func(context.Context, string) ([]string, error)
	now      func() time.Time
}

func New(st *store.Store, logger *slog.Logger, interval time.Duration) *Manager {
	if interval <= 0 {
		interval = time.Minute
	}
	return &Manager{store: st, logger: logger, interval: interval, resolve: ResolveIPv4, now: time.Now}
}

func (m *Manager) Run(ctx context.Context) {
	go func() {
		m.checkAll(ctx)
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.checkAll(ctx)
			}
		}
	}()
}

func (m *Manager) checkAll(ctx context.Context) {
	watchers, err := m.store.ListDNSWatchers(ctx, true)
	if err != nil {
		m.logger.Warn("读取 DNS 追踪列表失败", "err", err)
		return
	}
	for _, watcher := range watchers {
		if ctx.Err() != nil {
			return
		}
		m.checkOne(ctx, watcher)
	}
}

func (m *Manager) checkOne(parent context.Context, watcher store.DNSWatcher) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	now := m.now().UnixMilli()
	ips, err := m.resolve(ctx, watcher.DNSName)
	if err != nil {
		_ = m.store.UpdateDNSWatcherState(parent, watcher.ID, watcher.LastIPs, err.Error(), now)
		m.logger.Warn("DNS 追踪解析失败", "dns", watcher.DNSName, "tenant", watcher.Tenant, "err", err)
		return
	}
	current := strings.Join(ips, ",")
	if watcher.LastIPs == "" {
		_ = m.store.SetDNSWatcherBaseline(parent, watcher.ID, current, now)
		return
	}
	if current == watcher.LastIPs {
		_ = m.store.UpdateDNSWatcherState(parent, watcher.ID, current, "", now)
		return
	}

	change, err := m.store.AddAWSIPChange(parent, store.AWSIPChange{
		OccurredTS:      now,
		DNSName:         watcher.DNSName,
		Tenant:          watcher.Tenant,
		OldIP:           watcher.LastIPs,
		NewIP:           current,
		LookbackMinutes: watcher.LookbackMinutes,
		Note:            watcher.Note,
	})
	if err != nil {
		_ = m.store.UpdateDNSWatcherState(parent, watcher.ID, watcher.LastIPs, err.Error(), now)
		m.logger.Error("DNS 变化快照失败", "dns", watcher.DNSName, "tenant", watcher.Tenant, "err", err)
		return
	}
	if err := m.store.RecordDNSIPTransition(parent, watcher, current, now); err != nil {
		_ = m.store.UpdateDNSWatcherState(parent, watcher.ID, watcher.LastIPs, err.Error(), now)
		m.logger.Error("DNS IP 存活记录失败", "dns", watcher.DNSName, "tenant", watcher.Tenant, "err", err)
		return
	}
	m.logger.Warn("检测到入口 DNS IP 变化", "dns", watcher.DNSName, "tenant", watcher.Tenant,
		"old", watcher.LastIPs, "new", current, "subscribers", change.SubscriberCount)
}
