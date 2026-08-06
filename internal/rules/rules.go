// Package rules 维护 DB 来源的可热更新规则:IP 白名单。
//
// 设计:
//   - 启动时从 store 加载,在内存里构建快速匹配结构
//   - CRUD 后立即 Reload
//   - 提供给 detector 的查询函数线程安全
package rules

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

type Manager struct {
	mu sync.RWMutex
	st *store.Store

	// IP 白名单:支持单 IP 和 CIDR
	ipWhitelistSingle map[string]struct{}
	ipWhitelistNets   []*net.IPNet
}

func NewManager(st *store.Store) *Manager {
	return &Manager{
		st:                st,
		ipWhitelistSingle: map[string]struct{}{},
	}
}

// Reload 全量重读 DB。失败时保留旧数据。
func (m *Manager) Reload() error {
	ipEntries, err := m.st.ListIPWhitelist()
	if err != nil {
		return err
	}

	singles := map[string]struct{}{}
	var nets []*net.IPNet
	for _, e := range ipEntries {
		t := strings.TrimSpace(e.Target)
		if strings.Contains(t, "/") {
			_, n, err := net.ParseCIDR(t)
			if err == nil {
				nets = append(nets, n)
			}
		} else {
			singles[t] = struct{}{}
		}
	}
	domainEntries, err := m.st.ListDomainWhitelist()
	if err != nil {
		return err
	}
	for _, e := range domainEntries {
		for _, ip := range e.ResolvedIPs {
			if net.ParseIP(ip) != nil {
				singles[ip] = struct{}{}
			}
		}
	}

	m.mu.Lock()
	m.ipWhitelistSingle = singles
	m.ipWhitelistNets = nets
	m.mu.Unlock()
	return nil
}

// IPWhitelisted 检查 IP 是否在白名单(支持精确和 CIDR)。
func (m *Manager) IPWhitelisted(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.ipWhitelistSingle[ip]; ok {
		return true
	}
	if len(m.ipWhitelistNets) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range m.ipWhitelistNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// ---------- CRUD wrappers(写完触发 Reload) ----------

func (m *Manager) AddIPWhitelist(target, note string) error {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "/") {
		if _, _, err := net.ParseCIDR(t); err != nil {
			return err
		}
	} else if net.ParseIP(t) == nil {
		return errIPInvalid
	}
	if err := m.st.AddIPWhitelist(t, note); err != nil {
		return err
	}
	return m.Reload()
}

func (m *Manager) DeleteIPWhitelist(id int64) error {
	if err := m.st.DeleteIPWhitelist(id); err != nil {
		return err
	}
	return m.Reload()
}

// UpdateIPWhitelist 校验 target 合法性 + 写库 + 触发热加载。
func (m *Manager) UpdateIPWhitelist(id int64, target, note string) error {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "/") {
		if _, _, err := net.ParseCIDR(t); err != nil {
			return err
		}
	} else if net.ParseIP(t) == nil {
		return errIPInvalid
	}
	if err := m.st.UpdateIPWhitelist(id, t, note); err != nil {
		return err
	}
	return m.Reload()
}

func normalizeDomain(target string) (string, error) {
	t := strings.ToLower(strings.TrimSpace(target))
	if host, port, err := net.SplitHostPort(t); err == nil && port != "" {
		t = host
	} else if i := strings.LastIndexByte(t, ':'); i > 0 {
		if _, err := strconv.Atoi(t[i+1:]); err == nil {
			t = t[:i]
		}
	}
	t = strings.TrimSuffix(t, ".")
	if len(t) == 0 || len(t) > 253 || net.ParseIP(t) != nil || !strings.Contains(t, ".") {
		return "", fmt.Errorf("target must be a valid domain")
	}
	for _, label := range strings.Split(t, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("target must be a valid domain")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("target must be a valid domain")
			}
		}
	}
	return t, nil
}

func (m *Manager) AddDomainWhitelist(ctx context.Context, domain, note string) error {
	d, err := normalizeDomain(domain)
	if err != nil {
		return err
	}
	if err := m.st.AddDomainWhitelist(d, note); err != nil {
		return err
	}
	return m.RefreshDomainWhitelist(ctx)
}

func (m *Manager) DeleteDomainWhitelist(id int64) error {
	if err := m.st.DeleteDomainWhitelist(id); err != nil {
		return err
	}
	return m.Reload()
}

// RefreshDomainWhitelist 在本机解析域名，并原子替换它对应的白名单地址。
func (m *Manager) RefreshDomainWhitelist(ctx context.Context) error {
	entries, err := m.st.ListDomainWhitelist()
	if err != nil {
		return err
	}
	resolver := net.DefaultResolver
	for _, entry := range entries {
		lookupCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		addrs, lookupErr := resolver.LookupIPAddr(lookupCtx, entry.Domain)
		cancel()
		if lookupErr != nil {
			_ = m.st.SetDomainWhitelistResolution(entry.ID, entry.ResolvedIPs, lookupErr.Error())
			continue
		}
		seen := make(map[string]struct{})
		var ips []string
		for _, addr := range addrs {
			ip := addr.IP.String()
			if ip == "" {
				continue
			}
			if _, ok := seen[ip]; !ok {
				seen[ip] = struct{}{}
				ips = append(ips, ip)
			}
		}
		sort.Strings(ips)
		_ = m.st.SetDomainWhitelistResolution(entry.ID, ips, "")
	}
	return m.Reload()
}

func (m *Manager) RunDomainWhitelistResolver(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	go func() {
		_ = m.RefreshDomainWhitelist(ctx)
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = m.RefreshDomainWhitelist(ctx)
			}
		}
	}()
}

// errIPInvalid 用于 IP 校验失败。
var errIPInvalid = &simpleErr{"target must be valid IP or CIDR"}

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }
