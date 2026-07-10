// Package cloudip 提供"某 IP 是否属于云厂商"的快速查询。
//
// v2 实现:底层换成 geoip xdb,按 ISP 字段关键词反推云厂商。
// 不再爬 9 个上游数据源,所有云判定都走 xdb。
//
// 兼容性:对外 API 与旧版一致 (Matcher.Match / Fetcher.RunOnce / Snapshot),
// 上层 detector / webui / config 无需修改。
package cloudip

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huabanmao168/SubPanel/internal/geoip"
)

// Matcher 包装 geoip 提供 Match 接口。
type Matcher struct {
	geo *geoip.Searcher
}

// NewMatcher 用全局 geoip Searcher。
func NewMatcher() *Matcher {
	return &Matcher{geo: geoip.Global()}
}

// NewMatcherWith 测试或自定义场景显式注入。
func NewMatcherWith(g *geoip.Searcher) *Matcher {
	return &Matcher{geo: g}
}

// Match 返回 (是否云 IP, provider 英文标识)。
func (m *Matcher) Match(ipStr string) (bool, string) {
	if m == nil || m.geo == nil || !m.geo.Loaded() {
		return false, ""
	}
	info := m.geo.Lookup(ipStr)
	if info == nil || info.CloudProvider == "" {
		return false, ""
	}
	return true, info.CloudProvider
}

// Snapshot 给 Web UI 用。
// 由于 xdb 自身没有"按 provider 拆分计数"的能力(provider 是 ISP 关键词反推的),
// Stats 字段保留为空 map,Total 也是 0 — UI 改成显示 xdb 元信息即可。
type Snapshot struct {
	Updated    time.Time      `json:"updated"`
	Total      int            `json:"total"`
	Stats      map[string]int `json:"stats"`
	Source     string         `json:"source"`      // "ip2region-xdb"
	XdbPath    string         `json:"xdb_path"`    // 当前 xdb 路径
	XdbVersion string         `json:"xdb_version"` // IPv4/IPv6
	XdbLoaded  bool           `json:"xdb_loaded"`
}

func (m *Matcher) Snapshot() Snapshot {
	out := Snapshot{Source: "ip2region-xdb", Stats: map[string]int{}}
	if m != nil && m.geo != nil {
		snap := m.geo.Snapshot()
		out.XdbPath = snap.Path
		out.XdbVersion = snap.Version
		out.XdbLoaded = snap.Loaded
	}
	return out
}

// ----------------- Fetcher -----------------

// Fetcher 不再爬多数据源,但会重新加载 geoip.xdb_path 指向的本地文件。
type Fetcher struct {
	matcher *Matcher
	logger  *slog.Logger
	running atomic.Bool
	mu      sync.Mutex
	last    time.Time
}

func NewFetcher(m *Matcher, _ any, logger *slog.Logger) *Fetcher {
	return &Fetcher{matcher: m, logger: logger}
}

// RunOnce 从当前路径重新读取 xdb 并原子替换查询快照。
func (f *Fetcher) RunOnce(ctx context.Context) (int, error) {
	if !f.running.CompareAndSwap(false, true) {
		return 0, errors.New("已有任务在运行中")
	}
	defer f.running.Store(false)
	f.mu.Lock()
	f.last = time.Now()
	f.mu.Unlock()
	if f.matcher == nil || f.matcher.geo == nil || !f.matcher.geo.Loaded() {
		return 0, errors.New("xdb 未加载,请检查 geoip.xdb_path 配置")
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	path := f.matcher.geo.Path()
	if err := f.matcher.geo.Load(path); err != nil {
		return 0, err
	}
	if asnPath := f.matcher.geo.ASNPath(); asnPath != "" {
		if err := f.matcher.geo.LoadASN(asnPath); err != nil {
			return 0, err
		}
	}
	if f.logger != nil {
		f.logger.Info("云 IP 库: xdb 已重新加载",
			"path", path,
			"version", f.matcher.geo.Snapshot().Version,
		)
	}
	return 0, nil
}

// RunPeriodic 定期重载本地 xdb 文件。文件更新由安装器或运维流程负责。
func (f *Fetcher) RunPeriodic(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := f.RunOnce(ctx); err != nil && f.logger != nil {
					f.logger.Warn("云 IP 库定时重载失败", "err", err)
				}
			}
		}
	}()
}
