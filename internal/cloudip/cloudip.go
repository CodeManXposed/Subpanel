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

// ----------------- Fetcher (空实现,兼容旧接口) -----------------

// Fetcher 旧版会定期爬数据源,新版 xdb 由用户手动更新文件,这里只保留 stub。
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

// RunOnce 不再做网络拉取,仅返回 xdb 当前状态。
// 保留接口让 webui 的"立即更新"按钮不报错,前端改成"重新加载 xdb"语义。
func (f *Fetcher) RunOnce(_ context.Context) (int, error) {
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
	if f.logger != nil {
		f.logger.Info("云 IP 库: xdb 已就绪",
			"path", f.matcher.geo.Path(),
			"version", f.matcher.geo.Snapshot().Version,
		)
	}
	return 0, nil
}

// RunPeriodic 旧版后台周期任务,新版 xdb 不需要,留空 stub。
func (f *Fetcher) RunPeriodic(_ context.Context, _ time.Duration) {
	if f.logger != nil {
		f.logger.Info("云 IP 库: 已切换为 xdb 模式,不再定时拉取数据源")
	}
}
