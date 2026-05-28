// Package blacklist 全局黑名单 — 四个一键开关 + ISP 关键字。
// 与 detector 触发规则解耦:detector 跑「行为型 + GeoIP 字段命中」逻辑,
// 本模块跑「全局粗粒度拦截」,命中即投毒,优先级高于 detector。
//
// 持久化:store.meta,key 前缀 bl_。热更新走 atomic.Pointer 快照,免锁读取。
//
// 四个开关:
//   - bl_oversea_enabled : 非中国 IP 拉黑(ISOCode != CN/HK/MO/TW 视为海外,未知也算)
//     注:港澳台是否算境内有歧义,这里默认算境内,不拦
//   - bl_cloud_enabled   : 命中云厂商 IP 库拉黑
//   - bl_browser_enabled : 浏览器直访拉黑(Accept 头带 text/html)
//   - bl_isp_keywords    : ISP 字段子串包含(CSV,任一命中即拉黑)
package blacklist

import (
	"strings"
	"sync/atomic"

	"github.com/huabanmao168/SubPanel/internal/store"
)

type Snapshot struct {
	OverseaEnabled bool
	CloudEnabled   bool
	BrowserEnabled bool
	ISPKeywords    []string
}

type Manager struct {
	st   *store.Store
	snap atomic.Pointer[Snapshot]
}

const (
	MetaOversea  = "bl_oversea_enabled"
	MetaCloud    = "bl_cloud_enabled"
	MetaBrowser  = "bl_browser_enabled"
	MetaISPKwCSV = "bl_isp_keywords"
)

func New(st *store.Store) *Manager {
	m := &Manager{st: st}
	_ = m.Reload()
	return m
}

// Reload 从 meta 读最新配置,原子替换内存快照。
func (m *Manager) Reload() error {
	sn := &Snapshot{}
	sn.OverseaEnabled = readBool(m.st, MetaOversea)
	sn.CloudEnabled = readBool(m.st, MetaCloud)
	sn.BrowserEnabled = readBool(m.st, MetaBrowser)
	if v, _ := m.st.GetMeta(MetaISPKwCSV); v != "" {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				sn.ISPKeywords = append(sn.ISPKeywords, p)
			}
		}
	}
	m.snap.Store(sn)
	return nil
}

// Get 返回当前快照(只读,不要修改字段)。
func (m *Manager) Get() *Snapshot {
	s := m.snap.Load()
	if s == nil {
		return &Snapshot{}
	}
	return s
}

// Update 写 meta + reload。
func (m *Manager) Update(s Snapshot) error {
	if err := writeBool(m.st, MetaOversea, s.OverseaEnabled); err != nil {
		return err
	}
	if err := writeBool(m.st, MetaCloud, s.CloudEnabled); err != nil {
		return err
	}
	if err := writeBool(m.st, MetaBrowser, s.BrowserEnabled); err != nil {
		return err
	}
	kw := strings.Join(s.ISPKeywords, ",")
	if err := m.st.SetMeta(MetaISPKwCSV, kw); err != nil {
		return err
	}
	return m.Reload()
}

// IsOverseaCountry 判断是否非中国大陆。iso 优先 ISO 码,空 = 未知。
// 未知一律视为海外(防 xdb 漏库被绕过)。
// 注:港澳台按非 CN 算海外,符合"CN 以外全拦"的需求。
func IsOverseaCountry(iso, country string) bool {
	iso = strings.ToUpper(strings.TrimSpace(iso))
	country = strings.TrimSpace(country)
	if iso == "" && country == "" {
		return true // 未知 = 当海外拒
	}
	if iso == "CN" {
		return false
	}
	// 没有 ISO 码时用中文名兜底
	if iso == "" && country == "中国" {
		return false
	}
	return true
}

// IsBrowser 简单判断 — Accept 头含 text/html。
// 订阅客户端基本都发 */* 或不带,误伤面小。
func IsBrowser(acceptHeader string) bool {
	return strings.Contains(strings.ToLower(acceptHeader), "text/html")
}

// ISPHitKeyword 检查 ISP 字段是否包含任一关键字(子串、忽略大小写)。
func (m *Manager) ISPHitKeyword(isp string) (bool, string) {
	if isp == "" {
		return false, ""
	}
	low := strings.ToLower(isp)
	sn := m.Get()
	for _, kw := range sn.ISPKeywords {
		k := strings.ToLower(strings.TrimSpace(kw))
		if k != "" && strings.Contains(low, k) {
			return true, kw
		}
	}
	return false, ""
}

// Evaluate 综合判断 — 命中返回 (true, 原因 tag)。
//   - iso/country: GeoIP 国家字段
//   - isp:        GeoIP ISP 字段
//   - isCloud:    云厂商命中标志(调用方查 cloudMatcher 后传入)
//   - accept:     Accept 请求头
//
// 评估顺序:海外 → 云厂商 → ISP 关键字 → 浏览器。任一命中即返回。
// 顺序选择:粗→细,命中投毒后短路,省去后续 lookup。
func (m *Manager) Evaluate(iso, country, isp string, isCloud bool, accept string) (bool, string) {
	sn := m.Get()
	if sn.OverseaEnabled && IsOverseaCountry(iso, country) {
		c := iso
		if c == "" {
			c = country
		}
		if c == "" {
			c = "unknown"
		}
		return true, "bl_oversea:" + c
	}
	if sn.CloudEnabled && isCloud {
		return true, "bl_cloud"
	}
	if len(sn.ISPKeywords) > 0 {
		if hit, kw := m.ISPHitKeyword(isp); hit {
			return true, "bl_isp:" + kw
		}
	}
	if sn.BrowserEnabled && IsBrowser(accept) {
		return true, "bl_browser"
	}
	return false, ""
}

func readBool(st *store.Store, key string) bool {
	v, _ := st.GetMeta(key)
	return v == "true" || v == "1" || v == "on"
}

func writeBool(st *store.Store, key string, v bool) error {
	s := "false"
	if v {
		s = "true"
	}
	return st.SetMeta(key, s)
}
