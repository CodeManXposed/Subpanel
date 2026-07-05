// Package geoip 用 ip2region xdb 提供 IP -> 地理 + 运营商 + 用途类型 查询。
//
// 数据源:lionsoul2014/ip2region 满载版 xdb 文件。
// 字段格式:洲|国|省|市|区|ISP|经度|纬度|adcode|区号|邮编|时区|币种|ASN|usage_type|...
//
// 设计:
//   - 启动加载 xdb 到内存(file-only 模式,首次访问惰性 mmap,内存占用 ~350MB)
//   - Lookup 线程安全,O(log N) 二分查找
//   - 同时把 ISP 字段映射成"云厂商 provider"用于反爬规则
package geoip

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

// Info 单次查询的完整结果。
type Info struct {
	Continent string `json:"continent"`  // 洲(亚洲/北美洲/...)
	Country   string `json:"country"`    // 国家(中国/美国/...)
	Province  string `json:"province"`   // 省/州
	City      string `json:"city"`       // 市
	District  string `json:"district"`   // 区/县
	ISP       string `json:"isp"`        // 电信/移动/联通/阿里/腾讯/微软/谷歌/Cloudflare/...
	Lon       string `json:"lon"`        // 经度(字符串)
	Lat       string `json:"lat"`        // 纬度
	AreaCode  string `json:"area_code"`  // 行政区划编码
	DialCode  string `json:"dial_code"`  // 区号
	ZipCode   string `json:"zip_code"`   // 邮编
	Timezone  string `json:"timezone"`   // Asia/Shanghai
	Currency  string `json:"currency"`   // CNY/USD
	ASN       string `json:"asn"`        // AS4134
	UsageType string `json:"usage_type"` // IDC/CDN/DYN/MOB/COM/...
	// 后续字段(adcode_secondary / chxx_code / iso2)按需补
	ISOCode string `json:"iso_code"` // CN/US

	// 派生:云厂商标记。空字符串=不是云厂商,非空=厂商英文标识(aliyun/tencent/...)
	CloudProvider string `json:"cloud_provider,omitempty"`
}

// Searcher 用原子指针包 xdb.Searcher,Reload 时无锁切换。
type Searcher struct {
	cur     atomic.Pointer[xdbHandle]
	xdbPath atomic.Value // string
	loaded  atomic.Bool
}

type xdbHandle struct {
	s   *xdb.Searcher
	ver *xdb.Version
}

// New 返回未加载的 Searcher。空路径合法(意味着 geoip 关闭),所有查询返回 nil。
func New() *Searcher {
	return &Searcher{}
}

// Load 加载 xdb 文件。重复调用会替换旧实例。空路径=禁用。
func (s *Searcher) Load(path string) error {
	if path == "" {
		s.cur.Store(nil)
		s.loaded.Store(false)
		s.xdbPath.Store("")
		return nil
	}
	header, err := xdb.LoadHeaderFromFile(path)
	if err != nil {
		return fmt.Errorf("xdb header: %w", err)
	}
	ver, err := xdb.VersionFromHeader(header)
	if err != nil {
		return fmt.Errorf("xdb version: %w", err)
	}
	searcher, err := xdb.NewWithFileOnly(ver, path)
	if err != nil {
		return fmt.Errorf("xdb open: %w", err)
	}
	old := s.cur.Swap(&xdbHandle{s: searcher, ver: ver})
	s.xdbPath.Store(path)
	s.loaded.Store(true)
	if old != nil {
		old.s.Close()
	}
	return nil
}

// Loaded 是否已加载可用 xdb。
func (s *Searcher) Loaded() bool { return s.loaded.Load() }

// Path 当前 xdb 路径。
func (s *Searcher) Path() string {
	v := s.xdbPath.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// Close 释放底层资源。
func (s *Searcher) Close() {
	if h := s.cur.Swap(nil); h != nil {
		h.s.Close()
	}
	s.loaded.Store(false)
}

// ErrNotLoaded xdb 没加载,Lookup 不会做事。
var ErrNotLoaded = errors.New("geoip xdb 未加载")

// Lookup 查 IP。返回 nil 表示 IP 无效或 xdb 没加载。
func (s *Searcher) Lookup(ipStr string) *Info {
	h := s.cur.Load()
	if h == nil {
		return nil
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return nil
	}
	raw, err := h.s.Search(ipStr)
	if err != nil || raw == "" {
		return nil
	}
	return parseRecord(raw)
}

// parseRecord 解析 xdb 返回的 | 分隔字段。
// 标准格式: 洲|国|省|市|区|ISP|lon|lat|adcode|dial|zip|tz|cur|asn|usage|...|chxx|iso2
// 实际字段数 17-18,缺失部分留空。
func parseRecord(raw string) *Info {
	parts := strings.Split(raw, "|")
	get := func(i int) string {
		if i < 0 || i >= len(parts) {
			return ""
		}
		return strings.TrimSpace(parts[i])
	}
	info := &Info{
		Continent: get(0),
		Country:   get(1),
		Province:  get(2),
		City:      get(3),
		District:  get(4),
		ISP:       get(5),
		Lon:       get(6),
		Lat:       get(7),
		AreaCode:  get(8),
		DialCode:  get(9),
		ZipCode:   get(10),
		Timezone:  get(11),
		Currency:  get(12),
		ASN:       get(13),
		UsageType: get(14),
		// 15: chxx_code(行政编码二级),跳过
		ISOCode: get(len(parts) - 1), // 最后一个一般是 ISO2
	}
	info.CloudProvider = matchCloudProvider(
		info.ISP,
		info.City,
		info.Province,
		info.Country,
		info.ASN,
		info.UsageType,
	)
	return info
}

// cloudKeywords ISP 字段关键词 → provider 英文标识。
// 关键词大小写不敏感,中英文都覆盖。
var cloudKeywords = []struct {
	keyword  string
	provider string
}{
	// 国内云
	{"阿里", "aliyun"},
	{"aliyun", "aliyun"},
	{"alibaba", "aliyun"},
	{"腾讯", "tencent"},
	{"tencent", "tencent"},
	{"华为", "huawei"},
	{"huawei", "huawei"},
	{"字节", "bytedance"},
	{"bytedance", "bytedance"},
	{"火山", "bytedance"},
	{"百度", "baidu"},
	{"baidu", "baidu"},
	{"京东", "jdcloud"},
	{"金山", "kingsoft"},
	{"ucloud", "ucloud"},
	{"青云", "qingcloud"},
	{"qingcloud", "qingcloud"},

	// 海外云
	{"亚马逊", "aws"},
	{"amazon", "aws"},
	{"aws", "aws"},
	{"微软", "azure"},
	{"microsoft", "azure"},
	{"azure", "azure"},
	{"谷歌", "gcp"},
	{"google", "gcp"},
	{"oracle", "oracle"},
	{"甲骨文", "oracle"},
	{"vultr", "vultr"},
	{"digitalocean", "digitalocean"},
	{"linode", "linode"},
	{"hetzner", "hetzner"},
	{"ovh", "ovh"},
	{"akamai", "akamai"},
	{"cloudflare", "cloudflare"},
	{"fastly", "fastly"},
}

func matchCloudProvider(fields ...string) string {
	for _, field := range fields {
		if field == "" {
			continue
		}
		low := strings.ToLower(field)
		for _, kw := range cloudKeywords {
			if strings.Contains(low, kw.keyword) {
				return kw.provider
			}
		}
	}
	return ""
}

// Snapshot 提供给 UI 的状态摘要。
type Snapshot struct {
	Loaded  bool   `json:"loaded"`
	Path    string `json:"path"`
	Version string `json:"version"` // IPv4/IPv6
}

func (s *Searcher) Snapshot() Snapshot {
	out := Snapshot{Loaded: s.loaded.Load(), Path: s.Path()}
	if h := s.cur.Load(); h != nil && h.ver != nil {
		out.Version = h.ver.Name
	}
	return out
}

// 单例 + Once,方便外部不用传引用也能查(测试时可重置)。
var (
	globalOnce sync.Once
	global     *Searcher
)

func Global() *Searcher {
	globalOnce.Do(func() { global = New() })
	return global
}
