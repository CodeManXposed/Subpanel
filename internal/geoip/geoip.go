// Package geoip 用 ip2region xdb 提供 IP -> 地理 + 运营商 + 用途类型 查询。
//
// 数据源:lionsoul2014/ip2region IPv4 xdb + IPtoASN IPv4 TSV.GZ。
// 同时兼容旧的 18 字段满载 xdb。
//
// 设计:
//   - 启动加载完整 xdb 到内存,查询不走共享文件句柄
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
	ASNOrg    string `json:"asn_org"`    // ASN 注册组织
	UsageType string `json:"usage_type"` // IDC/CDN/DYN/MOB/COM/...
	// UsageTypeSource 为 xdb 或 inferred,避免把推断类型误认为原始数据。
	UsageTypeSource string `json:"usage_type_source,omitempty"`
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
	asnCur  atomic.Pointer[asnSnapshot]
	asnPath atomic.Value // string
}

type xdbHandle struct {
	ver     *xdb.Version
	content []byte
	pool    sync.Pool
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
	content, err := xdb.LoadContentFromFile(path)
	if err != nil {
		return fmt.Errorf("xdb content: %w", err)
	}
	h := &xdbHandle{ver: ver, content: content}
	probe, err := xdb.NewWithBuffer(ver, content)
	if err != nil {
		return fmt.Errorf("xdb searcher: %w", err)
	}
	h.pool.Put(probe)
	h.pool.New = func() any {
		searcher, _ := xdb.NewWithBuffer(ver, content)
		return searcher
	}
	s.cur.Store(h)
	s.xdbPath.Store(path)
	s.loaded.Store(true)
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

// LoadASN 加载 IPtoASN 的 IPv4 TSV/TSV.GZ 数据。空路径表示禁用。
func (s *Searcher) LoadASN(path string) error {
	if path == "" {
		s.asnCur.Store(nil)
		s.asnPath.Store("")
		return nil
	}
	snap, err := loadASNSnapshot(path)
	if err != nil {
		return err
	}
	s.asnCur.Store(snap)
	s.asnPath.Store(path)
	return nil
}

func (s *Searcher) ASNPath() string {
	v := s.asnPath.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

func (s *Searcher) ASNLoaded() bool { return s.asnCur.Load() != nil }

// Close 释放底层资源。
func (s *Searcher) Close() {
	s.cur.Store(nil)
	s.asnCur.Store(nil)
	s.loaded.Store(false)
}

// ErrNotLoaded xdb 没加载,Lookup 不会做事。
var ErrNotLoaded = errors.New("geoip xdb 未加载")

// Lookup 查 IP,并用 ASN 数据补充 ASN/组织/国家码以及推断网络类型。
func (s *Searcher) Lookup(ipStr string) *Info {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return nil
	}
	var info *Info
	if h := s.cur.Load(); h != nil {
		searcher := h.pool.Get().(*xdb.Searcher)
		raw, err := searcher.Search(ip.String())
		h.pool.Put(searcher)
		if err == nil && raw != "" {
			info = parseRecord(raw)
		}
	}
	var asn *ASNInfo
	if snap := s.asnCur.Load(); snap != nil {
		asn = snap.lookup(ip)
	}
	if info == nil && asn == nil {
		return nil
	}
	if info == nil {
		info = &Info{}
	}
	if info.ISP == "0" {
		info.ISP = ""
	}
	if asn != nil {
		if info.ASN == "" {
			info.ASN = asn.ASN
		}
		info.ASNOrg = asn.Organization
		if info.ISOCode == "" && asn.CountryCode != "None" {
			info.ISOCode = asn.CountryCode
		}
		if info.ISP == "" {
			info.ISP = asn.Organization
		}
	}
	info.CloudProvider = matchCloudProvider(
		info.ISP, info.ASNOrg, info.City, info.Province, info.Country, info.ASN, info.UsageType,
	)
	if info.UsageType == "" {
		info.UsageType, info.UsageTypeSource = inferUsageType(info)
	} else {
		info.UsageTypeSource = "xdb"
	}
	return info
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
	// 官方 ip2region_v4.xdb 使用 5 字段格式:
	// 国家|区域|省份|城市|ISP。旧的满载版使用下面的 18 字段格式。
	if len(parts) == 5 {
		info := &Info{
			Country:  get(0),
			Province: get(2),
			City:     get(3),
			ISP:      get(4),
		}
		info.ISOCode = inferISOCode(info.Country, info.Province)
		info.CloudProvider = matchCloudProvider(info.ISP, info.City, info.Province, info.Country)
		return info
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

func inferISOCode(country, province string) string {
	switch {
	case strings.Contains(province, "香港"):
		return "HK"
	case strings.Contains(province, "澳门"):
		return "MO"
	case strings.Contains(province, "台湾"):
		return "TW"
	case country == "中国" || strings.EqualFold(country, "China"):
		return "CN"
	default:
		return ""
	}
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
	Loaded     bool   `json:"loaded"`
	Path       string `json:"path"`
	Version    string `json:"version"` // IPv4/IPv6
	ASNLoaded  bool   `json:"asn_loaded"`
	ASNPath    string `json:"asn_path"`
	ASNRecords int    `json:"asn_records"`
}

func (s *Searcher) Snapshot() Snapshot {
	out := Snapshot{
		Loaded:    s.loaded.Load(),
		Path:      s.Path(),
		ASNLoaded: s.ASNLoaded(),
		ASNPath:   s.ASNPath(),
	}
	if h := s.cur.Load(); h != nil && h.ver != nil {
		out.Version = h.ver.Name
	}
	if snap := s.asnCur.Load(); snap != nil {
		out.ASNRecords = len(snap.ranges)
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
