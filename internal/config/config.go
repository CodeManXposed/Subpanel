package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen       string   `yaml:"listen"`         // gateway 反代监听,如 127.0.0.1:8443
	AdminListen  string   `yaml:"admin_listen"`   // Web UI 监听,如 127.0.0.1:9090
	HMACSaltFile string   `yaml:"hmac_salt_file"` // HMAC salt 文件路径
	Storage      Storage  `yaml:"storage"`
	RealIP       RealIP   `yaml:"real_ip"`
	Tenants      []Tenant `yaml:"tenants"`
	// Paths 全局订阅路径已弃用,改为每租户独立 subscribe_path。
	// 保留字段用于解析旧配置时给个明确报错提示(见 validate)。
	Paths    Paths       `yaml:"paths,omitempty"`
	Detector DetectorCfg `yaml:"detector"`
	// Actions 已废弃:命中规则即投毒,无等级映射。yaml 老配置里的 actions 节会被忽略。
	Faker FakerCfg `yaml:"faker"`
	Admin AdminCfg `yaml:"admin"`
	GeoIP GeoIPCfg `yaml:"geoip"`
}

// GeoIPCfg ip2region xdb 配置。xdb_path 为空时整体禁用 geoip 功能,
// from_cloud_ip / country / usage_type / isp 规则全部失效。
type GeoIPCfg struct {
	XDBPath string `yaml:"xdb_path"` // 城市/ISP xdb
	ASNPath string `yaml:"asn_path"` // IPtoASN IPv4 TSV.GZ
}

type Storage struct {
	SQLitePath         string    `yaml:"sqlite_path"`
	Retention          Retention `yaml:"retention"`
	BatchFlushInterval Duration  `yaml:"batch_flush_interval"`
	BatchFlushSize     int       `yaml:"batch_flush_size"`
}

type Retention struct {
	Events       Duration `yaml:"events"`
	Incidents    Duration `yaml:"incidents"`
	AWSIPChanges Duration `yaml:"aws_ip_changes"`
}

type RealIP struct {
	TrustHeaders []string `yaml:"trust_headers"`
	TrustProxies []string `yaml:"trust_proxies"`
	// Cloudflare=true 时启动自动追加 CF 官方 IP 段(v4+v6)到 trust_proxies,
	// 并把 CF-Connecting-IP 放到 trust_headers 最前面。
	Cloudflare bool `yaml:"cloudflare"`
}

type Tenant struct {
	Name string `yaml:"name"`
	// Host 字段已废弃,保留 yaml tag 仅为兼容旧配置,加载后忽略,不参与路由。
	Host          string `yaml:"host,omitempty"`
	SubscribePath string `yaml:"subscribe_path"` // 该机场的订阅路径前缀,全局唯一
	Upstream      string `yaml:"upstream"`       // 上游 V2Board 地址 http://host:port
	// UpstreamPath 可选,上游真实订阅路径。空则用 SubscribePath 透传。
	UpstreamPath string `yaml:"upstream_path"`
}

type Paths struct {
	Subscribe []string `yaml:"subscribe"` // 已弃用,见 Config.Paths 注释
}

type DetectorCfg struct {
	ObserveOnly bool                `yaml:"observe_only"`
	Windows     map[string]Duration `yaml:"windows"`
	Rules       []Rule              `yaml:"rules"`
	Whitelist   Whitelist           `yaml:"whitelist"`
}

type Rule struct {
	Name string `yaml:"name"`
	Desc string `yaml:"desc"`
	When When   `yaml:"when"`
	// Severity 已废弃:规则不再分等级,命中即投毒。yaml 里的 severity 字段会被忽略。
}

type When struct {
	TokenFreq        *Cond `yaml:"token_freq"`
	IPFreq           *Cond `yaml:"ip_freq"`
	TokenDistinctIPs *Cond `yaml:"token_distinct_ips"`
	IPDistinctTokens *Cond `yaml:"ip_distinct_tokens"`
	FromCloudIP      bool  `yaml:"from_cloud_ip"` // 命中云厂商 IP 库
	// CloudTokenDistinctUAs: 同一 token 在当前云厂商 IP 上的不同 UA 数。
	// 这是组合条件，只有“UA 达标”和“当前 IP 为云厂商”同时成立才触发。
	CloudTokenDistinctUAs *Cond `yaml:"cloud_token_distinct_uas"`

	// GeoIP 字段(需配 geoip.xdb_path 才生效)
	// 同一字段 in 和 not_in 同时配时,not_in 优先(用于"非 CN 拒"这种反向白名单语义)
	CountryIn      []string `yaml:"country_in"`     // 国家命中列表(ISO2/中文名都行)
	CountryNotIn   []string `yaml:"country_not_in"` // 国家不在列表则命中(反向白名单)
	UsageTypeIn    []string `yaml:"usage_type_in"`  // IDC/CDN/DYN/MOB/COM 命中
	UsageTypeNotIn []string `yaml:"usage_type_not_in"`
	ISPContains    []string `yaml:"isp_contains"` // ISP 子串包含,任一命中即触发
}

type Cond struct {
	Window Duration `yaml:"window"`
	GTE    int      `yaml:"gte"`
}

type Whitelist struct {
	IPs []string `yaml:"ips"`
}

type FakerCfg struct {
	BlackholeIPs []string `yaml:"blackhole_ips"`
	NodeCount    int      `yaml:"node_count"`
}

type AdminCfg struct {
	Username     string   `yaml:"username"`
	PasswordHash string   `yaml:"password_hash"` // bcrypt
	SessionTTL   Duration `yaml:"session_ttl"`
	SessionKey   string   `yaml:"session_key"` // 用于签 cookie,空则自动生成
}

// Duration 支持 "5m" / "24h" / "30d" 这种字符串
type Duration time.Duration

var dayRe = regexp.MustCompile(`^(\d+)d$`)

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	s := strings.TrimSpace(node.Value)
	if s == "" {
		*d = 0
		return nil
	}
	if m := dayRe.FindStringSubmatch(s); m != nil {
		days := 0
		fmt.Sscanf(m[1], "%d", &days)
		*d = Duration(time.Duration(days) * 24 * time.Hour)
		return nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.applyDefaults()
	applyCloudflare(&c)
	return &c, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if c.HMACSaltFile == "" {
		return errors.New("hmac_salt_file is required")
	}
	if c.Storage.SQLitePath == "" {
		return errors.New("storage.sqlite_path is required")
	}
	// 空 tenants 允许:此时反代不接任何路径,只起管理面,从 UI 后台添加租户
	// 后续 tenant 可热加载(/api/tenants POST)
	seen := map[string]bool{}
	seenPath := map[string]bool{} // subscribe_path 全局唯一
	for i := range c.Tenants {
		t := &c.Tenants[i]
		if t.Host != "" {
			// 老配置兼容:host 字段不再参与路由,丢弃。
			t.Host = ""
		}
		if t.Name == "" || t.Upstream == "" {
			return fmt.Errorf("租户 %+v 信息不完整 (name/upstream 必填)", *t)
		}
		if t.SubscribePath == "" {
			return fmt.Errorf("租户 %s 缺少 subscribe_path (例如 /sub/cat)", t.Name)
		}
		if !strings.HasPrefix(t.SubscribePath, "/") {
			return fmt.Errorf("租户 %s 的 subscribe_path 必须以 / 开头: %q", t.Name, t.SubscribePath)
		}
		if seen[t.Name] {
			return fmt.Errorf("租户名重复: %s", t.Name)
		}
		seen[t.Name] = true
		key := strings.TrimRight(t.SubscribePath, "/")
		if seenPath[key] {
			return fmt.Errorf("租户 subscribe_path 重复: %s", t.SubscribePath)
		}
		seenPath[key] = true
	}
	if len(c.Paths.Subscribe) > 0 {
		return errors.New("配置项 paths.subscribe 已弃用,请改为在每个 tenant 下设置 subscribe_path")
	}
	return nil
}

// validAction / ActionsCfg 已删除:命中规则统一投毒,无 action 概念。

func (c *Config) applyDefaults() {
	if c.GeoIP.ASNPath == "" && c.GeoIP.XDBPath != "" {
		c.GeoIP.ASNPath = filepath.Join(filepath.Dir(c.GeoIP.XDBPath), "ip2asn-v4.tsv.gz")
	}
	if c.Storage.BatchFlushInterval == 0 {
		c.Storage.BatchFlushInterval = Duration(time.Second)
	}
	if c.Storage.BatchFlushSize == 0 {
		c.Storage.BatchFlushSize = 100
	}
	if c.Storage.Retention.Events == 0 {
		c.Storage.Retention.Events = Duration(30 * 24 * time.Hour)
	}
	if c.Storage.Retention.Incidents == 0 {
		c.Storage.Retention.Incidents = Duration(90 * 24 * time.Hour)
	}
	if c.Storage.Retention.AWSIPChanges == 0 {
		c.Storage.Retention.AWSIPChanges = Duration(90 * 24 * time.Hour)
	}
	if c.Admin.SessionTTL == 0 {
		c.Admin.SessionTTL = Duration(12 * time.Hour)
	}
	if len(c.Faker.BlackholeIPs) == 0 {
		c.Faker.BlackholeIPs = []string{
			"192.0.2.1", "192.0.2.2", "192.0.2.3",
			"198.51.100.1", "198.51.100.2",
			"203.0.113.1", "203.0.113.2",
		}
	}
	if c.Faker.NodeCount == 0 {
		c.Faker.NodeCount = 8
	}
	if c.AdminListen == "" {
		c.AdminListen = "127.0.0.1:9090"
	}
}

// TenantByPath 根据 URL Path 找 tenant。
// 匹配规则:取请求路径,按 tenant.SubscribePath 做"路径前缀"匹配,
// 命中后 pathMatched=true。Host 头不参与路由。
// 兼容两种命中形态:
//  1. 完全相等(tp == urlPath)
//  2. urlPath 以 tp+"/" 开头(允许子路径,例如 /sub/cat/extra)
//
// 没命中任何 tenant 返回 (nil, false)。
func (c *Config) TenantByPath(urlPath string) (tenant *Tenant, pathMatched bool) {
	urlPath = strings.TrimRight(urlPath, "/")
	if urlPath == "" {
		urlPath = "/"
	}
	// 最长前缀优先:避免 /sub 抢 /sub/cat 的请求
	var best *Tenant
	bestLen := -1
	for i := range c.Tenants {
		t := &c.Tenants[i]
		tp := strings.TrimRight(t.SubscribePath, "/")
		if tp == "" {
			tp = "/"
		}
		if tp == urlPath || strings.HasPrefix(urlPath, tp+"/") {
			if len(tp) > bestLen {
				best = t
				bestLen = len(tp)
			}
		}
	}
	if best != nil {
		return best, true
	}
	return nil, false
}
