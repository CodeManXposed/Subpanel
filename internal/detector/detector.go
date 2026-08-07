// Package detector 跑规则引擎,输出命中 tag 集合 + 最高 severity。
package detector

import (
	"strings"
	"sync/atomic"
	"time"

	"github.com/huabanmao168/SubPanel/internal/blacklist"
	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/slidingwin"
)

// Severity / sevRank 删除:规则不再分等级。处置由每条规则的 Action 决定。

type Detector struct {
	cfg         *config.DetectorCfg
	rulesSnap   atomic.Pointer[[]config.Rule] // 热更:nil → 用 cfg.Rules
	maxWindow   atomic.Int64
	tokenFreq   *slidingwin.Counter
	ipFreq      *slidingwin.Counter
	tokenIPSet  *slidingwin.DistinctSet
	ipTokenSet  *slidingwin.DistinctSet
	tokenIPUAs  *slidingwin.TimedDistinctSet
	ipWhitelist map[string]struct{}

	// 可选:云 IP 查询函数。nil 时 from_cloud_ip 规则跳过。
	cloudLookup func(ip string) (bool, string)
	// 可选:GeoIP 查询函数。nil 时 country/usage_type/isp 规则跳过。
	geoLookup func(ip string) *GeoInfo
	// 可选:外部 IP 白名单提供者(热更新,来自 DB)。
	dynamicIPWhitelist func(ip string) bool
	// 可选:动态 UA 白名单。仅豁免 uncommon_ua 条件，不跳过其他风控规则。
	dynamicUAWhitelist func(ua string) bool
}

// GeoInfo 给 detector 用的精简版 IP 地理信息。
// 避免 detector 直接依赖 geoip 包(循环 import 风险),由上层注入。
type GeoInfo struct {
	Country   string // 国家(中国/美国/...)
	ISOCode   string // CN/US
	ISP       string // 电信/阿里/Cloudflare/...
	UsageType string // IDC/CDN/DYN/MOB/COM
}

// SetCloudLookup 注入云 IP 查询函数(可热更换)。
func (d *Detector) SetCloudLookup(fn func(ip string) (bool, string)) {
	d.cloudLookup = fn
}

// SetGeoLookup 注入 GeoIP 查询函数(可热更换)。
func (d *Detector) SetGeoLookup(fn func(ip string) *GeoInfo) {
	d.geoLookup = fn
}

// SetDynamicIPWhitelist 注入 DB 来源的 IP 白名单查询函数。
func (d *Detector) SetDynamicIPWhitelist(fn func(string) bool) {
	d.dynamicIPWhitelist = fn
}

// SetDynamicUAWhitelist 注入 DB 来源的 UA 白名单查询函数。
func (d *Detector) SetDynamicUAWhitelist(fn func(string) bool) {
	d.dynamicUAWhitelist = fn
}

func New(cfg *config.DetectorCfg) (*Detector, error) {
	maxWindow := rulesMaxWindow(cfg.Rules)
	bucket := time.Minute
	if maxWindow < 5*time.Minute {
		bucket = 30 * time.Second
	}

	d := &Detector{
		cfg:         cfg,
		tokenFreq:   slidingwin.NewCounter(bucket, maxWindow),
		ipFreq:      slidingwin.NewCounter(bucket, maxWindow),
		tokenIPSet:  slidingwin.NewDistinctSet(bucket, maxWindow),
		ipTokenSet:  slidingwin.NewDistinctSet(bucket, maxWindow),
		tokenIPUAs:  slidingwin.NewTimedDistinctSet(maxWindow),
		ipWhitelist: map[string]struct{}{},
	}
	d.maxWindow.Store(int64(maxWindow))

	for _, ip := range cfg.Whitelist.IPs {
		d.ipWhitelist[ip] = struct{}{}
	}

	return d, nil
}

func (d *Detector) MaxWindow() time.Duration { return time.Duration(d.maxWindow.Load()) }

// ResetAll 清空所有滑窗状态(tokenFreq/ipFreq/tokenIPSet/ipTokenSet)。
// 配合"清空日志"使用,语义统一:用户视角一切归零。
func (d *Detector) ResetAll() {
	d.tokenFreq.Reset()
	d.ipFreq.Reset()
	d.tokenIPSet.Reset()
	d.ipTokenSet.Reset()
	d.tokenIPUAs.Reset()
}

// ResetToken 清掉指定 token 在 detector 里所有滑窗里的累计状态(tokenFreq / tokenIPSet)
// 以及"被该 token 触达过的所有 IP"的 ipFreq + ipTokenSet。
// 运维型按钮:把误判的 token 从风控里"拉出来",下次重新计数。
func (d *Detector) ResetToken(tokenHash string) {
	if tokenHash == "" {
		return
	}
	// 拿到这个 token 在窗口期内出现过的 IP 列表,顺手把对应 IP 维度也清掉。
	// (否则 ipTokenSet[ip] 还残留该 token,后续 ip_token_count 仍可能触发)
	ips := d.tokenIPSet.Items(tokenHash)
	d.tokenFreq.Delete(tokenHash)
	d.tokenIPSet.Delete(tokenHash)
	for _, ip := range ips {
		d.ipFreq.Delete(ip)
		d.ipTokenSet.Delete(ip)
		d.tokenIPUAs.Delete(tokenIPUAKey(tokenHash, ip))
	}
}

func (d *Detector) GCTargets() []interface{ GC() } {
	return []interface{ GC() }{d.tokenFreq, d.ipFreq, d.tokenIPSet, d.ipTokenSet, d.tokenIPUAs}
}

// Observe 把请求记入计数器(请求落库前调用)。
// tokenHash 可能为空。ua 参数保留兼容签名,内部不再使用。
func (d *Detector) Observe(ip, tokenHash, ua string) {
	if tokenHash != "" {
		d.tokenFreq.Inc(tokenHash)
		d.tokenIPSet.Add(tokenHash, ip)
		d.ipTokenSet.Add(ip, tokenHash)
		if strings.TrimSpace(ua) != "" {
			d.tokenIPUAs.Add(tokenIPUAKey(tokenHash, ip), ua)
		}
	}
	d.ipFreq.Inc(ip)
}

// Result 检测结果。多条规则同时命中时 deny 优先于 fake。
type Result struct {
	Hit    bool
	Action string   // fake|deny
	Tags   []string // 命中的规则名
	Note   string
}

// Whitelisted IP 白名单 — 完全跳过所有规则。
// ua 参数保留兼容签名,内部不再使用。
func (d *Detector) Whitelisted(ip, ua string) bool {
	if _, ok := d.ipWhitelist[ip]; ok {
		return true
	}
	if d.dynamicIPWhitelist != nil && d.dynamicIPWhitelist(ip) {
		return true
	}
	_ = ua
	return false
}

// Evaluate 运行所有规则。注意 Evaluate 必须在 Observe 之后调用,
// 这样当前请求自身也算进窗口。ua 参数保留兼容签名,内部不再使用。
func (d *Detector) Evaluate(ip, tokenHash, ua string) Result {
	if d.Whitelisted(ip, ua) {
		return Result{}
	}
	var (
		tags   []string
		notes  []string
		action = "fake"
	)
	rules := d.cfg.Rules
	if snap := d.rulesSnap.Load(); snap != nil {
		rules = *snap
	}
	for _, r := range rules {
		hit, note := d.matchRule(r, ip, tokenHash, ua)
		if !hit {
			continue
		}
		tags = append(tags, r.Name)
		if strings.EqualFold(strings.TrimSpace(r.Action), "deny") {
			action = "deny"
		}
		if note != "" {
			notes = append(notes, note)
		}
	}
	return Result{Hit: len(tags) > 0, Action: action, Tags: tags, Note: strings.Join(notes, "; ")}
}

func (d *Detector) matchRule(r config.Rule, ip, tokenHash, ua string) (bool, string) {
	w := r.When
	if w.UncommonUA && !blacklist.IsKnownSubClient(ua) {
		if d.dynamicUAWhitelist == nil || !d.dynamicUAWhitelist(ua) {
			shown := strings.TrimSpace(ua)
			if shown == "" {
				shown = "(empty)"
			}
			return true, "uncommon_ua:" + shown
		}
	}
	if c := w.TokenFreq; c != nil && tokenHash != "" {
		n := d.tokenFreq.Sum(tokenHash, c.Window.Std())
		if n >= c.GTE {
			return true, formatN("token_freq", n, c)
		}
	}
	if c := w.IPFreq; c != nil {
		n := d.ipFreq.Sum(ip, c.Window.Std())
		if n >= c.GTE {
			return true, formatN("ip_freq", n, c)
		}
	}
	if c := w.TokenDistinctIPs; c != nil && tokenHash != "" {
		n := d.tokenIPSet.Count(tokenHash, c.Window.Std())
		if n >= c.GTE {
			return true, formatN("token_distinct_ips", n, c)
		}
	}
	if c := w.IPDistinctTokens; c != nil {
		n := d.ipTokenSet.Count(ip, c.Window.Std())
		if n >= c.GTE {
			return true, formatN("ip_distinct_tokens", n, c)
		}
	}
	if c := w.CloudTokenDistinctUAs; c != nil && tokenHash != "" && d.cloudLookup != nil {
		n := d.tokenIPUAs.Count(tokenIPUAKey(tokenHash, ip), c.Window.Std())
		if n >= c.GTE {
			if hit, prov := d.cloudLookup(ip); hit {
				return true, formatN("cloud_token_distinct_uas", n, c) + " provider=" + prov
			}
		}
	}
	if w.FromCloudIP && d.cloudLookup != nil {
		if hit, prov := d.cloudLookup(ip); hit {
			return true, "cloud_ip:" + prov
		}
	}
	// GeoIP 字段评估(country/usage_type/isp)
	if d.geoLookup != nil && needsGeo(&w) {
		if info := d.geoLookup(ip); info != nil {
			if hit, note := evalGeoConds(&w, info); hit {
				return true, note
			}
		}
	}
	return false, ""
}

func formatN(name string, n int, c *config.Cond) string {
	return name + "=" + itoa(n) + ">=" + itoa(c.GTE) + " window=" + c.Window.Std().String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// SetRules 用 DB 来源的规则覆盖 yaml 静态规则,热生效。
// nil 表示回退到 cfg.Rules;空 slice 表示禁用所有规则。
func (d *Detector) SetRules(rs []config.Rule) {
	if rs == nil {
		d.rulesSnap.Store(nil)
		rs = d.cfg.Rules
	} else {
		cp := make([]config.Rule, len(rs))
		copy(cp, rs)
		d.rulesSnap.Store(&cp)
		rs = cp
	}
	maxWindow := rulesMaxWindow(rs)
	d.maxWindow.Store(int64(maxWindow))
	d.tokenFreq.SetMaxWindow(maxWindow)
	d.ipFreq.SetMaxWindow(maxWindow)
	d.tokenIPSet.SetMaxWindow(maxWindow)
	d.ipTokenSet.SetMaxWindow(maxWindow)
	d.tokenIPUAs.SetMaxWindow(maxWindow)
}

func rulesMaxWindow(rules []config.Rule) time.Duration {
	maxWindow := time.Hour
	for _, r := range rules {
		w := r.When
		for _, c := range []*config.Cond{w.TokenFreq, w.IPFreq, w.TokenDistinctIPs, w.IPDistinctTokens, w.CloudTokenDistinctUAs} {
			if c != nil && c.Window.Std() > maxWindow {
				maxWindow = c.Window.Std()
			}
		}
	}
	return maxWindow
}

func tokenIPUAKey(tokenHash, ip string) string {
	return tokenHash + "\x00" + ip
}
