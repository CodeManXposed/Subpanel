// Package proxy 是网关核心 HTTP handler:
// 解析 → banlist → detector.Observe → detector.Evaluate → judge → 执行。
package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huabanmao168/SubPanel/internal/banlist"
	"github.com/huabanmao168/SubPanel/internal/blacklist"
	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/detector"
	"github.com/huabanmao168/SubPanel/internal/faker"
	"github.com/huabanmao168/SubPanel/internal/parser"
	"github.com/huabanmao168/SubPanel/internal/store"
	"github.com/huabanmao168/SubPanel/internal/token"
)

const (
	maxUpstreamSubscriptionBytes = 16 << 20
	maxDecodedSubscriptionBytes  = 32 << 20
)

type Gateway struct {
	cfg    *config.Config
	hasher *token.Hasher
	st     *store.Store
	bans   *banlist.List
	det    *detector.Detector
	faker  *faker.Renderer
	rng    *rand.Rand
	// passthroughAll 一键透传:网关入口短路直接透传,不进任何规则/黑白名单。
	passthroughAll atomic.Bool
	// autoBan 字段已删除:命中规则统一投毒,无自动封禁逻辑。
	requests atomic.Uint64
	logger   *slog.Logger
	guard    *upstreamGuard
	abuseLog *abuseLogSampler

	// 可选:GeoIP 查询,用于把地区、ASN 与云厂商信息落进请求日志。
	geoLookup func(ip string) NetworkInfo

	// 可选:云厂商 IP 命中查询(给全局黑名单"云厂商一键"用)
	cloudLookup func(ip string) (bool, string)

	// 可选:全局黑名单(海外/云/ISP/浏览器),命中即投毒,优先级高于触发规则
	bl *blacklist.Manager

	// 可选:IP 白名单查询(优先级最高,命中直接放行,跳过黑名单/触发规则)
	ipWhitelisted func(ip string) bool

	// tenants 快照:读多写少,Reload 时原子替换整个 snap 指针,
	// 读路径只取一次指针,避免遍历期间被改。
	snap atomic.Pointer[tenantSnap]
}

// NetworkInfo 是写入请求事件的网络画像。
type NetworkInfo struct {
	Country       string
	UsageType     string
	ISP           string
	ASN           string
	ASNOrg        string
	CloudProvider string
}

// SetGeoLookup 注入 GeoIP 查询(给请求日志用)。
func (g *Gateway) SetGeoLookup(fn func(ip string) NetworkInfo) {
	g.geoLookup = fn
}

// SetCloudLookup 注入云厂商 IP 命中查询(给全局黑名单"云厂商一键"用)。
func (g *Gateway) SetCloudLookup(fn func(ip string) (bool, string)) {
	g.cloudLookup = fn
}

// SetBlacklist 注入全局黑名单管理器。
func (g *Gateway) SetBlacklist(b *blacklist.Manager) {
	g.bl = b
}

// SetPassthroughAll 一键透传开关。热生效。
func (g *Gateway) SetPassthroughAll(b bool) { g.passthroughAll.Store(b) }

// SetIPWhitelist 注入 IP 白名单查询(优先级最高,命中直接放行)。
func (g *Gateway) SetIPWhitelist(fn func(ip string) bool) {
	g.ipWhitelisted = fn
}

// geoFor 包装 geoLookup,nil-safe。
func (g *Gateway) geoFor(ip string) NetworkInfo {
	if g.geoLookup == nil || ip == "" {
		return NetworkInfo{}
	}
	return g.geoLookup(ip)
}

// tenantSnap 是一份不可变的 tenants + 反代视图。
type tenantSnap struct {
	tenants []config.Tenant
	proxies map[string]*httputil.ReverseProxy
}

// AutoBanCfg 已废弃:删等级后无"红色自动封禁",banlist 仅手工维护。
// 仅保留空类型避免外部引用立即编译失败,后续可清除。
type AutoBanCfg struct{}

func NewGateway(
	cfg *config.Config, hasher *token.Hasher, st *store.Store, bans *banlist.List,
	det *detector.Detector, fk *faker.Renderer,
	autoBan AutoBanCfg, logger *slog.Logger,
) (*Gateway, error) {
	_ = autoBan
	g := &Gateway{
		cfg: cfg, hasher: hasher, st: st, bans: bans, det: det,
		faker:    fk,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
		logger:   logger,
		guard:    newUpstreamGuard(cfg.RateLimit),
		abuseLog: newAbuseLogSampler(10*time.Second, 10000),
	}
	if err := g.Reload(cfg.Tenants); err != nil {
		return nil, err
	}
	return g, nil
}

// buildProxy 单个 tenant 构造一个 httputil.ReverseProxy。
func buildProxy(t config.Tenant, logger *slog.Logger) (*httputil.ReverseProxy, error) {
	u, err := url.Parse(t.Upstream)
	if err != nil {
		return nil, fmt.Errorf("租户 %s 上游地址 %s 解析失败: %w", t.Name, t.Upstream, err)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	baseDir := rp.Director
	host := u.Host
	fromPath := strings.TrimRight(t.SubscribePath, "/")
	toPath := strings.TrimRight(t.UpstreamPath, "/")
	rewritePath := toPath != "" && toPath != fromPath
	rp.Director = func(req *http.Request) {
		if rewritePath && strings.HasPrefix(req.URL.Path, fromPath) {
			req.URL.Path = toPath + strings.TrimPrefix(req.URL.Path, fromPath)
		}
		baseDir(req)
		req.Host = host
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Warn("上游请求失败", "err", err, "host", r.Host)
		setNoStoreHeaders(w.Header())
		http.Error(w, "上游服务不可用", http.StatusBadGateway)
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		clearBodyValidators(resp.Header)
		setNoStoreHeaders(resp.Header)
		return nil
	}
	return rp, nil
}

// Reload 用新的 tenants 列表原子重建反代 map,并同步回 g.cfg.Tenants。
// 调用者(webui)校验过 host+path 唯一/字段合法后才进来。
func (g *Gateway) Reload(tenants []config.Tenant) error {
	proxies := make(map[string]*httputil.ReverseProxy, len(tenants))
	for _, t := range tenants {
		rp, err := buildProxy(t, g.logger)
		if err != nil {
			return err
		}
		proxies[t.Name] = rp
	}
	cp := make([]config.Tenant, len(tenants))
	copy(cp, tenants)
	g.snap.Store(&tenantSnap{tenants: cp, proxies: proxies})
	g.cfg.Tenants = cp
	return nil
}

// Tenants 返回当前生效的 tenants 拷贝(给 webui 读)。
func (g *Gateway) Tenants() []config.Tenant {
	s := g.snap.Load()
	if s == nil {
		return nil
	}
	out := make([]config.Tenant, len(s.tenants))
	copy(out, s.tenants)
	return out
}

// LookupTenant 在当前快照里按路径前缀找 tenant。Host 头不参与路由。
// 匹配规则:取最长 SubscribePath 前缀(完全相等或 urlPath 以 tp+"/" 开头)。
func (g *Gateway) LookupTenant(urlPath string) (tenant *config.Tenant, pathMatched bool) {
	s := g.snap.Load()
	if s == nil {
		return nil, false
	}
	urlPath = strings.TrimRight(urlPath, "/")
	if urlPath == "" {
		urlPath = "/"
	}
	var best *config.Tenant
	bestLen := -1
	for i := range s.tenants {
		t := &s.tenants[i]
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

func (g *Gateway) Requests() uint64 { return g.requests.Load() }

// ServeHTTP 是顶层 handler。
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.requests.Add(1)
	start := time.Now()

	pr := parser.Parse(r, g.cfg)
	tenant, pathMatched := g.LookupTenant(r.URL.Path)
	pr.Tenant = tenant
	pr.IsSubPath = pathMatched

	// 0) 一键透传:跳过所有规则/黑白名单,只要 tenant 匹配就透传(紧急回滚用)
	if g.passthroughAll.Load() && pr.Tenant != nil && pr.IsSubPath {
		tokenHash := g.hasher.Hash(pr.Token)
		g.transparentProxyWithLog(w, r, pr, tokenHash, []string{"passthrough_all"}, "pass", start)
		return
	}

	// 1) tenant 不存在 → 404 (路径前缀不匹配,默认静默)
	if pr.Tenant == nil {
		http.Error(w, "404 page not found", http.StatusNotFound)
		g.logEvent(pr, "", "deny", http.StatusNotFound, []string{"path_not_match"}, 0, int64(len("404 page not found\n")), start)
		return
	}

	// 2) 非订阅路径 → 404,不透传(防止 V2board 其他端点经我们泄露)
	if !pr.IsSubPath {
		http.Error(w, "404 page not found", http.StatusNotFound)
		g.logEvent(pr, "", "block_path", http.StatusNotFound, []string{"path_not_match"}, 0, int64(len("404 page not found\n")), start)
		return
	}

	tokenHash := g.hasher.Hash(pr.Token)

	// 2.5) Token 黑名单优先于 IP 白名单：明确拉黑的账户不能借白名单 IP 绕过。
	if banned, action, reason := g.bans.CheckToken(tokenHash); banned {
		tag := "banlist_token"
		if reason != "" {
			tag += ":" + reason
		}
		if action == "deny" {
			g.respondDeny(w, pr, tokenHash, []string{tag}, start)
		} else {
			g.respondFake(w, r, pr, tokenHash, []string{tag}, start)
		}
		return
	}

	// 2.6) IP 白名单命中即跳过 IP banlist/黑名单/触发规则,直接透传。
	// 也不进 detector.Observe(避免影响频率统计)。
	if g.ipWhitelisted != nil && g.ipWhitelisted(pr.ClientIP) {
		g.transparentProxyWithLog(w, r, pr, tokenHash, []string{"ip_whitelist"}, "pass", start)
		return
	}

	// 3) IP banlist 检查：按记录动作投毒或直接 403，均在访问上游前执行。
	if banned, action, reason := g.bans.CheckIPAction(pr.ClientIP); banned {
		tag := "banlist_ip"
		if reason != "" {
			tag += ":" + reason
		}
		if action == "deny" {
			g.respondDeny(w, pr, tokenHash, []string{tag}, start)
		} else {
			g.respondFake(w, r, pr, tokenHash, []string{tag}, start)
		}
		return
	}

	// 3.5) 全局黑名单(海外/云/ISP/浏览器)— 粗粒度规则,优先于触发规则。
	// 命中即投毒,不进 detector.Observe(不污染频率窗口)。
	if g.bl != nil {
		network := g.geoFor(pr.ClientIP)
		// xdb 返回的 country 字段是中文,需要 ISO 码就要单独存。这里把 country
		// 当 ISO 兜底字段两边都传,IsOverseaCountry 会两个都判。
		var iso string
		country := network.Country
		if len(country) == 2 { // 启发式:两字母大写视作 ISO
			iso = country
			country = ""
		}
		var isCloud bool
		if g.cloudLookup != nil {
			isCloud, _ = g.cloudLookup(pr.ClientIP)
		}
		accept := r.Header.Get("Accept")
		if hit, tag := g.bl.Evaluate(iso, country, network.UsageType, network.ISP, isCloud, accept, pr.UA); hit {
			g.respondFake(w, r, pr, tokenHash, []string{tag}, start)
			return
		}
	}

	// 4) detector observe(把当前请求算进窗口)
	g.det.Observe(pr.ClientIP, tokenHash, pr.UA)

	// 5) evaluate
	res := g.det.Evaluate(pr.ClientIP, tokenHash, pr.UA)

	// 6) 记 incident(如有命中)
	if res.Hit {
		// 429 攻击流量按 IP 采样 incident；否则攻击者虽打不到源站，仍可
		// 通过 incidents 表制造百万行写放大。
		if res.Action != "rate_limit" || g.abuseLog.Allow("incident_rate_limit", pr.ClientIP, start) {
			g.st.SubmitIncident(store.Incident{
				TS:        time.Now(),
				Tenant:    pr.Tenant.Name,
				ClientIP:  pr.ClientIP,
				TokenHash: tokenHash,
				RuleTags:  res.Tags,
				Note:      res.Note,
			})
		}
	}
	if res.Hit && g.cfg.Detector.ObserveOnly {
		tags := append(append([]string(nil), res.Tags...), "observe_only")
		g.transparentProxyWithLog(w, r, pr, tokenHash, tags, "pass", start)
		return
	}

	// 7) 执行:按命中规则处置。429/403 都在反代前短路，绝不访问上游。
	if res.Hit {
		switch res.Action {
		case "deny":
			g.respondDeny(w, pr, tokenHash, res.Tags, start)
		case "rate_limit":
			g.respondRateLimit(w, pr, tokenHash, res.Tags, res.RetryAfter, start)
		default:
			g.respondFake(w, r, pr, tokenHash, res.Tags, start)
		}
	} else {
		g.transparentProxyWithLog(w, r, pr, tokenHash, res.Tags, "pass", start)
	}
}

func (g *Gateway) respondRateLimit(w http.ResponseWriter, pr *parser.Request, tokenHash string, tags []string, retryAfter time.Duration, start time.Time) {
	if retryAfter <= 0 {
		retryAfter = time.Minute
	}
	seconds := int(retryAfter.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	// 避免向客户端宣告过长的等待时间；滑窗仍按规则原始窗口自动恢复。
	if seconds > 3600 {
		seconds = 3600
	}
	setNoStoreHeaders(w.Header())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	const body = "Too Many Requests\n"
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = io.WriteString(w, body)
	if g.abuseLog.Allow("rate_limit", pr.ClientIP, start) {
		g.logEvent(pr, tokenHash, "rate_limit", http.StatusTooManyRequests, tags, 0, int64(len(body)), start)
	}
}

func (g *Gateway) respondDeny(w http.ResponseWriter, pr *parser.Request, tokenHash string, tags []string, start time.Time) {
	setNoStoreHeaders(w.Header())
	const body = "Forbidden\n"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, body)
	// 手工 REJECT IP 在 CC 场景下可能每秒数千次；全部拦截，但同 IP 每 10 秒
	// 最多落一条明细，避免攻击者改为打满 SQLite。Token/规则 deny 仍完整记录。
	if !hasTagPrefix(tags, "banlist_ip") || g.abuseLog.Allow("ip_reject", pr.ClientIP, start) {
		g.logEvent(pr, tokenHash, "deny", http.StatusForbidden, tags, 0, int64(len(body)), start)
	}
}

func hasTagPrefix(tags []string, prefix string) bool {
	for _, tag := range tags {
		if tag == prefix || strings.HasPrefix(tag, prefix+":") {
			return true
		}
	}
	return false
}

// 带日志的反代
func (g *Gateway) transparentProxyWithLog(
	w http.ResponseWriter, r *http.Request, pr *parser.Request,
	tokenHash string, tags []string, action string, start time.Time,
) {
	release, ok, reason := g.guard.TryAcquire(pr.ClientIP)
	if !ok {
		g.respondRateLimit(w, pr, tokenHash, append(tags, reason), time.Duration(g.cfg.RateLimit.RetryAfterSeconds)*time.Second, start)
		return
	}
	defer release()
	rp := g.snap.Load().proxies[pr.Tenant.Name]
	if rp == nil {
		http.Error(w, "无可用上游", http.StatusBadGateway)
		return
	}
	// 标记 X-Forwarded-For
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		r.Header.Set("X-Forwarded-For", pr.ClientIP)
	} else {
		r.Header.Set("X-Forwarded-For", xff+", "+pr.ClientIP)
	}

	// 用 ResponseWriter wrapper 抓状态码和长度
	rw := &capturingWriter{ResponseWriter: w, status: 200}
	rp.ServeHTTP(rw, r)

	upstreamMS := time.Since(start).Milliseconds()
	network := g.geoFor(pr.ClientIP)
	g.st.SubmitEvent(store.Event{
		TS:            start,
		Tenant:        pr.Tenant.Name,
		ClientIP:      pr.ClientIP,
		UA:            pr.UA,
		TokenHash:     tokenHash,
		Flag:          pr.Flag,
		Path:          pr.Path,
		Status:        rw.status,
		Action:        action,
		RuleTags:      tags,
		UpstreamMS:    upstreamMS,
		RespSize:      rw.size,
		Country:       network.Country,
		UsageType:     network.UsageType,
		ISP:           network.ISP,
		ASN:           network.ASN,
		ASNOrg:        network.ASNOrg,
		CloudProvider: network.CloudProvider,
	})
}

// respondFake:拉上游真订阅,把节点 host 改写成 RFC5737 黑洞 IP 后返回。
// 上游失败(订阅过期/被封等)直接 502,日志 action=fake_failed。
func (g *Gateway) respondFake(
	w http.ResponseWriter, r *http.Request, pr *parser.Request,
	tokenHash string, tags []string, start time.Time,
) {
	release, ok, reason := g.guard.TryAcquire(pr.ClientIP)
	if !ok {
		g.respondRateLimit(w, pr, tokenHash, append(tags, reason), time.Duration(g.cfg.RateLimit.RetryAfterSeconds)*time.Second, start)
		return
	}
	defer release()
	rp := g.snap.Load().proxies[pr.Tenant.Name]
	if rp == nil {
		http.Error(w, "无可用上游", http.StatusBadGateway)
		g.logEvent(pr, tokenHash, "fake_failed", http.StatusBadGateway, append(tags, "no_proxy"), 0, 0, start)
		return
	}
	// 标记 X-Forwarded-For
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		r.Header.Set("X-Forwarded-For", pr.ClientIP)
	} else {
		r.Header.Set("X-Forwarded-For", xff+", "+pr.ClientIP)
	}
	// 剥掉 Accept-Encoding,强制上游返回明文,否则 Poison 无法对 gzip 字节流做正则替换。
	r.Header.Del("Accept-Encoding")
	for _, name := range []string{
		"If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "If-Range", "Range",
	} {
		r.Header.Del(name)
	}
	bw := &bufferingWriter{
		header:  http.Header{},
		status:  http.StatusOK,
		body:    &bytes.Buffer{},
		maxSize: maxUpstreamSubscriptionBytes,
	}
	rp.ServeHTTP(bw, r)

	// 上游失败(非 2xx)直接透传错误,标 fake_failed
	if bw.status < 200 || bw.status >= 300 {
		for k, vs := range bw.header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(bw.status)
		_, _ = w.Write(bw.body.Bytes())
		g.logEvent(pr, tokenHash, "fake_failed", bw.status, append(tags, "upstream_bad"), time.Since(start).Milliseconds(), int64(bw.body.Len()), start)
		return
	}

	// 投毒:只有确认至少改写了一个节点地址才返回改写结果。
	// 上游过大、解压失败或格式不支持时,退回独立生成的伪订阅,绝不回传原文。
	var poisoned []byte
	enc := strings.ToLower(strings.TrimSpace(bw.header.Get("Content-Encoding")))
	fallbackReason := ""
	if bw.tooLarge {
		fallbackReason = "poison_upstream_too_large"
	} else {
		decoded, decErr := decodeBody(bw.body.Bytes(), enc)
		if decErr != nil {
			fallbackReason = "poison_decode_failed"
		} else {
			result := faker.PoisonWithResult(decoded, bw.header.Get("Content-Type"))
			if !result.Complete() {
				fallbackReason = "poison_no_replacements"
			} else {
				poisoned = result.Body
			}
		}
	}
	if fallbackReason != "" {
		fallback := g.faker.Render(pr.Flag, pr.UA)
		poisoned = fallback.Body
		bw.header.Set("Content-Type", fallback.ContentType)
		bw.header.Del("Content-Encoding")
		enc = ""
		for k, v := range fallback.Headers {
			bw.header.Set(k, v)
		}
		tags = append(append([]string(nil), tags...), fallbackReason)
	} else if enc != "" {
		if reEncoded, encErr := encodeBody(poisoned, enc); encErr == nil {
			poisoned = reEncoded
		} else {
			// 压回失败:剥掉 Content-Encoding 头,以明文返回
			bw.header.Del("Content-Encoding")
		}
	}
	clearBodyValidators(bw.header)
	setNoStoreHeaders(bw.header)

	// 头透传(去掉 Content-Length,后面重写)
	for k, vs := range bw.header {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(poisoned)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(poisoned)

	network := g.geoFor(pr.ClientIP)
	g.st.SubmitEvent(store.Event{
		TS:            start,
		Tenant:        pr.Tenant.Name,
		ClientIP:      pr.ClientIP,
		UA:            pr.UA,
		TokenHash:     tokenHash,
		Flag:          pr.Flag,
		Path:          pr.Path,
		Status:        200,
		Action:        "fake",
		RuleTags:      tags,
		UpstreamMS:    time.Since(start).Milliseconds(),
		RespSize:      int64(len(poisoned)),
		Country:       network.Country,
		UsageType:     network.UsageType,
		ISP:           network.ISP,
		ASN:           network.ASN,
		ASNOrg:        network.ASNOrg,
		CloudProvider: network.CloudProvider,
	})
}

// upstreamGuard 同时限制进入源站的速率与并发。所有检查均为非阻塞：
// 容量不足时立刻失败，绝不让请求在 Sub-Panel 内排队占住 goroutine。
type upstreamGuard struct {
	mu            sync.Mutex
	globalRPS     float64
	globalBurst   float64
	tokens        float64
	lastRefill    time.Time
	perIPMax      int
	perIPActive   map[string]int
	upstreamSlots chan struct{}
}

// abuseLogSampler 只控制高频拦截事件的日志落库，不影响请求拦截。
// 容量封顶，避免分布式随机 IP 反过来撑爆采样器自身。
type abuseLogSampler struct {
	mu       sync.Mutex
	interval time.Duration
	maxKeys  int
	last     map[string]time.Time
	lastGC   time.Time
}

func newAbuseLogSampler(interval time.Duration, maxKeys int) *abuseLogSampler {
	return &abuseLogSampler{interval: interval, maxKeys: maxKeys, last: make(map[string]time.Time), lastGC: time.Now()}
}

func (s *abuseLogSampler) Allow(action, ip string, now time.Time) bool {
	key := action + "\x00" + ip
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.lastGC) >= time.Minute {
		cutoff := now.Add(-2 * s.interval)
		for k, ts := range s.last {
			if ts.Before(cutoff) {
				delete(s.last, k)
			}
		}
		s.lastGC = now
	}
	if prev, ok := s.last[key]; ok {
		if now.Sub(prev) < s.interval {
			return false
		}
		s.last[key] = now
		return true
	}
	if len(s.last) >= s.maxKeys {
		return false
	}
	s.last[key] = now
	return true
}

func newUpstreamGuard(cfg config.RateLimitCfg) *upstreamGuard {
	if cfg.GlobalRPS <= 0 {
		cfg.GlobalRPS = 200
	}
	if cfg.GlobalBurst <= 0 {
		cfg.GlobalBurst = cfg.GlobalRPS * 2
	}
	if cfg.UpstreamMaxConcurrent <= 0 {
		cfg.UpstreamMaxConcurrent = 64
	}
	if cfg.PerIPMaxConcurrent <= 0 {
		cfg.PerIPMaxConcurrent = 3
	}
	return &upstreamGuard{
		globalRPS:     float64(cfg.GlobalRPS),
		globalBurst:   float64(cfg.GlobalBurst),
		tokens:        float64(cfg.GlobalBurst),
		lastRefill:    time.Now(),
		perIPMax:      cfg.PerIPMaxConcurrent,
		perIPActive:   make(map[string]int),
		upstreamSlots: make(chan struct{}, cfg.UpstreamMaxConcurrent),
	}
}

func (g *upstreamGuard) TryAcquire(ip string) (release func(), ok bool, reason string) {
	now := time.Now()
	g.mu.Lock()
	elapsed := now.Sub(g.lastRefill).Seconds()
	if elapsed > 0 {
		g.tokens += elapsed * g.globalRPS
		if g.tokens > g.globalBurst {
			g.tokens = g.globalBurst
		}
		g.lastRefill = now
	}
	if g.tokens < 1 {
		g.mu.Unlock()
		return nil, false, "global_rate_limit"
	}
	if g.perIPActive[ip] >= g.perIPMax {
		g.mu.Unlock()
		return nil, false, "ip_upstream_concurrency"
	}
	g.tokens--
	g.perIPActive[ip]++
	g.mu.Unlock()

	select {
	case g.upstreamSlots <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-g.upstreamSlots
				g.mu.Lock()
				g.perIPActive[ip]--
				if g.perIPActive[ip] <= 0 {
					delete(g.perIPActive, ip)
				}
				g.mu.Unlock()
			})
		}, true, ""
	default:
		g.mu.Lock()
		g.perIPActive[ip]--
		if g.perIPActive[ip] <= 0 {
			delete(g.perIPActive, ip)
		}
		g.mu.Unlock()
		return nil, false, "upstream_concurrency_limit"
	}
}

// bufferingWriter 拦截上游响应,buffer 在内存里方便改写。
type bufferingWriter struct {
	header    http.Header
	status    int
	body      *bytes.Buffer
	maxSize   int
	tooLarge  bool
	wroteHead bool
}

func (b *bufferingWriter) Header() http.Header { return b.header }

func (b *bufferingWriter) WriteHeader(s int) {
	if b.wroteHead {
		return
	}
	b.wroteHead = true
	b.status = s
}

func (b *bufferingWriter) Write(p []byte) (int, error) {
	if !b.wroteHead {
		b.WriteHeader(http.StatusOK)
	}
	if b.tooLarge {
		return len(p), nil
	}
	remaining := b.maxSize - b.body.Len()
	if remaining <= 0 {
		b.tooLarge = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = b.body.Write(p[:remaining])
		b.tooLarge = true
		return len(p), nil
	}
	_, _ = b.body.Write(p)
	return len(p), nil
}

// logEvent 仅落库,不写响应。
func (g *Gateway) logEvent(
	pr *parser.Request,
	tokenHash, action string, status int, tags []string, upstreamMS int64,
	respSize int64, start time.Time,
) {
	tenantName := ""
	if pr != nil && pr.Tenant != nil {
		tenantName = pr.Tenant.Name
	} else if pr != nil {
		tenantName = "_unmatched"
	}
	clientIP, ua, flag, path := "", "", "", ""
	if pr != nil {
		clientIP, ua, flag, path = pr.ClientIP, pr.UA, pr.Flag, pr.Path
	}
	network := g.geoFor(clientIP)
	g.st.SubmitEvent(store.Event{
		TS:            start,
		Tenant:        tenantName,
		ClientIP:      clientIP,
		UA:            ua,
		TokenHash:     tokenHash,
		Flag:          flag,
		Path:          path,
		Status:        status,
		Action:        action,
		RuleTags:      tags,
		UpstreamMS:    upstreamMS,
		RespSize:      respSize,
		Country:       network.Country,
		UsageType:     network.UsageType,
		ISP:           network.ISP,
		ASN:           network.ASN,
		ASNOrg:        network.ASNOrg,
		CloudProvider: network.CloudProvider,
	})
}

// ----- helpers -----

type capturingWriter struct {
	http.ResponseWriter
	status    int
	size      int64
	wroteHead bool
}

func (c *capturingWriter) WriteHeader(code int) {
	c.status = code
	c.wroteHead = true
	c.ResponseWriter.WriteHeader(code)
}

func (c *capturingWriter) Write(p []byte) (int, error) {
	if !c.wroteHead {
		c.status = http.StatusOK
		c.wroteHead = true
	}
	n, err := c.ResponseWriter.Write(p)
	c.size += int64(n)
	return n, err
}

// 静态 healthz
func Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func setNoStoreHeaders(h http.Header) {
	h.Set("Cache-Control", "private, no-store, no-cache, max-age=0")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
}

func clearBodyValidators(h http.Header) {
	for _, name := range []string{"ETag", "Last-Modified", "Content-MD5", "Content-Range", "Accept-Ranges"} {
		h.Del(name)
	}
}

// decodeBody 按 Content-Encoding 解压响应体。空 enc 直接返回原样。
func decodeBody(body []byte, enc string) ([]byte, error) {
	switch enc {
	case "", "identity":
		if len(body) > maxDecodedSubscriptionBytes {
			return nil, fmt.Errorf("decoded body exceeds %d bytes", maxDecodedSubscriptionBytes)
		}
		return body, nil
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return readAllLimited(r, maxDecodedSubscriptionBytes)
	case "deflate":
		r := flate.NewReader(bytes.NewReader(body))
		defer r.Close()
		return readAllLimited(r, maxDecodedSubscriptionBytes)
	default:
		// br/zstd 等暂不支持
		return nil, fmt.Errorf("unsupported encoding: %s", enc)
	}
}

func readAllLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("decoded body exceeds %d bytes", max)
	}
	return b, nil
}

// encodeBody 按 enc 把投毒后的明文压回去。
func encodeBody(body []byte, enc string) ([]byte, error) {
	switch enc {
	case "", "identity":
		return body, nil
	case "gzip":
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(body); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "deflate":
		var buf bytes.Buffer
		zw, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			return nil, err
		}
		if _, err := zw.Write(body); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", enc)
	}
}
