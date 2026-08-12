package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/banlist"
	"github.com/huabanmao168/SubPanel/internal/blacklist"
	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/detector"
	"github.com/huabanmao168/SubPanel/internal/faker"
	"github.com/huabanmao168/SubPanel/internal/store"
	"github.com/huabanmao168/SubPanel/internal/token"
)

func newE2E(t *testing.T, observe bool, extraRules ...config.Rule) (*Gateway, *httptest.Server, *store.Store, *banlist.List, func()) {
	t.Helper()

	// fake upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "REAL-SUB-FROM-V2BOARD ip="+r.Header.Get("X-Forwarded-For"))
	}))

	upURL, _ := url.Parse(upstream.URL)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "e2e.db")
	saltPath := filepath.Join(dir, "salt")

	cfg := &config.Config{
		Listen:       "127.0.0.1:0",
		AdminListen:  "127.0.0.1:0",
		HMACSaltFile: saltPath,
		Storage: config.Storage{
			SQLitePath:         dbPath,
			BatchFlushInterval: config.Duration(50 * time.Millisecond),
			BatchFlushSize:     5,
			Retention: config.Retention{
				Events:    config.Duration(time.Hour),
				Incidents: config.Duration(time.Hour),
			},
		},
		RealIP: config.RealIP{
			TrustProxies: []string{"127.0.0.1"},
			TrustHeaders: []string{"X-Real-IP"},
		},
		Paths: config.Paths{},
		Tenants: []config.Tenant{
			{Name: "default", Host: "sub.example.com", SubscribePath: "/sub/cat", Upstream: upURL.String()},
		},
		Detector: config.DetectorCfg{
			ObserveOnly: observe,
			Rules: append([]config.Rule{
				{
					Name: "tf_red", When: config.When{TokenFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 5}},
				},
				{
					Name: "ip_red", When: config.When{IPFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 100}},
				},
			}, extraRules...),
		},
		Faker: config.FakerCfg{NodeCount: 3, BlackholeIPs: []string{"192.0.2.1"}},
	}

	salt, err := token.LoadOrCreateSalt(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	hasher := token.NewHasher(salt)
	st, err := store.Open(dbPath, 50*time.Millisecond, 5)
	if err != nil {
		t.Fatal(err)
	}
	bans := banlist.New(st)
	_ = bans.LoadFromStore(context.Background())
	det, err := detector.New(&cfg.Detector)
	if err != nil {
		t.Fatal(err)
	}
	fk := faker.New(cfg.Faker.BlackholeIPs, cfg.Faker.NodeCount)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gw, err := NewGateway(cfg, hasher, st, bans, det, fk, AutoBanCfg{}, logger)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		upstream.Close()
		_ = st.Close()
		_ = os.RemoveAll(dir)
	}
	return gw, upstream, st, bans, cleanup
}

func mkSubReq(host, ua, tok, flag, realIP string) *http.Request {
	q := url.Values{}
	if tok != "" {
		q.Set("token", tok)
	}
	if flag != "" {
		q.Set("flag", flag)
	}
	r := httptest.NewRequest("GET", "http://"+host+"/sub/cat?"+q.Encode(), nil)
	r.Host = host
	r.RemoteAddr = "127.0.0.1:55555"
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	if realIP != "" {
		r.Header.Set("X-Real-IP", realIP)
	}
	return r
}

func TestE2EPassNormalRequest(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "user1", "clash", "8.8.8.8"))

	if w.Code != 200 {
		t.Errorf("status: %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Errorf("did not reach upstream: %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "8.8.8.8") {
		t.Errorf("X-Forwarded-For not propagated: %q", w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("subscription response must disable caching, got %q", got)
	}
}

func TestE2EUnknownTenantReturns404(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false)
	defer cleanup()

	// Host 头不再参与路由,unknown 应该改测"路径不匹配 → 404"
	w := httptest.NewRecorder()
	r := mkSubReq("sub.example.com", "ClashforWindows/0.20", "u", "clash", "")
	r.URL.Path = "/sub/nope" // 没配置的路径
	gw.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("expected 404 for unknown path, got %d", w.Code)
	}
}

func TestE2EUnsupportedUpstreamFallsBackToGeneratedFake(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false, config.Rule{
		Name: "ip_once",
		When: config.When{IPFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 1}},
	})
	defer cleanup()

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "curl/8.0", "user1", "ss", "9.9.9.9"))
	if w.Code != 200 {
		t.Errorf("fake should return 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Fatalf("unsupported upstream format leaked real subscription: %q", w.Body.String())
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(w.Body.String()))
	if err != nil || !strings.Contains(string(decoded), "192.0.2.1") {
		t.Fatalf("expected generated blackhole subscription, err=%v body=%q", err, w.Body.String())
	}
}

func TestE2ERuleDenyReturnsForbidden(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false, config.Rule{
		Name:   "deny_once",
		Action: "deny",
		When:   config.When{IPFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 1}},
	})
	defer cleanup()

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "Clash/1.0", "blocked", "clash", "9.9.9.9"))
	if w.Code != http.StatusForbidden || strings.TrimSpace(w.Body.String()) != "Forbidden" {
		t.Fatalf("expected HTTP 403 deny, got %d %q", w.Code, w.Body.String())
	}
}

func TestE2ERateLimitNeverReachesUpstream(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false, config.Rule{
		Name:   "rate_once",
		Action: "rate_limit",
		When:   config.When{IPFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 1}},
	})
	defer cleanup()

	var upstreamHits atomic.Int64
	protectedUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "must-not-be-returned")
	}))
	defer protectedUpstream.Close()
	tenants := gw.Tenants()
	tenants[0].Upstream = protectedUpstream.URL
	if err := gw.Reload(tenants); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "Clash/1.0", "random-token", "clash", "9.9.9.9"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected HTTP 429, got %d %q", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Retry-After"); got != "60" {
		t.Fatalf("Retry-After=%q, want 60", got)
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Fatalf("rate-limited request reached PHP upstream %d times", got)
	}
}

func TestE2EIPWhitelistStillRateLimited(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, false,
		config.Rule{Name: "ip_freq_burst", Action: "rate_limit", When: config.When{IPFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 2}}},
		config.Rule{Name: "ip_multi_token", Action: "rate_limit", When: config.When{IPDistinctTokens: &config.Cond{Window: config.Duration(10 * time.Minute), GTE: 1}}},
	)
	defer cleanup()
	gw.SetIPWhitelist(func(ip string) bool { return ip == "9.9.9.9" })

	first := httptest.NewRecorder()
	gw.ServeHTTP(first, mkSubReq("sub.example.com", "Clash/1.0", "token-a", "clash", "9.9.9.9"))
	if first.Code != http.StatusOK {
		t.Fatalf("IP whitelist should allow first request, got %d %q", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	gw.ServeHTTP(second, mkSubReq("sub.example.com", "Clash/1.0", "token-b", "clash", "9.9.9.9"))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("whitelisted IP must still receive 429 for frequency, got %d %q", second.Code, second.Body.String())
	}
}

func TestE2EIPWhitelistBypassesGlobalIPClassification(t *testing.T) {
	gw, _, st, _, cleanup := newE2E(t, false)
	defer cleanup()
	bl := blacklist.New(st)
	if err := bl.Update(blacklist.Snapshot{
		OverseaEnabled: true,
		CloudEnabled:   true,
		CNIDCEnabled:   true,
		ISPKeywords:    []string{"cloudflare"},
	}); err != nil {
		t.Fatal(err)
	}
	gw.SetBlacklist(bl)
	gw.SetCloudLookup(func(ip string) (bool, string) { return true, "cloudflare" })
	gw.SetIPWhitelist(func(ip string) bool { return ip == "9.9.9.9" })

	allowed := httptest.NewRecorder()
	gw.ServeHTTP(allowed, mkSubReq("sub.example.com", "Clash/1.0", "token-a", "clash", "9.9.9.9"))
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Fatalf("whitelisted cloud/oversea IP should reach upstream, got %d %q", allowed.Code, allowed.Body.String())
	}

	blocked := httptest.NewRecorder()
	gw.ServeHTTP(blocked, mkSubReq("sub.example.com", "Clash/1.0", "token-b", "clash", "8.8.8.8"))
	if blocked.Code != http.StatusOK || strings.Contains(blocked.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Fatalf("non-whitelisted IP should still be poisoned, got %d %q", blocked.Code, blocked.Body.String())
	}
}

func TestE2EIPWhitelistDoesNotOverrideIPBlacklist(t *testing.T) {
	gw, _, _, bans, cleanup := newE2E(t, false)
	defer cleanup()
	gw.SetIPWhitelist(func(ip string) bool { return ip == "7.7.7.7" })
	if err := bans.AddIPWithAction("7.7.7.7", "deny", "manual block", time.Hour, nil, "test"); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "Clash/1.0", "token", "clash", "7.7.7.7"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("IP blacklist must override IP whitelist, got %d %q", w.Code, w.Body.String())
	}
}

func TestUpstreamGuardRejectsWithoutQueueing(t *testing.T) {
	g := newUpstreamGuard(config.RateLimitCfg{
		GlobalRPS: 100, GlobalBurst: 100, UpstreamMaxConcurrent: 1, PerIPMaxConcurrent: 1,
	})
	release, ok, _ := g.TryAcquire("1.2.3.4")
	if !ok {
		t.Fatal("first request should acquire upstream slot")
	}
	if _, ok, reason := g.TryAcquire("1.2.3.4"); ok || reason != "ip_upstream_concurrency" {
		t.Fatalf("second request=(ok=%v reason=%q), want immediate per-IP rejection", ok, reason)
	}
	if _, ok, reason := g.TryAcquire("5.6.7.8"); ok || reason != "upstream_concurrency_limit" {
		t.Fatalf("other IP=(ok=%v reason=%q), want immediate global concurrency rejection", ok, reason)
	}
	release()
	if release2, ok, reason := g.TryAcquire("5.6.7.8"); !ok {
		t.Fatalf("slot should be reusable after release: %q", reason)
	} else {
		release2()
	}
}

func TestAbuseLogSamplerBoundsRepeatedAndDistributedKeys(t *testing.T) {
	s := newAbuseLogSampler(10*time.Second, 2)
	now := time.Now()
	if !s.Allow("ip_reject", "1.1.1.1", now) {
		t.Fatal("first event should be logged")
	}
	if s.Allow("ip_reject", "1.1.1.1", now.Add(time.Second)) {
		t.Fatal("repeated event inside sample window should be suppressed")
	}
	if !s.Allow("ip_reject", "2.2.2.2", now) {
		t.Fatal("second key should fit")
	}
	if s.Allow("ip_reject", "3.3.3.3", now) {
		t.Fatal("sampler must reject new keys after capacity is reached")
	}
	if !s.Allow("ip_reject", "1.1.1.1", now.Add(11*time.Second)) {
		t.Fatal("existing key should be logged after sample window")
	}
}

func TestE2EHighTokenFreqRedDenyAndBan(t *testing.T) {
	gw, _, _, bans, cleanup := newE2E(t, false)
	defer cleanup()

	// 5 个请求后触发命中(token_freq >=5)→ 投毒
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClientApp/1.0", "samesubtoken", "clash", "10.0.0.1"))
	}
	time.Sleep(50 * time.Millisecond)
	// 第 6 次:命中后仍是投毒(200 假节点)
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClientApp/1.0", "samesubtoken", "clash", "10.0.0.1"))
	if w.Code != 200 {
		t.Errorf("expected 200 (poisoned), got %d", w.Code)
	}
	// banlist 不再被 SevRed 自动加入,bans 应当为空
	if banned, _ := bans.CheckIP("10.0.0.1"); banned {
		t.Errorf("banlist 不再自动封禁,但 10.0.0.1 被加入了")
	}
}

func TestE2EObserveOnly(t *testing.T) {
	gw, _, _, _, cleanup := newE2E(t, true)
	defer cleanup()

	// 先累计 4 次,第 5 次达到 token_freq >= 5。
	for i := 0; i < 4; i++ {
		w := httptest.NewRecorder()
		gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClientApp/1.0", "tok", "ss", "8.8.8.8"))
	}
	// observe_only 下即使命中规则,也必须继续透传真实上游。
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClientApp/1.0", "tok", "ss", "8.8.8.8"))
	if w.Code != 200 {
		t.Errorf("status: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Errorf("observe_only should pass through, got %q", w.Body.String())
	}
}

func TestBufferingWriterCapsMemory(t *testing.T) {
	bw := &bufferingWriter{
		header:  http.Header{},
		status:  http.StatusOK,
		body:    &bytes.Buffer{},
		maxSize: 8,
	}
	n, err := bw.Write([]byte("0123456789"))
	if err != nil || n != 10 {
		t.Fatalf("Write() = (%d, %v), want (10, nil)", n, err)
	}
	if !bw.tooLarge || bw.body.Len() != 8 {
		t.Fatalf("buffer cap failed: tooLarge=%v len=%d", bw.tooLarge, bw.body.Len())
	}
}

func TestE2EManualBan(t *testing.T) {
	gw, _, _, bans, cleanup := newE2E(t, false)
	defer cleanup()

	_ = bans.AddIP("7.7.7.7", "manual", time.Hour, nil, "test")

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "t", "clash", "7.7.7.7"))
	// banlist 命中也走投毒(200)
	if w.Code != 200 {
		t.Errorf("expected 200 (poisoned) for banned IP, got %d", w.Code)
	}
}

func TestE2EIPRejectNeverReachesUpstream(t *testing.T) {
	gw, _, _, bans, cleanup := newE2E(t, false)
	defer cleanup()

	var upstreamHits atomic.Int64
	protectedUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer protectedUpstream.Close()
	tenants := gw.Tenants()
	tenants[0].Upstream = protectedUpstream.URL
	if err := gw.Reload(tenants); err != nil {
		t.Fatal(err)
	}
	if err := bans.AddIPWithAction("7.7.7.8", "deny", "scanner", time.Hour, nil, "test"); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "t", "clash", "7.7.7.8"))
	if w.Code != http.StatusForbidden || strings.TrimSpace(w.Body.String()) != "Forbidden" {
		t.Fatalf("IP reject response=%d %q", w.Code, w.Body.String())
	}
	if got := upstreamHits.Load(); got != 0 {
		t.Fatalf("rejected IP reached upstream %d times", got)
	}
}

func TestE2ETokenBanFakeAndDeny(t *testing.T) {
	gw, _, _, bans, cleanup := newE2E(t, false)
	defer cleanup()

	if err := bans.AddToken("fake-token", "fake", "leaked", time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "fake-token", "clash", "8.8.8.8"))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "REAL-SUB-FROM-V2BOARD") {
		t.Fatalf("fake token response=%d %q", w.Code, w.Body.String())
	}

	if err := bans.AddToken("deny-token", "deny", "confirmed", 0, "test"); err != nil {
		t.Fatal(err)
	}
	gw.SetIPWhitelist(func(string) bool { return true })
	w = httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "deny-token", "clash", "8.8.8.8"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("deny token should override IP whitelist, got %d %q", w.Code, w.Body.String())
	}
}

func TestE2EEventsPersisted(t *testing.T) {
	gw, _, st, _, cleanup := newE2E(t, false)
	defer cleanup()

	w := httptest.NewRecorder()
	gw.ServeHTTP(w, mkSubReq("sub.example.com", "ClashforWindows/0.20", "tttt", "clash", "8.8.8.8"))

	// 等 batch flush
	time.Sleep(200 * time.Millisecond)
	evs, err := st.QueryEvents(context.Background(), store.EventFilter{Tenant: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		t.Fatal("event not persisted")
	}
	e := evs[0]
	if e.ClientIP != "8.8.8.8" || e.Action != "pass" || e.Flag != "clash" {
		t.Errorf("unexpected event: %+v", e)
	}
	// token 直接存原文(面板要反查用户)
	if e.TokenHash != "tttt" {
		t.Errorf("expected raw token 'tttt', got %q", e.TokenHash)
	}
}

// TestE2EGzipUpstreamPoisoned 回归保护:上游用 gzip 返回 base64 节点列表时,
// 投毒必须解压 → 改 host → 重新压回。
// 触发原因:Cloudflare 等 CDN 会强制塞 Content-Encoding: gzip,
// 早期 Poison 直接对压缩字节流跑正则匹配不到 ss://,导致真节点透传。
func TestE2EGzipUpstreamPoisoned(t *testing.T) {
	// 自己起一个 gzip 上游 + 新 gateway,不复用 newE2E(它的上游是明文)
	const subBody = "ss://aaaa@1.2.3.4:11300#hk\r\nss://bbbb@5.6.7.8:11301#jp\r\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(subBody))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(encoded))
		_ = zw.Close()
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(200)
		_, _ = w.Write(buf.Bytes())
	}))
	defer upstream.Close()
	upURL, _ := url.Parse(upstream.URL)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "gz.db")
	saltPath := filepath.Join(dir, "salt")
	cfg := &config.Config{
		Listen: "127.0.0.1:0", AdminListen: "127.0.0.1:0", HMACSaltFile: saltPath,
		Storage: config.Storage{
			SQLitePath: dbPath, BatchFlushInterval: config.Duration(50 * time.Millisecond), BatchFlushSize: 5,
			Retention: config.Retention{Events: config.Duration(time.Hour), Incidents: config.Duration(time.Hour)},
		},
		RealIP:  config.RealIP{TrustProxies: []string{"127.0.0.1"}, TrustHeaders: []string{"X-Real-IP"}},
		Tenants: []config.Tenant{{Name: "default", Host: "sub.example.com", SubscribePath: "/sub/cat", Upstream: upURL.String()}},
		Detector: config.DetectorCfg{
			Rules: []config.Rule{{Name: "ip_red", When: config.When{IPFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 1}}}},
		},
		Faker: config.FakerCfg{NodeCount: 3, BlackholeIPs: []string{"192.0.2.1"}},
	}
	salt, err := token.LoadOrCreateSalt(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dbPath, 50*time.Millisecond, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bans := banlist.New(st)
	_ = bans.LoadFromStore(context.Background())
	det, _ := detector.New(&cfg.Detector)
	fk := faker.New(cfg.Faker.BlackholeIPs, cfg.Faker.NodeCount)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gw, err := NewGateway(cfg, token.NewHasher(salt), st, bans, det, fk, AutoBanCfg{}, logger)
	if err != nil {
		t.Fatal(err)
	}

	// 用 curl UA 强制命中 bad_ua → 走 respondFake
	w := httptest.NewRecorder()
	req := mkSubReq("sub.example.com", "curl/8.0", "tok", "", "9.9.9.9")
	req.Header.Set("Accept-Encoding", "gzip")
	gw.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	// 响应:可能 gzip 也可能明文(看实现选哪种回写),都得 OK
	respBody := w.Body.Bytes()
	if w.Header().Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(respBody))
		if err != nil {
			t.Fatalf("response should be valid gzip: %v", err)
		}
		respBody, err = io.ReadAll(zr)
		_ = zr.Close()
		if err != nil {
			t.Fatalf("gunzip: %v", err)
		}
	}

	// body 应当还是 base64,解码后含 RFC5737 黑洞段
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(respBody)))
	if err != nil {
		t.Fatalf("response body not valid base64 after decompress: %v body=%q", err, string(respBody))
	}
	plain := string(decoded)
	if strings.Contains(plain, "@1.2.3.4") || strings.Contains(plain, "@5.6.7.8") {
		t.Errorf("真节点 IP 未被投毒,body=%q", plain)
	}
	if !strings.Contains(plain, "192.0.2.") && !strings.Contains(plain, "198.51.100.") && !strings.Contains(plain, "203.0.113.") {
		t.Errorf("response 缺少黑洞 IP,body=%q", plain)
	}
}
