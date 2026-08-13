package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/huabanmao168/SubPanel/internal/banlist"
	"github.com/huabanmao168/SubPanel/internal/blacklist"
	"github.com/huabanmao168/SubPanel/internal/cloudip"
	"github.com/huabanmao168/SubPanel/internal/config"
	"github.com/huabanmao168/SubPanel/internal/geoip"
	"github.com/huabanmao168/SubPanel/internal/rules"
	"github.com/huabanmao168/SubPanel/internal/store"
	"github.com/huabanmao168/SubPanel/internal/token"
)

func setup(t *testing.T) (*Server, *store.Store, *banlist.List) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "ui.db"), 50*time.Millisecond, 5)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	pwdHash, _ := bcrypt.GenerateFromPassword([]byte("p@ss"), bcrypt.MinCost)
	cfg := &config.Config{
		Admin: config.AdminCfg{
			Username:     "admin",
			PasswordHash: string(pwdHash),
			SessionTTL:   config.Duration(time.Hour),
		},
		RealIP: config.RealIP{
			TrustHeaders: []string{"X-Real-IP", "X-Forwarded-For"},
			TrustProxies: []string{"127.0.0.1"},
		},
		Tenants: []config.Tenant{{Name: "default", Host: "x", SubscribePath: "/sub/x", Upstream: "http://x"}},
	}

	salt, _ := token.LoadOrCreateSalt(filepath.Join(dir, "salt"))
	hasher := token.NewHasher(salt)
	bans := banlist.New(st)
	_ = bans.LoadFromStore(context.Background())

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cm := cloudip.NewMatcher()
	rulesMgr := rules.NewManager(st)
	_ = rulesMgr.Reload()
	srv := NewServer(cfg, st, bans, hasher, cm, nil, rulesMgr, nil, nil, nil, "0.1.87-test", logger)
	return srv, st, bans
}

func login(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	body := strings.NewReader(`{"username":"admin","password":"p@ss"}`)
	req := httptest.NewRequest("POST", "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("login failed: %d", w.Code)
	}
	return w.Result().Cookies()[0]
}

func TestLoginRequired(t *testing.T) {
	srv, _, _ := setup(t)
	h := srv.Handler()

	req := httptest.NewRequest("GET", "/api/summary", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("want 401, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRenderedPagesUseRuntimeVersion(t *testing.T) {
	srv, _, _ := setup(t)
	h := srv.Handler()

	loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	loginRec := httptest.NewRecorder()
	h.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK || !strings.Contains(loginRec.Body.String(), "v0.1.87-test") || strings.Contains(loginRec.Body.String(), "{{VERSION}}") {
		t.Fatalf("login runtime version not rendered: code=%d", loginRec.Code)
	}
	if got := loginRec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("login cache control=%q", got)
	}

	cookie := login(t, h)
	indexReq := httptest.NewRequest(http.MethodGet, "/", nil)
	indexReq.AddCookie(cookie)
	indexRec := httptest.NewRecorder()
	h.ServeHTTP(indexRec, indexReq)
	if indexRec.Code != http.StatusOK || !strings.Contains(indexRec.Body.String(), "Sub-Panel v0.1.87-test") {
		t.Fatalf("index runtime version not rendered: code=%d", indexRec.Code)
	}
	if !strings.Contains(indexRec.Body.String(), "/static/app.css?v=0.1.87-test") ||
		!strings.Contains(indexRec.Body.String(), "/static/app.js?v=0.1.87-test") {
		t.Fatalf("index static assets are not versioned")
	}
}

func TestPanelAnalysisToggleAndEmptyQuery(t *testing.T) {
	srv, _, _ := setup(t)
	h := srv.Handler()
	cookie := login(t, h)

	post := httptest.NewRequest(http.MethodPost, "/api/panel-analysis/settings", strings.NewReader(`{"enabled":true}`))
	post.Header.Set("Content-Type", "application/json")
	post.AddCookie(cookie)
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, post)
	if postRec.Code != http.StatusOK {
		t.Fatalf("enable analysis: %d %s", postRec.Code, postRec.Body.String())
	}

	now := time.Now()
	url := fmt.Sprintf("/api/panel-analysis?start_ts=%d&end_ts=%d", now.Add(-time.Hour).UnixMilli(), now.UnixMilli())
	get := httptest.NewRequest(http.MethodGet, url, nil)
	get.AddCookie(cookie)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusOK {
		t.Fatalf("query analysis: %d %s", getRec.Code, getRec.Body.String())
	}
	var payload struct {
		Enabled bool                     `json:"enabled"`
		Rows    []store.PanelAnalysisRow `json:"rows"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &payload); err != nil || !payload.Enabled || len(payload.Rows) != 0 {
		t.Fatalf("unexpected analysis response: %+v err=%v", payload, err)
	}
}

func TestLoginBadCreds(t *testing.T) {
	srv, _, _ := setup(t)
	h := srv.Handler()

	body := strings.NewReader(`{"username":"admin","password":"wrong"}`)
	req := httptest.NewRequest("POST", "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestLoginAndAccessAPI(t *testing.T) {
	srv, st, _ := setup(t)
	h := srv.Handler()

	// 准备一条 event
	st.SubmitEvent(store.Event{
		TS: time.Now(), Tenant: "default", ClientIP: "1.1.1.1",
		Action: "pass", Status: 200,
	})
	time.Sleep(150 * time.Millisecond)
	if err := srv.rules.AddIPWhitelist("1.1.1.0/24", "summary test"); err != nil {
		t.Fatal(err)
	}

	// 登录
	body := strings.NewReader(`{"username":"admin","password":"p@ss"}`)
	req := httptest.NewRequest("POST", "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("login failed: %d body=%s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie set")
	}

	// 用 cookie 访问 summary
	req = httptest.NewRequest("GET", "/api/summary", nil)
	req.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("summary: %d", w.Code)
	}
	var s store.Stats
	if err := json.NewDecoder(w.Body).Decode(&s); err != nil {
		t.Fatal(err)
	}
	if s.TotalEvents < 1 {
		t.Errorf("expected at least 1 event, got %d", s.TotalEvents)
	}
	if len(s.TopIPs) != 1 || !s.TopIPs[0].Whitelisted {
		t.Fatalf("summary top IP whitelist annotation missing: %+v", s.TopIPs)
	}
}

func TestIPPolicyStatusShowsWhitelistManualBanAndGlobalIPRules(t *testing.T) {
	srv, st, _ := setup(t)
	if err := srv.rules.AddIPWhitelist("203.0.113.0/24", "trusted node"); err != nil {
		t.Fatal(err)
	}
	if err := srv.bans.AddIP("203.0.113.8", "manual test", 0, nil, "test"); err != nil {
		t.Fatal(err)
	}
	srv.bl = blacklist.New(st)
	if err := srv.bl.Update(blacklist.Snapshot{CloudEnabled: true, CNIDCEnabled: true}); err != nil {
		t.Fatal(err)
	}
	status := srv.ipPolicyStatus("203.0.113.8", &geoip.Info{
		Country: "中国", ISOCode: "CN", UsageType: "IDC", CloudProvider: "aws",
	})
	if !status.Whitelisted || !status.IPBlacklisted || status.IPBlacklistReason != "manual test" {
		t.Fatalf("missing list status: %+v", status)
	}
	joined := strings.Join(status.GlobalHits, "|")
	if !strings.Contains(joined, "云厂商 IP") || !strings.Contains(joined, "国内 IDC") {
		t.Fatalf("missing global blacklist hits: %+v", status)
	}
}

func TestAWSIPChangeAPIRecordsSnapshot(t *testing.T) {
	srv, st, _ := setup(t)
	h := srv.Handler()
	cookie := login(t, h)
	actionAt := time.Now().Truncate(time.Second)
	st.SubmitEvent(store.Event{
		TS: actionAt.Add(-10 * time.Minute), Tenant: "default", ClientIP: "8.8.8.8",
		UA: "clash", TokenHash: "snapshot-token", Action: "pass", CloudProvider: "aws", ASN: "AS16509",
	})
	time.Sleep(150 * time.Millisecond)

	body := strings.NewReader(fmt.Sprintf(`{"occurred_ts":%d,"old_ip":"1.2.3.4","new_ip":"5.6.7.8","lookback_minutes":20}`,
		actionAt.UnixMilli()))
	req := httptest.NewRequest(http.MethodPost, "/api/aws-ip-changes/add", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("add change: %d %s", w.Code, w.Body.String())
	}
	var change store.AWSIPChange
	if err := json.NewDecoder(w.Body).Decode(&change); err != nil {
		t.Fatal(err)
	}
	if change.SiteCount != 1 || change.SubscriberCount != 1 || change.PullCount != 1 {
		t.Fatalf("unexpected change response: %+v", change)
	}
	st.SubmitEvent(store.Event{
		TS: actionAt.Add(time.Second), Tenant: "default", ClientIP: "9.9.9.9",
		UA: "clash-after", TokenHash: "snapshot-token", Action: "pass", ASN: "AS2",
	})
	time.Sleep(150 * time.Millisecond)

	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/aws-ip-changes/detail?id=%d&sample_size=20", change.ID), nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"sample_size":20`) ||
		!strings.Contains(w.Body.String(), `"token":"snapshot-token"`) ||
		!strings.Contains(w.Body.String(), `"before_pull_count":1`) ||
		!strings.Contains(w.Body.String(), `"after_pull_count":1`) ||
		!strings.Contains(w.Body.String(), `"history_hits":1`) ||
		!strings.Contains(w.Body.String(), `"history_total":1`) {
		t.Fatalf("detail: %d %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/aws-ip-changes/detail?id=%d&sample_size=501", change.ID), nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid sample size: %d %s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/aws-ip-changes/detail?id=%d&history_size=51", change.ID), nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid history size: %d %s", w.Code, w.Body.String())
	}

	if err := srv.rules.AddIPWhitelist("8.8.8.0/24", "测试 CIDR 白名单"); err != nil {
		t.Fatal(err)
	}
	rows := []store.AWSSuspectSummary{{IPs: []store.AWSSuspectIP{{IP: "8.8.8.8"}, {IP: "1.1.1.1"}}}}
	srv.annotateAWSSuspectWhitelist(rows)
	if !rows[0].IPs[0].Whitelisted || rows[0].IPs[1].Whitelisted {
		t.Fatalf("unexpected suspect whitelist annotation: %+v", rows[0].IPs)
	}
}

func TestDNSWatcherAPIStartsForAllSites(t *testing.T) {
	srv, _, _ := setup(t)
	h := srv.Handler()
	cookie := login(t, h)

	body := strings.NewReader(`{"dns_name":"localhost","tenant":"","lookback_minutes":15}`)
	req := httptest.NewRequest(http.MethodPost, "/api/dns-watchers/add", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("add DNS watcher: %d %s", w.Code, w.Body.String())
	}
	var watcher store.DNSWatcher
	if err := json.NewDecoder(w.Body).Decode(&watcher); err != nil {
		t.Fatal(err)
	}
	if watcher.DNSName != "localhost" || watcher.Tenant != "" || !watcher.Enabled || watcher.LastIPs == "" {
		t.Fatalf("unexpected watcher: %+v", watcher)
	}
	body = strings.NewReader(fmt.Sprintf(`{"id":%d,"note":"测试入口"}`, watcher.ID))
	req = httptest.NewRequest(http.MethodPost, "/api/dns-watchers/note", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("save DNS watcher note: %d %s", w.Code, w.Body.String())
	}
	body = strings.NewReader(fmt.Sprintf(`{"id":%d,"minutes":3}`, watcher.ID))
	req = httptest.NewRequest(http.MethodPost, "/api/dns-watchers/lookback", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"minutes":3`) {
		t.Fatalf("save DNS watcher lookback: %d %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/dns-watchers", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"dns_name":"localhost"`) || !strings.Contains(w.Body.String(), `"note":"测试入口"`) || !strings.Contains(w.Body.String(), `"lookback_minutes":3`) {
		t.Fatalf("list DNS watchers: %d %s", w.Code, w.Body.String())
	}
}

func TestAWSFailureHookRequiresSecretAndRecordsAnchor(t *testing.T) {
	srv, st, _ := setup(t)
	h := srv.Handler()
	now := time.Now().UnixMilli()
	_, err := st.AddDNSWatcher(context.Background(), store.DNSWatcher{
		DNSName: "entry.example.com", Tenant: "", LookbackMinutes: 20, Enabled: true,
		LastIPs: "1.2.3.4", LastCheckedTS: now, LastChangedTS: now - 60_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetMeta("report_secret", "hook-secret"); err != nil {
		t.Fatal(err)
	}
	body := `{"dns_name":"entry.example.com","tenant":"","ip":"1.2.3.4"}`
	req := httptest.NewRequest(http.MethodPost, "/hook/aws-failure", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing secret: %d %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/hook/aws-failure", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Report-Key", "hook-secret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "failure anchor recorded") {
		t.Fatalf("record failure: %d %s", w.Code, w.Body.String())
	}
	watchers, err := st.ListDNSWatchers(context.Background(), false)
	if err != nil || len(watchers) != 1 || watchers[0].PendingFailureTS == 0 || watchers[0].PendingFailureIP != "1.2.3.4" {
		t.Fatalf("anchor not persisted: watchers=%+v err=%v", watchers, err)
	}
}

func TestAWSManualFailureAPIRecordsExactTime(t *testing.T) {
	srv, st, _ := setup(t)
	h := srv.Handler()
	cookie := login(t, h)
	now := time.Now().Truncate(time.Second)
	watcher, err := st.AddDNSWatcher(context.Background(), store.DNSWatcher{
		DNSName: "manual.example.com", Tenant: "sled", LookbackMinutes: 20, Enabled: true,
		LastIPs: "1.2.3.4", LastCheckedTS: now.UnixMilli(), LastChangedTS: now.Add(-time.Hour).UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	failedTS := now.Add(-3 * time.Hour).UnixMilli()
	body := strings.NewReader(fmt.Sprintf(`{"id":%d,"ip":"1.2.3.4","failed_ts":%d}`, watcher.ID, failedTS))
	req := httptest.NewRequest(http.MethodPost, "/api/dns-watchers/manual-failure", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"failure_ts":`+strconv.FormatInt(failedTS, 10)) {
		t.Fatalf("manual failure: %d %s", w.Code, w.Body.String())
	}
	got, err := st.GetDNSWatcher(context.Background(), watcher.ID)
	if err != nil || got.PendingFailureTS != failedTS || got.PendingFailureIP != "1.2.3.4" {
		t.Fatalf("manual failure not persisted: watcher=%+v err=%v", got, err)
	}

	body = strings.NewReader(fmt.Sprintf(`{"id":%d,"ip":"9.9.9.9","failed_ts":%d}`, watcher.ID, failedTS))
	req = httptest.NewRequest(http.MethodPost, "/api/dns-watchers/manual-failure", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("wrong current IP should conflict: %d %s", w.Code, w.Body.String())
	}
}

func TestCloudUAProbeRuleConversion(t *testing.T) {
	a := &detectRuleAPI{CloudTokenUAsWindowSec: 60, CloudTokenUAsGTE: 4}
	w, err := apiToWhen(a)
	if err != nil {
		t.Fatal(err)
	}
	if w.CloudTokenDistinctUAs == nil || w.CloudTokenDistinctUAs.Window.Std() != time.Minute || w.CloudTokenDistinctUAs.GTE != 4 {
		t.Fatalf("unexpected condition: %+v", w.CloudTokenDistinctUAs)
	}
	row, err := rowToAPI(store.DetectRuleRow{Name: "cloud_ua_probe", Action: "deny", WhenJSON: `{"CloudTokenDistinctUAs":{"Window":60000000000,"GTE":4}}`})
	if err != nil {
		t.Fatal(err)
	}
	if row.CloudTokenUAsWindowSec != 60 || row.CloudTokenUAsGTE != 4 || row.Action != "deny" {
		t.Fatalf("unexpected API rule: %+v", row)
	}
}

func TestRateLimitRuleConversion(t *testing.T) {
	row, err := rowToAPI(store.DetectRuleRow{
		Name: "ip_freq_burst", Action: "rate_limit", WhenJSON: `{"IPFreq":{"Window":60000000000,"GTE":20}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.Action != "rate_limit" || row.IPFreqWindowSec != 60 || row.IPFreqGTE != 20 {
		t.Fatalf("unexpected rate-limit API rule: %+v", row)
	}
}

func TestUncommonUARuleConversion(t *testing.T) {
	a := &detectRuleAPI{UncommonUA: true, Action: "fake"}
	w, err := apiToWhen(a)
	if err != nil {
		t.Fatal(err)
	}
	if !w.UncommonUA {
		t.Fatal("uncommon UA condition lost")
	}
	row, err := rowToAPI(store.DetectRuleRow{Name: "uncommon_ua", Action: "fake", WhenJSON: `{"UncommonUA":true}`})
	if err != nil || !row.UncommonUA {
		t.Fatalf("unexpected API rule: %+v err=%v", row, err)
	}
}

func TestFocusTokenAPI(t *testing.T) {
	srv, _, _ := setup(t)
	h := srv.Handler()
	cookie := login(t, h)
	body := strings.NewReader(`{"token":"focus-token","tenant":"default","note":""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/focus/add", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("focus add: %d %s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/focus?tenant=default", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token":"focus-token"`) {
		t.Fatalf("focus list: %d %s", w.Code, w.Body.String())
	}
}

func TestTokenAssociationAPI(t *testing.T) {
	srv, _, _ := setup(t)
	h := srv.Handler()
	cookie := login(t, h)
	body := strings.NewReader(`{"token":"new-token","related_token":"old-token","tenant":"default"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/token-associations/add", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("associate token: %d %s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/suspect-detail?token=new-token&tenant=default&window=1h", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token":"old-token"`) {
		t.Fatalf("association detail: %d %s", w.Code, w.Body.String())
	}
}

func TestBatchIPBanSeparatorsAndValidation(t *testing.T) {
	srv, _, bans := setup(t)
	h := srv.Handler()
	cookie := login(t, h)
	post := func(payload string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/bans/add", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	w := post(`{"kind":"ip","target":"1.1.1.1, 2.2.2.2 / 3.3.3.3\n4.4.4.4，1.1.1.1","reason":"batch","ttl":"24h"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"added":4`) || !strings.Contains(w.Body.String(), `"total":4`) {
		t.Fatalf("batch add: %d %s", w.Code, w.Body.String())
	}
	if len(bans.Snapshot()) != 4 {
		t.Fatalf("want 4 unique bans, got %+v", bans.Snapshot())
	}
	w = post(`{"kind":"ip","target":"1.1.1.1","reason":"updated"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"updated":1`) {
		t.Fatalf("duplicate update: %d %s", w.Code, w.Body.String())
	}
	w = post(`{"kind":"ip","target":"5.5.5.5 / not-an-ip"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "无效 IP") || len(bans.Snapshot()) != 4 {
		t.Fatalf("invalid batch must be atomic: code=%d body=%s bans=%+v", w.Code, w.Body.String(), bans.Snapshot())
	}
}

func TestCDNSettingsDiagnostic(t *testing.T) {
	srv, _, _ := setup(t)
	h := srv.Handler()
	cookie := login(t, h)

	req := httptest.NewRequest("GET", "/api/settings/cdn", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Real-IP", "8.8.8.8")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("want 200 got %d body=%s", w.Code, w.Body.String())
	}
	var out struct {
		Diagnostic struct {
			ClientIP     string `json:"client_ip"`
			Source       string `json:"source"`
			TrustedProxy bool   `json:"trusted_proxy"`
		} `json:"diagnostic"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Diagnostic.ClientIP != "8.8.8.8" || out.Diagnostic.Source != "X-Real-IP" || !out.Diagnostic.TrustedProxy {
		t.Fatalf("unexpected diagnostic: %+v", out.Diagnostic)
	}
}

func TestBanAddRemoveViaAPI(t *testing.T) {
	srv, _, bans := setup(t)
	h := srv.Handler()

	// 登录拿 cookie
	body := strings.NewReader(`{"username":"admin","password":"p@ss"}`)
	req := httptest.NewRequest("POST", "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	cookie := w.Result().Cookies()[0]

	// 加封禁
	body = strings.NewReader(`{"kind":"ip","target":"1.2.3.4","action":"deny","reason":"manual","ttl":"1h"}`)
	req = httptest.NewRequest("POST", "/api/bans/add", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("ban add: %d body=%s", w.Code, w.Body.String())
	}
	if banned, action, _ := bans.CheckIPAction("1.2.3.4"); !banned || action != "deny" {
		t.Errorf("ip should be rejected in memory, banned=%v action=%q", banned, action)
	}

	// 删
	body = strings.NewReader(`{"kind":"ip","target":"1.2.3.4"}`)
	req = httptest.NewRequest("POST", "/api/bans/remove", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("ban remove: %d", w.Code)
	}
	if banned, _ := bans.CheckIP("1.2.3.4"); banned {
		t.Error("ip should be unbanned")
	}
}

func TestCIDRBanAndLegacySlashBatchViaAPI(t *testing.T) {
	srv, _, bans := setup(t)
	h := srv.Handler()
	cookie := login(t, h)

	post := func(payload string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/bans/add", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	w := post(`{"kind":"ip","target":"203.0.113.77/24","action":"deny","reason":"range","ttl":"1h"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"added":1`) {
		t.Fatalf("CIDR add: %d %s", w.Code, w.Body.String())
	}
	if hit, action, reason := bans.CheckIPAction("203.0.113.9"); !hit || action != "deny" || reason != "range" {
		t.Fatalf("CIDR API check=(%v,%q,%q)", hit, action, reason)
	}

	w = post(`{"kind":"ip","target":"198.51.100.1/198.51.100.2","action":"fake"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"added":2`) {
		t.Fatalf("legacy slash batch: %d %s", w.Code, w.Body.String())
	}
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if hit, action, _ := bans.CheckIPAction(ip); !hit || action != "fake" {
			t.Fatalf("legacy IP %s check=(%v,%q)", ip, hit, action)
		}
	}

	w = post(`{"kind":"ip","target":"203.0.113.0/33","action":"deny"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "无效 IP/CIDR") {
		t.Fatalf("invalid CIDR: %d %s", w.Code, w.Body.String())
	}
}

func TestTokenBanActionsViaAPI(t *testing.T) {
	srv, _, bans := setup(t)
	h := srv.Handler()
	cookie := login(t, h)

	post := func(path, payload string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	w := post("/api/bans/add", `{"kind":"token","target":"tok-a, tok-b\ntok-a","action":"deny","reason":"leaked","ttl":"24h"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"added":2`) || !strings.Contains(w.Body.String(), `"action":"deny"`) {
		t.Fatalf("token add: %d %s", w.Code, w.Body.String())
	}
	if hit, action, reason := bans.CheckToken("tok-a"); !hit || action != "deny" || reason != "leaked" {
		t.Fatalf("token check=(%v,%q,%q)", hit, action, reason)
	}

	w = post("/api/bans/add", `{"kind":"token","target":"tok-a","action":"fake","reason":"changed"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"updated":1`) {
		t.Fatalf("token update: %d %s", w.Code, w.Body.String())
	}
	if hit, action, _ := bans.CheckToken("tok-a"); !hit || action != "fake" {
		t.Fatalf("updated token check=(%v,%q)", hit, action)
	}

	w = post("/api/bans/remove", `{"kind":"token","target":"tok-a"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("token remove: %d %s", w.Code, w.Body.String())
	}
	if hit, _, _ := bans.CheckToken("tok-a"); hit {
		t.Error("token should be removed")
	}

	w = post("/api/bans/add", `{"kind":"token","target":"tok-c","action":"drop"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid action: %d %s", w.Code, w.Body.String())
	}
}

func TestTokenBlockWorkflowViaAPI(t *testing.T) {
	srv, st, bans := setup(t)
	h := srv.Handler()
	cookie := login(t, h)

	post := func(path, payload string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	if err := st.AddFocusToken(context.Background(), "suspect-token", "sled", "watching"); err != nil {
		t.Fatalf("focus token before block: %v", err)
	}

	w := post("/api/token-blocks/add", `{"token":"suspect-token","tenant":"sled","action":"deny","reason":"confirmed leak","ttl":"24h"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"action":"deny"`) {
		t.Fatalf("token block add: %d %s", w.Code, w.Body.String())
	}
	if hit, action, reason := bans.CheckToken("suspect-token"); !hit || action != "deny" || reason != "confirmed leak" {
		t.Fatalf("runtime token block=(%v,%q,%q)", hit, action, reason)
	}
	resolved, err := st.ListResolvedTokens(context.Background(), "sled")
	if err != nil || len(resolved) != 1 || resolved[0].Token != "suspect-token" {
		t.Fatalf("resolved after block: rows=%+v err=%v", resolved, err)
	}
	focused, err := st.ListFocusTokens(context.Background(), "sled")
	if err != nil || len(focused) != 0 {
		t.Fatalf("focus remained after block: rows=%+v err=%v", focused, err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/token-blocks?tenant=sled", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token":"suspect-token"`) || !strings.Contains(w.Body.String(), `"tenant":"sled"`) {
		t.Fatalf("token block list: %d %s", w.Code, w.Body.String())
	}

	w = post("/api/token-blocks/remove", `{"token":"suspect-token"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("token block remove: %d %s", w.Code, w.Body.String())
	}
	if hit, _, _ := bans.CheckToken("suspect-token"); hit {
		t.Error("runtime token block remained after remove")
	}
	resolved, err = st.ListResolvedTokens(context.Background(), "sled")
	if err != nil || len(resolved) != 0 {
		t.Fatalf("resolved remained after unblock: rows=%+v err=%v", resolved, err)
	}
}

// Token 目前以原文反查用户，管理面直接录入，无需单独的 hash-token API。

func TestLogoutInvalidatesSession(t *testing.T) {
	srv, _, _ := setup(t)
	h := srv.Handler()

	// 登录
	body := strings.NewReader(`{"username":"admin","password":"p@ss"}`)
	req := httptest.NewRequest("POST", "/api/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	cookie := w.Result().Cookies()[0]

	// logout
	req = httptest.NewRequest("POST", "/api/logout", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// 再用旧 cookie
	req = httptest.NewRequest("GET", "/api/summary", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("expected 401 after logout, got %d", w.Code)
	}
}

func TestLoginPageServed(t *testing.T) {
	srv, _, _ := setup(t)
	h := srv.Handler()
	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("login page: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "<html") {
		t.Error("login page does not look like HTML")
	}
}

func TestUnauthorizedHTMLRedirect(t *testing.T) {
	srv, _, _ := setup(t)
	h := srv.Handler()
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Errorf("expected redirect to /login, got code=%d loc=%q", w.Code, w.Header().Get("Location"))
	}
}

// 防止 unused import warning
var _ = http.StatusOK
