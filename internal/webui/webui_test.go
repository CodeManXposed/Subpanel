package webui

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/huabanmao168/SubPanel/internal/banlist"
	"github.com/huabanmao168/SubPanel/internal/cloudip"
	"github.com/huabanmao168/SubPanel/internal/config"
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
	srv := NewServer(cfg, st, bans, hasher, cm, nil, rulesMgr, nil, nil, nil, logger)
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
	body = strings.NewReader(`{"kind":"ip","target":"1.2.3.4","reason":"manual","ttl":"1h"}`)
	req = httptest.NewRequest("POST", "/api/bans/add", body)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("ban add: %d body=%s", w.Code, w.Body.String())
	}
	if banned, _ := bans.CheckIP("1.2.3.4"); !banned {
		t.Error("ip should be banned in memory")
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

// TestHashTokenAPI 已删除:/api/hash-token 路由随 token 黑名单一起废弃。

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
