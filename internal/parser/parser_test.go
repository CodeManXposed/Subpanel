package parser

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/huabanmao168/SubPanel/internal/config"
)

func mkReq(t *testing.T, host string, remote string, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("GET", "http://"+host+"/api/v1/client/subscribe?token=abc&flag=clash", nil)
	r.RemoteAddr = remote
	r.Host = host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestExtractClientIPDirect(t *testing.T) {
	r := mkReq(t, "example.com", "8.8.8.8:12345", nil)
	rip := &config.RealIP{TrustHeaders: []string{"X-Real-IP"}, TrustProxies: []string{"127.0.0.1"}}
	// RemoteAddr 不在 trust_proxies 内,直接返回 RemoteAddr
	if got := ExtractClientIP(r, rip); got != "8.8.8.8" {
		t.Errorf("want 8.8.8.8 got %q", got)
	}
}

func TestExtractClientIPFromHeader(t *testing.T) {
	r := mkReq(t, "example.com", "127.0.0.1:55555", map[string]string{
		"X-Real-IP":       "8.8.8.8",
		"X-Forwarded-For": "192.168.0.1, 8.8.8.8",
	})
	rip := &config.RealIP{
		TrustHeaders: []string{"X-Real-IP", "X-Forwarded-For"},
		TrustProxies: []string{"127.0.0.1"},
	}
	if got := ExtractClientIP(r, rip); got != "8.8.8.8" {
		t.Errorf("want 8.8.8.8 got %q", got)
	}
}

func TestExtractClientIPSkipsPrivateInXFF(t *testing.T) {
	r := mkReq(t, "example.com", "127.0.0.1:55555", map[string]string{
		"X-Forwarded-For": "10.0.0.1, 1.2.3.4",
	})
	rip := &config.RealIP{
		TrustHeaders: []string{"X-Forwarded-For"},
		TrustProxies: []string{"127.0.0.1"},
	}
	if got := ExtractClientIP(r, rip); got != "1.2.3.4" {
		t.Errorf("want 1.2.3.4 got %q", got)
	}
}

func TestExtractClientIPSingleHeaderHonorsPrivate(t *testing.T) {
	// X-Real-IP 是单值,即使是私网也应当被采纳(来自可信代理)
	r := mkReq(t, "example.com", "127.0.0.1:55555", map[string]string{
		"X-Real-IP": "10.0.0.1",
	})
	rip := &config.RealIP{
		TrustHeaders: []string{"X-Real-IP"},
		TrustProxies: []string{"127.0.0.1"},
	}
	if got := ExtractClientIP(r, rip); got != "10.0.0.1" {
		t.Errorf("want 10.0.0.1 got %q", got)
	}
}

func TestParseBasicFields(t *testing.T) {
	cfg := &config.Config{
		RealIP: config.RealIP{TrustProxies: []string{"127.0.0.1"}, TrustHeaders: []string{"X-Real-IP"}},
	}
	r := httptest.NewRequest("GET", "http://sub.example.com/sub/cat?token=abc&flag=clash", nil)
	r.Host = "sub.example.com"
	r.RemoteAddr = "127.0.0.1:55555"
	r.Header.Set("X-Real-IP", "1.2.3.4")
	pr := Parse(r, cfg)
	if pr.ClientIP != "1.2.3.4" {
		t.Errorf("ip: %q", pr.ClientIP)
	}
	if pr.Token != "abc" {
		t.Errorf("token: %q", pr.Token)
	}
	if pr.Flag != "clash" {
		t.Errorf("flag: %q", pr.Flag)
	}
	if pr.Path != "/sub/cat" {
		t.Errorf("path: %q", pr.Path)
	}
}

func TestTenantByPathExact(t *testing.T) {
	cfg := &config.Config{
		Tenants: []config.Tenant{
			{Name: "cat", SubscribePath: "/sub/cat", Upstream: "http://127.0.0.1:7001"},
		},
	}
	tenant, matched := cfg.TenantByPath("/sub/cat")
	if tenant == nil || tenant.Name != "cat" {
		t.Fatalf("tenant: %+v", tenant)
	}
	if !matched {
		t.Error("path should match")
	}
}

func TestTenantByPathWrongPath(t *testing.T) {
	cfg := &config.Config{
		Tenants: []config.Tenant{
			{Name: "cat", SubscribePath: "/sub/cat", Upstream: "http://127.0.0.1:7001"},
		},
	}
	tenant, matched := cfg.TenantByPath("/sub/dog")
	if tenant != nil || matched {
		t.Errorf("路径不匹配应返回 nil/false: %+v matched=%v", tenant, matched)
	}
}

func TestTenantByPathMultiTenant(t *testing.T) {
	cfg := &config.Config{
		Tenants: []config.Tenant{
			{Name: "cat", SubscribePath: "/sub/cat", Upstream: "http://127.0.0.1:7001"},
			{Name: "dog", SubscribePath: "/sub/dog", Upstream: "http://127.0.0.1:7002"},
		},
	}
	t1, m1 := cfg.TenantByPath("/sub/cat")
	if t1 == nil || t1.Name != "cat" || !m1 {
		t.Errorf("cat 应匹配: %+v matched=%v", t1, m1)
	}
	t2, m2 := cfg.TenantByPath("/sub/dog")
	if t2 == nil || t2.Name != "dog" || !m2 {
		t.Errorf("dog 应匹配: %+v matched=%v", t2, m2)
	}
}

func TestTenantByPathSubprefix(t *testing.T) {
	cfg := &config.Config{
		Tenants: []config.Tenant{
			{Name: "x", SubscribePath: "/sub/x", Upstream: "http://127.0.0.1:7001"},
		},
	}
	// 子路径前缀匹配
	tenant, matched := cfg.TenantByPath("/sub/x/extra/token")
	if tenant == nil || tenant.Name != "x" {
		t.Fatal("tenant should match by prefix")
	}
	if !matched {
		t.Error("路径应匹配")
	}
}
