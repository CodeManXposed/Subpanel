package faker

import (
	"encoding/base64"
	"strings"
	"testing"
)

var defaultBlackholes = []string{"192.0.2.1", "192.0.2.2"}

func TestPickKindFromFlag(t *testing.T) {
	cases := map[string]string{
		"clash":    "clash",
		"v2ray":    "vmess",
		"sing-box": "sing-box",
		"ss":       "ss",
		"trojan":   "trojan",
	}
	for flag, want := range cases {
		if got := pickKind(flag, ""); got != want {
			t.Errorf("flag %q: want %q got %q", flag, want, got)
		}
	}
}

func TestPickKindFromUA(t *testing.T) {
	if got := pickKind("", "Clash for Windows/0.20.0"); got != "clash" {
		t.Errorf("clash UA -> %q", got)
	}
	if got := pickKind("", "v2rayNG/1.8.0"); got != "vmess" {
		t.Errorf("v2rayNG UA -> %q", got)
	}
	if got := pickKind("", "Shadowrocket/1.0"); got != "ss" {
		t.Errorf("shadowrocket UA -> %q", got)
	}
}

func TestRenderClash(t *testing.T) {
	r := New(defaultBlackholes, 5)
	out := r.Render("clash", "")
	if !strings.HasPrefix(out.ContentType, "application/x-yaml") {
		t.Errorf("bad content type: %s", out.ContentType)
	}
	body := string(out.Body)
	if !strings.Contains(body, "proxies:") {
		t.Errorf("missing proxies: section")
	}
	if !strings.Contains(body, "proxy-groups:") {
		t.Errorf("missing proxy-groups: section")
	}
	if !strings.Contains(body, "rules:") {
		t.Errorf("missing rules: section")
	}
	// 必须包含至少一个黑洞 IP
	hit := false
	for _, ip := range defaultBlackholes {
		if strings.Contains(body, ip) {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("body has no blackhole IP")
	}
}

func TestRenderVmessBase64Decodable(t *testing.T) {
	r := New(defaultBlackholes, 3)
	out := r.Render("v2ray", "")
	dec, err := base64.StdEncoding.DecodeString(string(out.Body))
	if err != nil {
		t.Fatalf("body must be valid base64: %v", err)
	}
	if !strings.Contains(string(dec), "vmess://") {
		t.Errorf("decoded body missing vmess://")
	}
}

func TestRenderShadowsocksBase64Decodable(t *testing.T) {
	r := New(defaultBlackholes, 3)
	out := r.Render("ss", "")
	dec, err := base64.StdEncoding.DecodeString(string(out.Body))
	if err != nil {
		t.Fatalf("body must be valid base64: %v", err)
	}
	if !strings.Contains(string(dec), "ss://") {
		t.Errorf("decoded body missing ss://")
	}
}

func TestRenderSingBoxJSON(t *testing.T) {
	r := New(defaultBlackholes, 2)
	out := r.Render("sing-box", "")
	if !strings.HasPrefix(out.ContentType, "application/json") {
		t.Errorf("bad content type: %s", out.ContentType)
	}
	if !strings.Contains(string(out.Body), `"outbounds"`) {
		t.Errorf("missing outbounds")
	}
}

func TestSubInfoHeader(t *testing.T) {
	r := New(defaultBlackholes, 2)
	out := r.Render("ss", "")
	if out.Headers["Subscription-Userinfo"] == "" {
		t.Errorf("missing Subscription-Userinfo header")
	}
}
