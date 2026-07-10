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

func TestPoisonWithResultCountsAddressReplacements(t *testing.T) {
	plain := "ss://aaaa@1.2.3.4:443#hk\nss://bbbb@5.6.7.8:8443#jp\n"
	body := []byte(base64.StdEncoding.EncodeToString([]byte(plain)))
	result := PoisonWithResult(body, "text/plain")
	if !result.Complete() || result.Replacements != 2 {
		t.Fatalf("result=%+v, want complete with 2 replacements", result)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(result.Body))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(decoded), "1.2.3.4") || strings.Contains(string(decoded), "5.6.7.8") {
		t.Fatalf("real node address remained: %q", decoded)
	}
}

func TestPoisonWithResultDetectsPartialRewrite(t *testing.T) {
	body := []byte("ss://aaaa@1.2.3.4:443#supported\nss://YWVzLTI1Ni1nY206cGFzc3dvcmQ#sip002\n")
	result := PoisonWithResult(body, "text/plain")
	if result.Complete() {
		t.Fatalf("partial rewrite must not be accepted: %+v", result)
	}
	if result.Candidates != 2 || result.Replacements != 1 {
		t.Fatalf("unexpected partial rewrite counts: %+v", result)
	}
}

func TestPoisonWithResultRewritesBracketedIPv6(t *testing.T) {
	body := []byte("vless://uuid@[2001:db8::1]:443#ipv6\n")
	result := PoisonWithResult(body, "text/plain")
	if !result.Complete() || strings.Contains(string(result.Body), "2001:db8") {
		t.Fatalf("IPv6 node was not fully rewritten: %+v body=%q", result, result.Body)
	}
}

func TestPoisonWithResultReportsUnsupportedFormat(t *testing.T) {
	body := []byte("REAL-SUB-FROM-V2BOARD")
	result := PoisonWithResult(body, "text/plain")
	if result.Replacements != 0 {
		t.Fatalf("replacements=%d, want 0", result.Replacements)
	}
	if string(result.Body) != string(body) {
		t.Fatalf("unsupported format should be reported unchanged to caller")
	}
}
