package blacklist

import "testing"

// TestIsKnownSubClient 验证订阅客户端 UA 豁免逻辑:
// 已知客户端(含误伤源头 clash-verge)命中白名单,真浏览器 / 空 UA 不命中。
func TestIsKnownSubClient(t *testing.T) {
	cases := []struct {
		ua   string
		want bool
	}{
		// 已知订阅客户端 — 应命中(豁免浏览器拦截)
		{"clash-verge/v2.3.1", true}, // 本次误伤源头
		{"clash-verge/2.0.0", true},
		{"ClashforAndroid/2.5.12", true},
		{"clash.meta", true},
		{"ClashX/1.95.1", true},
		{"FlClash/0.8.0", true},
		{"mihomo/1.18.0", true},
		{"v2rayN/6.42", true},
		{"v2rayNG/1.8.5", true},
		{"sing-box 1.8.0", true},
		{"SFA/1.8.0 (singbox)", true},
		{"Shadowrocket/2.2.27", true},
		{"Quantumult%20X/1.4.0", true},
		{"Surge/5.8.0", true},
		{"Loon/3.1.4", true},
		{"Stash/2.5.0", true},
		{"NekoBox/1.3.0", true},
		{"Hiddify/2.0.5", true},
		{"Streisand/1.6.0", true},
		{"Surfboard/2.24", true},

		// 真浏览器 — 不应命中(保留拦截能力)
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36", false},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", false},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0", false},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0", false},

		// 边界 — 空 / 未知
		{"", false},
		{"curl/8.4.0", false},
		{"python-requests/2.31.0", false},
	}
	for _, c := range cases {
		if got := IsKnownSubClient(c.ua); got != c.want {
			t.Errorf("IsKnownSubClient(%q) = %v, want %v", c.ua, got, c.want)
		}
	}
}

// TestIsBrowser 确认 Accept 判定本身未变(text/html 仍判浏览器)。
func TestIsBrowser(t *testing.T) {
	cases := []struct {
		accept string
		want   bool
	}{
		{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", true},
		{"text/html", true},
		{"*/*", false},
		{"application/json", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsBrowser(c.accept); got != c.want {
			t.Errorf("IsBrowser(%q) = %v, want %v", c.accept, got, c.want)
		}
	}
}
