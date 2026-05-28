package cloudip

import (
	"os"
	"testing"

	"github.com/huabanmao168/SubPanel/internal/geoip"
)

func TestMatcher_NotLoaded(t *testing.T) {
	g := geoip.New()
	m := NewMatcherWith(g)
	if hit, _ := m.Match("8.8.8.8"); hit {
		t.Error("xdb 未加载时不应命中")
	}
	snap := m.Snapshot()
	if snap.XdbLoaded {
		t.Error("snapshot 应显示未加载")
	}
}

// TestMatcher_WithXdb 集成测:仅在 XDB_PATH 环境变量指向真实 xdb 时运行。
// CI 上没文件直接 skip,本地有文件再跑。
func TestMatcher_WithXdb(t *testing.T) {
	path := os.Getenv("SUBGW_TEST_XDB")
	if path == "" {
		t.Skip("SUBGW_TEST_XDB 未设置,跳过 xdb 集成测试")
	}
	g := geoip.New()
	if err := g.Load(path); err != nil {
		t.Fatalf("load xdb: %v", err)
	}
	defer g.Close()
	m := NewMatcherWith(g)

	// 已知云段
	cases := map[string]string{
		"47.96.0.1":   "aliyun",
		"42.192.0.1":  "tencent",
		"13.107.42.14": "azure",
		"35.190.247.1": "gcp",
		"8.8.8.8":      "gcp",
		"1.1.1.1":      "cloudflare",
	}
	for ip, wantProv := range cases {
		hit, gotProv := m.Match(ip)
		if !hit {
			t.Errorf("%s: 应命中云,实际 miss", ip)
			continue
		}
		if gotProv != wantProv {
			t.Errorf("%s: provider 实际 %q, 期望 %q", ip, gotProv, wantProv)
		}
	}

	// 真实家宽用户(电信),不应命中
	if hit, p := m.Match("223.246.253.34"); hit {
		t.Errorf("家宽 IP 不应命中云,实际 hit=%v p=%q", hit, p)
	}

	// 无效 IP
	if hit, _ := m.Match("not-an-ip"); hit {
		t.Error("无效 IP 不应命中")
	}
}
