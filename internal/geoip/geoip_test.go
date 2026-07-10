package geoip

import (
	"os"
	"sync"
	"testing"
)

func TestMatchCloudProvider(t *testing.T) {
	cases := map[string]string{
		"阿里":         "aliyun",
		"阿里云":        "aliyun",
		"Alibaba":    "aliyun",
		"腾讯":         "tencent",
		"Tencent":    "tencent",
		"微软":         "azure",
		"Microsoft":  "azure",
		"Azure":      "azure",
		"谷歌":         "gcp",
		"Google":     "gcp",
		"Cloudflare": "cloudflare",
		"华为":         "huawei",
		"字节跳动":       "bytedance",
		"火山引擎":       "bytedance",
		"电信":         "",
		"移动":         "",
		"联通":         "",
		"":           "",
	}
	for isp, want := range cases {
		if got := matchCloudProvider(isp); got != want {
			t.Errorf("matchCloudProvider(%q) = %q, want %q", isp, got, want)
		}
	}
}

func TestParseRecord(t *testing.T) {
	// 阿里云示例
	raw := "亚洲|中国|浙江|杭州||阿里|120.153576|30.287459|330100|0571|310000|Asia/Shanghai|CNY|AS37963|CDN|17|CHXX0044|CN"
	info := parseRecord(raw)
	if info.Country != "中国" {
		t.Errorf("country: %q", info.Country)
	}
	if info.ISP != "阿里" {
		t.Errorf("isp: %q", info.ISP)
	}
	if info.UsageType != "CDN" {
		t.Errorf("usage_type: %q", info.UsageType)
	}
	if info.ASN != "AS37963" {
		t.Errorf("asn: %q", info.ASN)
	}
	if info.CloudProvider != "aliyun" {
		t.Errorf("cloud_provider: %q", info.CloudProvider)
	}
	if info.ISOCode != "CN" {
		t.Errorf("iso: %q", info.ISOCode)
	}
}

func TestParseRecord_OfficialFiveFields(t *testing.T) {
	info := parseRecord("中国|0|浙江省|杭州市|阿里云")
	if info.Country != "中国" || info.Province != "浙江省" || info.City != "杭州市" {
		t.Fatalf("unexpected location: %+v", info)
	}
	if info.ISOCode != "CN" || info.CloudProvider != "aliyun" {
		t.Fatalf("unexpected derived fields: %+v", info)
	}
}

func TestParseRecord_CloudProviderOutsideISP(t *testing.T) {
	raw := "中国|河北省|张家口市|阿里|CN|||||||||||||CN"
	info := parseRecord(raw)
	if info.CloudProvider != "aliyun" {
		t.Errorf("cloud_provider: %q", info.CloudProvider)
	}
}

func TestParseRecord_FamilyBroadband(t *testing.T) {
	// 电信家宽用户
	raw := "亚洲|中国|安徽|合肥|肥东|电信|117.47128|31.88525|340122|0551|230000|Asia/Shanghai|CNY|AS4134|MOB|22|CHXX0448|CN"
	info := parseRecord(raw)
	if info.CloudProvider != "" {
		t.Errorf("家宽 IP 不应判云,实际 %q", info.CloudProvider)
	}
	if info.UsageType != "MOB" {
		t.Errorf("usage_type: %q", info.UsageType)
	}
	if info.ISP != "电信" {
		t.Errorf("isp: %q", info.ISP)
	}
}

func TestLookup_NotLoaded(t *testing.T) {
	s := New()
	if info := s.Lookup("8.8.8.8"); info != nil {
		t.Errorf("xdb 未加载应返回 nil,实际 %+v", info)
	}
	if s.Loaded() {
		t.Error("Loaded 应为 false")
	}
}

func TestLookup_WithXdb(t *testing.T) {
	path := os.Getenv("SUBGW_TEST_XDB")
	if path == "" {
		t.Skip("SUBGW_TEST_XDB 未设置,跳过 xdb 集成测试")
	}
	s := New()
	if err := s.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if asnPath := os.Getenv("SUBGW_TEST_ASN"); asnPath != "" {
		if err := s.LoadASN(asnPath); err != nil {
			t.Fatalf("load ASN: %v", err)
		}
	}
	defer s.Close()

	info := s.Lookup("47.96.0.1")
	if info == nil {
		t.Fatal("查 47.96.0.1 返回 nil")
	}
	if info.Country != "中国" {
		t.Errorf("country: %q", info.Country)
	}
	if info.CloudProvider != "aliyun" {
		t.Errorf("cloud_provider: %q", info.CloudProvider)
	}
	if info.ISP == "" {
		t.Error("ISP should not be empty")
	}
	if os.Getenv("SUBGW_TEST_ASN") != "" {
		if info.ASN != "AS37963" || info.ASNOrg == "" || info.UsageType == "" {
			t.Errorf("ASN enrichment incomplete: %+v", info)
		}
		cf := s.Lookup("1.1.1.1")
		if cf == nil || cf.ASN != "AS13335" || cf.UsageType != "CDN" || cf.UsageTypeSource != "inferred" {
			t.Errorf("Cloudflare enrichment incomplete: %+v", cf)
		}
	}

	// 无效 IP
	if info := s.Lookup("not-an-ip"); info != nil {
		t.Errorf("无效 IP 应返回 nil")
	}
}

func TestLookupConcurrentWithXdb(t *testing.T) {
	path := os.Getenv("SUBGW_TEST_XDB")
	if path == "" {
		t.Skip("SUBGW_TEST_XDB 未设置,跳过 xdb 并发集成测试")
	}
	s := New()
	if err := s.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if asnPath := os.Getenv("SUBGW_TEST_ASN"); asnPath != "" {
		if err := s.LoadASN(asnPath); err != nil {
			t.Fatalf("load ASN: %v", err)
		}
	}
	defer s.Close()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				info := s.Lookup("47.96.0.1")
				if info == nil || info.Country != "中国" || info.CloudProvider != "aliyun" {
					t.Errorf("concurrent lookup returned %+v", info)
					return
				}
			}
		}()
	}
	wg.Wait()
}
