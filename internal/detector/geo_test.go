package detector

import (
	"testing"

	"github.com/huabanmao168/SubPanel/internal/config"
)

func TestEvalGeoConds_CountryIn(t *testing.T) {
	w := &config.When{CountryIn: []string{"CN", "中国"}}
	if hit, _ := evalGeoConds(w, &GeoInfo{Country: "中国", ISOCode: "CN"}); !hit {
		t.Fatal("应该命中 CN")
	}
	if hit, _ := evalGeoConds(w, &GeoInfo{Country: "美国", ISOCode: "US"}); hit {
		t.Fatal("US 不该命中")
	}
}

func TestEvalGeoConds_CountryNotIn(t *testing.T) {
	w := &config.When{CountryNotIn: []string{"CN"}}
	if hit, _ := evalGeoConds(w, &GeoInfo{ISOCode: "US"}); !hit {
		t.Fatal("非 CN 应该命中")
	}
	if hit, _ := evalGeoConds(w, &GeoInfo{ISOCode: "CN"}); hit {
		t.Fatal("CN 不该命中")
	}
	// 未知国家算命中(防漏库)
	if hit, _ := evalGeoConds(w, &GeoInfo{}); !hit {
		t.Fatal("空国家应当命中 not_in(防漏库)")
	}
}

func TestEvalGeoConds_UsageType(t *testing.T) {
	w := &config.When{UsageTypeIn: []string{"IDC", "CDN"}}
	if hit, _ := evalGeoConds(w, &GeoInfo{UsageType: "IDC"}); !hit {
		t.Fatal("IDC 应该命中")
	}
	if hit, _ := evalGeoConds(w, &GeoInfo{UsageType: "MOB"}); hit {
		t.Fatal("MOB 不该命中")
	}
}

func TestEvalGeoConds_ISPContains(t *testing.T) {
	w := &config.When{ISPContains: []string{"阿里", "腾讯"}}
	if hit, _ := evalGeoConds(w, &GeoInfo{ISP: "阿里云CDN"}); !hit {
		t.Fatal("阿里应命中")
	}
	if hit, _ := evalGeoConds(w, &GeoInfo{ISP: "电信"}); hit {
		t.Fatal("电信不该命中")
	}
}

func TestNeedsGeo(t *testing.T) {
	if needsGeo(&config.When{}) {
		t.Fatal("空 When 不该 needsGeo")
	}
	if !needsGeo(&config.When{CountryIn: []string{"CN"}}) {
		t.Fatal("CountryIn 应 needsGeo")
	}
}
