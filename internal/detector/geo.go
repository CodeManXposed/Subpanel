package detector

import (
	"strings"

	"github.com/huabanmao168/SubPanel/internal/config"
)

// needsGeo 该规则是否要查 GeoIP(避免没用到时白白 Lookup)。
func needsGeo(w *config.When) bool {
	return len(w.CountryIn) > 0 ||
		len(w.CountryNotIn) > 0 ||
		len(w.UsageTypeIn) > 0 ||
		len(w.UsageTypeNotIn) > 0 ||
		len(w.ISPContains) > 0
}

// evalGeoConds 评估 country/usage_type/isp 四个字段,任一命中返回 true。
// 多字段是 OR 关系(任一规则字段命中即视为该规则命中),与频率/UA 规则评估方式一致。
func evalGeoConds(w *config.When, info *GeoInfo) (bool, string) {
	// country_in: 国家在列表内命中。Country/ISOCode 都试一遍,避免 "CN" 和 "中国" 写哪个都行。
	if len(w.CountryIn) > 0 {
		if matchAnyCI(w.CountryIn, info.Country) || matchAnyCI(w.CountryIn, info.ISOCode) {
			return true, "country_in:" + nonEmpty(info.ISOCode, info.Country)
		}
	}
	// country_not_in: 国家不在列表(用于"非 CN 拒"反向白名单)
	// 注意:info.Country/ISOCode 都空时视为"未知",也算命中(防 xdb 漏库)
	if len(w.CountryNotIn) > 0 {
		c := info.Country
		iso := info.ISOCode
		if c == "" && iso == "" {
			return true, "country_not_in:unknown"
		}
		// 任一字段在白名单里就放过,两个都不在才算命中
		if !matchAnyCI(w.CountryNotIn, c) && !matchAnyCI(w.CountryNotIn, iso) {
			return true, "country_not_in:" + nonEmpty(iso, c)
		}
	}
	// usage_type_in
	if len(w.UsageTypeIn) > 0 && info.UsageType != "" {
		if matchAnyCI(w.UsageTypeIn, info.UsageType) {
			return true, "usage_type_in:" + info.UsageType
		}
	}
	// usage_type_not_in(反向白名单)
	if len(w.UsageTypeNotIn) > 0 {
		if info.UsageType == "" {
			return true, "usage_type_not_in:unknown"
		}
		if !matchAnyCI(w.UsageTypeNotIn, info.UsageType) {
			return true, "usage_type_not_in:" + info.UsageType
		}
	}
	// isp_contains 子串包含(任一子串出现在 ISP 字段内即命中)
	if len(w.ISPContains) > 0 && info.ISP != "" {
		low := strings.ToLower(info.ISP)
		for _, sub := range w.ISPContains {
			s := strings.ToLower(strings.TrimSpace(sub))
			if s != "" && strings.Contains(low, s) {
				return true, "isp_contains:" + sub
			}
		}
	}
	return false, ""
}

func matchAnyCI(list []string, s string) bool {
	if s == "" {
		return false
	}
	low := strings.ToLower(strings.TrimSpace(s))
	for _, v := range list {
		if strings.ToLower(strings.TrimSpace(v)) == low {
			return true
		}
	}
	return false
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
