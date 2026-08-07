package store

import "strings"

// clientFamilyFromFlag 将订阅 flag 归一为客户端/配置格式家族。
// ss 等通用格式不绑定单一客户端，因此刻意保留为未知，避免误报。
func clientFamilyFromFlag(flag string) string {
	value := strings.ToLower(strings.TrimSpace(flag))
	switch {
	case strings.Contains(value, "shadowrocket"):
		return "Shadowrocket"
	case strings.Contains(value, "quantumult"):
		return "Quantumult X"
	case strings.Contains(value, "surfboard"):
		return "Surfboard"
	case strings.Contains(value, "surge"):
		return "Surge"
	case strings.Contains(value, "loon"):
		return "Loon"
	case strings.Contains(value, "sing-box"), strings.Contains(value, "singbox"):
		return "sing-box"
	case strings.Contains(value, "v2ray"), strings.Contains(value, "vmess"):
		return "V2Ray"
	case strings.Contains(value, "clash"), strings.Contains(value, "mihomo"), strings.Contains(value, "meta"), strings.Contains(value, "stash"):
		return "Clash"
	default:
		return ""
	}
}

func clientFamilyFromUA(ua string) string {
	value := strings.ToLower(strings.TrimSpace(ua))
	switch {
	case strings.Contains(value, "shadowrocket"):
		return "Shadowrocket"
	case strings.Contains(value, "quantumult"):
		return "Quantumult X"
	case strings.Contains(value, "surfboard"):
		return "Surfboard"
	case strings.Contains(value, "surge"):
		return "Surge"
	case strings.Contains(value, "loon"):
		return "Loon"
	case strings.Contains(value, "sing-box"), strings.Contains(value, "singbox"):
		return "sing-box"
	case strings.Contains(value, "v2rayn"), strings.Contains(value, "v2rayng"), strings.Contains(value, "v2ray"):
		return "V2Ray"
	case strings.Contains(value, "clash"), strings.Contains(value, "mihomo"), strings.Contains(value, "stash"):
		return "Clash"
	default:
		return ""
	}
}

// classifyClientMatch 返回后缀家族、UA 家族和匹配状态。
// 状态为空表示任一侧无法可靠识别，不参与匹配/不匹配筛选。
func classifyClientMatch(flag, ua string) (suffixFamily, uaFamily, state string) {
	suffixFamily = clientFamilyFromFlag(flag)
	uaFamily = clientFamilyFromUA(ua)
	if suffixFamily == "" || uaFamily == "" {
		return suffixFamily, uaFamily, ""
	}
	if suffixFamily == uaFamily {
		return suffixFamily, uaFamily, "match"
	}
	return suffixFamily, uaFamily, "mismatch"
}

func clientMatchDBValue(flag, ua string) any {
	_, _, state := classifyClientMatch(flag, ua)
	switch state {
	case "match":
		return 0
	case "mismatch":
		return 1
	default:
		return -1
	}
}

func clientFlagFamilySQL(column string) string {
	value := "LOWER(TRIM(COALESCE(" + column + ",'')))"
	return `(CASE
		WHEN ` + value + ` LIKE '%shadowrocket%' THEN 'shadowrocket'
		WHEN ` + value + ` LIKE '%quantumult%' THEN 'quantumult'
		WHEN ` + value + ` LIKE '%surfboard%' THEN 'surfboard'
		WHEN ` + value + ` LIKE '%surge%' THEN 'surge'
		WHEN ` + value + ` LIKE '%loon%' THEN 'loon'
		WHEN ` + value + ` LIKE '%sing-box%' OR ` + value + ` LIKE '%singbox%' THEN 'sing-box'
		WHEN ` + value + ` LIKE '%v2ray%' OR ` + value + ` LIKE '%vmess%' THEN 'v2ray'
		WHEN ` + value + ` LIKE '%clash%' OR ` + value + ` LIKE '%mihomo%' OR ` + value + ` LIKE '%meta%' OR ` + value + ` LIKE '%stash%' THEN 'clash'
		ELSE '' END)`
}

func clientUAFamilySQL(column string) string {
	value := "LOWER(TRIM(COALESCE(" + column + ",'')))"
	return `(CASE
		WHEN ` + value + ` LIKE '%shadowrocket%' THEN 'shadowrocket'
		WHEN ` + value + ` LIKE '%quantumult%' THEN 'quantumult'
		WHEN ` + value + ` LIKE '%surfboard%' THEN 'surfboard'
		WHEN ` + value + ` LIKE '%surge%' THEN 'surge'
		WHEN ` + value + ` LIKE '%loon%' THEN 'loon'
		WHEN ` + value + ` LIKE '%sing-box%' OR ` + value + ` LIKE '%singbox%' THEN 'sing-box'
		WHEN ` + value + ` LIKE '%v2rayn%' OR ` + value + ` LIKE '%v2rayng%' OR ` + value + ` LIKE '%v2ray%' THEN 'v2ray'
		WHEN ` + value + ` LIKE '%clash%' OR ` + value + ` LIKE '%mihomo%' OR ` + value + ` LIKE '%stash%' THEN 'clash'
		ELSE '' END)`
}

func clientMatchBackfillSQL() string {
	flagFamily := clientFlagFamilySQL("flag")
	uaFamily := clientUAFamilySQL("ua")
	return `UPDATE events SET client_match=CASE
		WHEN ` + flagFamily + `='' OR ` + uaFamily + `='' THEN -1
		WHEN ` + flagFamily + `=` + uaFamily + ` THEN 0
		ELSE 1 END
		WHERE client_match IS NULL`
}
