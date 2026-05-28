// Package faker — poison: 把真订阅响应里的节点 server/host 改写成 RFC 5737
// 文档保留段(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)的黑洞 IP,
// 保留节点数量、名字、端口、加密方式、UUID/密码不变。
//
// 思路:
//   1. 顶层 body 若是 base64 整体编码(常见于 v2board 默认订阅),先解码;
//   2. 对纯文本里的 URI 节点(ss / trojan / vless / ssr / hysteria(2) / tuic / anytls / naive 等)
//      用正则替换 @HOST:PORT 中的 HOST;
//   3. vmess:// 特殊处理:解 base64 JSON → 改 "add" → 重编;
//   4. Clash YAML 用正则改 `server: xxx`;
//   5. sing-box JSON 用正则改 `"server":"xxx"`;
//   6. 处理完若原 body 是 base64,重新编码回去。
//
// 解析失败的字段保持原样,绝不抛错(投毒永远要"看起来正常")。
package faker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	mrand "math/rand"
	"regexp"
	"strconv"
	"strings"
)

// RFC 5737 文档保留段,保证全球不可路由。
var rfc5737Pool = []string{"192.0.2.", "198.51.100.", "203.0.113."}

func randBlackholeIP() string {
	seg := rfc5737Pool[mrand.Intn(len(rfc5737Pool))]
	return seg + strconv.Itoa(1+mrand.Intn(254))
}

var (
	// vmess://<base64-json>
	vmessRE = regexp.MustCompile(`vmess://([A-Za-z0-9+/=_-]+)`)

	// ss/trojan/vless/ssr/hysteria/hysteria2/tuic/anytls/naive 等 URI 形态:
	//   scheme://<userinfo>@<host>[:<port>][?...][#name]
	// 抓 host 段(不含 :port)。
	uriHostRE = regexp.MustCompile(
		`(ssr?|trojan|vless|hysteria2?|tuic|anytls|naive\+https?|naive)://([^@\s/?#]+)@([^:/\s?#]+)`,
	)

	// Clash YAML: 行内 `server: 1.2.3.4` 或 `server: example.com`
	yamlServerRE = regexp.MustCompile(`(?m)(server\s*:\s*)([^,\s}]+)`)

	// JSON: "server":"1.2.3.4"
	jsonServerRE = regexp.MustCompile(`"server"\s*:\s*"[^"]*"`)

	// URI fragment #name (节点名,url 编码)。
	uriNameRE = regexp.MustCompile(`#([^#\s&]+)`)

	// Clash YAML `- name: xxx`(列表项节点名)
	yamlNameRE = regexp.MustCompile(`(?m)(^\s*-\s*name\s*:\s*)(.+)$`)
)

// poisonMark 节点名前缀,标记"已投毒"。改前端无害,sing-box 的 tag 字段
// 会被 route 引用,所以这里只标 URI fragment / vmess ps / Clash name。
const poisonMark = "!"

// Poison 改写 body 中所有节点 host 为 RFC5737 黑洞 IP。content-type 仅作参考。
func Poison(body []byte, contentType string) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return body
	}
	// 步骤 1:尝试整体 base64 解码(v2board 默认订阅常见)。
	if dec, ok := tryBase64(trimmed); ok && looksLikeProxyURIs(dec) {
		out := poisonText(dec)
		return []byte(base64.StdEncoding.EncodeToString(out))
	}
	return poisonText(body)
}

func tryBase64(b []byte) ([]byte, bool) {
	s := string(b)
	// 容忍换行/空白
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if d, err := enc.DecodeString(clean); err == nil && len(d) > 0 {
			return d, true
		}
	}
	return nil, false
}

func looksLikeProxyURIs(b []byte) bool {
	s := string(b)
	return strings.Contains(s, "://") &&
		(strings.Contains(s, "vmess://") || strings.Contains(s, "ss://") ||
			strings.Contains(s, "trojan://") || strings.Contains(s, "vless://") ||
			strings.Contains(s, "ssr://") || strings.Contains(s, "hysteria") ||
			strings.Contains(s, "tuic://") || strings.Contains(s, "anytls://"))
}

func poisonText(b []byte) []byte {
	s := string(b)
	// 1) vmess://<b64-json>(改 add + 在 ps 前加 !)
	s = vmessRE.ReplaceAllStringFunc(s, replaceVmess)
	// 2) URI 形态 host
	s = uriHostRE.ReplaceAllStringFunc(s, replaceURIHost)
	// 3) URI fragment #name —— 节点名前加 !
	s = uriNameRE.ReplaceAllStringFunc(s, replaceURIName)
	// 4) Clash YAML `server: xxx`
	s = yamlServerRE.ReplaceAllStringFunc(s, replaceYAMLServer)
	// 5) Clash YAML `- name: xxx` —— 节点名前加 !
	s = yamlNameRE.ReplaceAllStringFunc(s, replaceYAMLName)
	// 6) sing-box / 通用 JSON `"server":"xxx"`
	s = jsonServerRE.ReplaceAllString(s, `"server":"`+"__BH__"+`"`)
	// JSON 的占位符要逐个换成不同的随机 IP,避免所有节点同 IP
	for strings.Contains(s, "__BH__") {
		s = strings.Replace(s, "__BH__", randBlackholeIP(), 1)
	}
	return []byte(s)
}

func replaceVmess(match string) string {
	raw := strings.TrimPrefix(match, "vmess://")
	var dec []byte
	var err error
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if dec, err = enc.DecodeString(raw); err == nil {
			break
		}
	}
	if err != nil || len(dec) == 0 {
		return match
	}
	var obj map[string]any
	if json.Unmarshal(dec, &obj) != nil {
		return match
	}
	obj["add"] = randBlackholeIP()
	// 节点名 ps 前加 !,标记被投毒
	if ps, _ := obj["ps"].(string); ps != "" && !strings.HasPrefix(ps, poisonMark) {
		obj["ps"] = poisonMark + ps
	} else if _, ok := obj["ps"]; !ok {
		obj["ps"] = poisonMark
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return match
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(out)
}

func replaceURIHost(match string) string {
	// 匹配组: scheme://userinfo@host
	idx := strings.LastIndex(match, "@")
	if idx < 0 {
		return match
	}
	prefix := match[:idx+1]
	// 原 host 直接丢,接黑洞 IP。剩余的 :port 由原串后续保留(uriHostRE 没吞 :port)。
	_ = match[idx+1:]
	return prefix + randBlackholeIP()
}

func replaceYAMLServer(match string) string {
	// match 形如 "server: 1.2.3.4" 或 "server:example.com"
	idx := strings.Index(match, ":")
	if idx < 0 {
		return match
	}
	return match[:idx+1] + " " + randBlackholeIP()
}

// replaceURIName 在 URI fragment #name 节点名前加 ! 标记。
// name 是 url 编码的,直接在 # 后插 ! 即可(! 是 fragment 合法字符)。
func replaceURIName(match string) string {
	if len(match) < 2 {
		return match
	}
	rest := match[1:]
	if strings.HasPrefix(rest, poisonMark) {
		return match
	}
	return "#" + poisonMark + rest
}

// replaceYAMLName 在 Clash `- name: xxx` 节点名前加 ! 标记。
// YAML name 可能带引号("xxx" / 'xxx'),要插到引号内。
func replaceYAMLName(match string) string {
	// 用 yamlNameRE 重新拆分,避免重复解析。
	sub := yamlNameRE.FindStringSubmatch(match)
	if len(sub) < 3 {
		return match
	}
	prefix, name := sub[1], sub[2]
	name = strings.TrimRight(name, " \t\r")
	// 已经标过就不重复
	stripped := strings.Trim(name, `"' `)
	if strings.HasPrefix(stripped, poisonMark) {
		return match
	}
	// 保留引号风格;裸名要加引号(! 在 YAML 是 tag 关键字,会让解析炸)
	switch {
	case strings.HasPrefix(name, `"`) && strings.HasSuffix(name, `"`):
		inner := strings.TrimSuffix(strings.TrimPrefix(name, `"`), `"`)
		return prefix + `"` + poisonMark + inner + `"`
	case strings.HasPrefix(name, `'`) && strings.HasSuffix(name, `'`):
		inner := strings.TrimSuffix(strings.TrimPrefix(name, `'`), `'`)
		return prefix + `'` + poisonMark + inner + `'`
	default:
		return prefix + `"` + poisonMark + name + `"`
	}
}
