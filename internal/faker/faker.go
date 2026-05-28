// Package faker 生成"看起来合法但全是黑洞 IP"的虚假订阅响应。
//
// 根据 flag(优先)或 UA 选择格式:
//   - flag=clash | UA 含 Clash → Clash YAML
//   - flag=v2ray | UA 含 v2rayN → base64(vmess://...)
//   - flag=sing-box | UA 含 sing-box → sing-box JSON
//   - default → base64(ss://...)
package faker

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"strings"
)

// Renderer 给定上下文生成响应体和 Content-Type。
type Renderer struct {
	blackholes []string
	nodeCount  int
}

func New(blackholes []string, nodeCount int) *Renderer {
	if nodeCount <= 0 {
		nodeCount = 6
	}
	if len(blackholes) == 0 {
		blackholes = []string{"192.0.2.1"}
	}
	return &Renderer{blackholes: blackholes, nodeCount: nodeCount}
}

// Output 渲染结果。
type Output struct {
	Body        []byte
	ContentType string
	Headers     map[string]string
}

// Render 根据 flag/UA 选择格式生成。
func (r *Renderer) Render(flag, ua string) Output {
	kind := pickKind(flag, ua)
	switch kind {
	case "clash":
		return r.renderClash()
	case "vmess":
		return r.renderVmess()
	case "sing-box":
		return r.renderSingBox()
	case "trojan":
		return r.renderTrojan()
	default:
		return r.renderShadowsocks()
	}
}

func pickKind(flag, ua string) string {
	flag = strings.ToLower(flag)
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(flag, "clash"), strings.Contains(flag, "meta"), strings.Contains(flag, "stash"):
		return "clash"
	case strings.Contains(flag, "v2ray"), strings.Contains(flag, "vmess"):
		return "vmess"
	case strings.Contains(flag, "sing-box"), strings.Contains(flag, "singbox"):
		return "sing-box"
	case strings.Contains(flag, "trojan"):
		return "trojan"
	case strings.Contains(flag, "ss"), strings.Contains(flag, "shadowsocks"):
		return "ss"
	}
	switch {
	case strings.Contains(ua, "clash"), strings.Contains(ua, "stash"), strings.Contains(ua, "mihomo"):
		return "clash"
	case strings.Contains(ua, "v2rayn"), strings.Contains(ua, "v2rayng"):
		return "vmess"
	case strings.Contains(ua, "sing-box"), strings.Contains(ua, "singbox"):
		return "sing-box"
	case strings.Contains(ua, "shadowrocket"):
		return "ss"
	}
	return "ss"
}

// 通用 header(模仿 V2board 订阅响应)
func subInfoHeaders() map[string]string {
	return map[string]string{
		"Profile-Update-Interval": "24",
		// Subscription-Userinfo: 给客户端展示流量/到期,假数据
		"Subscription-Userinfo": "upload=0; download=0; total=107374182400; expire=4102444800",
	}
}

func (r *Renderer) randHost() string {
	return r.blackholes[mrand.Intn(len(r.blackholes))]
}

func randPort() int { return 10000 + mrand.Intn(50000) }

func randPassword() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func randName(i int) string {
	pool := []string{"🇭🇰 HK", "🇸🇬 SG", "🇺🇸 US", "🇯🇵 JP", "🇰🇷 KR", "🇩🇪 DE", "🇬🇧 UK", "🇨🇦 CA"}
	return fmt.Sprintf("%s-%02d", pool[i%len(pool)], i+1)
}

// ---------------- Shadowsocks ----------------

func (r *Renderer) renderShadowsocks() Output {
	var lines []string
	for i := 0; i < r.nodeCount; i++ {
		// ss://base64(method:password)@host:port#name
		userinfo := "aes-256-gcm:" + randPassword()
		b64 := base64.RawURLEncoding.EncodeToString([]byte(userinfo))
		line := fmt.Sprintf("ss://%s@%s:%d#%s", b64, r.randHost(), randPort(), urlEscape(randName(i)))
		lines = append(lines, line)
	}
	body := []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n"))))
	return Output{
		Body:        body,
		ContentType: "text/plain; charset=utf-8",
		Headers:     subInfoHeaders(),
	}
}

// ---------------- VMess ----------------

func (r *Renderer) renderVmess() Output {
	var lines []string
	for i := 0; i < r.nodeCount; i++ {
		obj := fmt.Sprintf(
			`{"v":"2","ps":"%s","add":"%s","port":"%d","id":"%s","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":""}`,
			jsonEscape(randName(i)), r.randHost(), randPort(), randUUID(),
		)
		lines = append(lines, "vmess://"+base64.StdEncoding.EncodeToString([]byte(obj)))
	}
	body := []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n"))))
	return Output{
		Body:        body,
		ContentType: "text/plain; charset=utf-8",
		Headers:     subInfoHeaders(),
	}
}

// ---------------- Trojan ----------------

func (r *Renderer) renderTrojan() Output {
	var lines []string
	for i := 0; i < r.nodeCount; i++ {
		line := fmt.Sprintf("trojan://%s@%s:%d?sni=example.com#%s", randPassword(), r.randHost(), randPort(), urlEscape(randName(i)))
		lines = append(lines, line)
	}
	body := []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n"))))
	return Output{
		Body:        body,
		ContentType: "text/plain; charset=utf-8",
		Headers:     subInfoHeaders(),
	}
}

// ---------------- Clash YAML ----------------

func (r *Renderer) renderClash() Output {
	var sb strings.Builder
	sb.WriteString("port: 7890\n")
	sb.WriteString("socks-port: 7891\n")
	sb.WriteString("mode: rule\n")
	sb.WriteString("log-level: info\n")
	sb.WriteString("external-controller: 127.0.0.1:9090\n")
	sb.WriteString("proxies:\n")
	var names []string
	for i := 0; i < r.nodeCount; i++ {
		name := randName(i)
		names = append(names, name)
		sb.WriteString(fmt.Sprintf("  - {name: %q, type: ss, server: %s, port: %d, cipher: aes-256-gcm, password: %q, udp: true}\n",
			name, r.randHost(), randPort(), randPassword()))
	}
	sb.WriteString("proxy-groups:\n")
	sb.WriteString("  - name: PROXY\n    type: select\n    proxies:\n")
	for _, n := range names {
		sb.WriteString(fmt.Sprintf("      - %q\n", n))
	}
	sb.WriteString("rules:\n")
	sb.WriteString("  - GEOIP,CN,DIRECT\n")
	sb.WriteString("  - MATCH,PROXY\n")
	return Output{
		Body:        []byte(sb.String()),
		ContentType: "application/x-yaml; charset=utf-8",
		Headers:     subInfoHeaders(),
	}
}

// ---------------- sing-box ----------------

func (r *Renderer) renderSingBox() Output {
	var outs []string
	for i := 0; i < r.nodeCount; i++ {
		outs = append(outs, fmt.Sprintf(
			`{"type":"shadowsocks","tag":%q,"server":"%s","server_port":%d,"method":"aes-256-gcm","password":%q}`,
			randName(i), r.randHost(), randPort(), randPassword(),
		))
	}
	body := fmt.Sprintf(`{"log":{"level":"info"},"outbounds":[%s,{"type":"direct","tag":"direct"}]}`, strings.Join(outs, ","))
	return Output{
		Body:        []byte(body),
		ContentType: "application/json; charset=utf-8",
		Headers:     subInfoHeaders(),
	}
}

// ---------------- helpers ----------------

func urlEscape(s string) string {
	// 极简的 URL 转义,只把空格和 # 处理掉
	r := strings.NewReplacer(" ", "%20", "#", "%23", "\n", "")
	return r.Replace(s)
}

func jsonEscape(s string) string {
	r := strings.NewReplacer(`"`, `\"`, `\`, `\\`)
	return r.Replace(s)
}
