// Package parser 从 HTTP 请求里提取 client_ip / token / flag / tenant 等关键字段。
package parser

import (
	"net"
	"net/http"
	"strings"

	"github.com/huabanmao168/SubPanel/internal/config"
)

type Request struct {
	ClientIP  string
	UA        string
	Token     string // 原文,使用后立即丢弃
	Flag      string
	Tenant    *config.Tenant
	IsSubPath bool // 是否命中订阅路径
	Path      string
}

type HeaderInspect struct {
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	Selected bool     `json:"selected"`
	Reason   string   `json:"reason"`
	IPs      []string `json:"ips,omitempty"`
}

type RealIPInspect struct {
	RemoteAddr   string          `json:"remote_addr"`
	RemoteIP     string          `json:"remote_ip"`
	ClientIP     string          `json:"client_ip"`
	Source       string          `json:"source"`
	TrustedProxy bool            `json:"trusted_proxy"`
	Cloudflare   bool            `json:"cloudflare"`
	TrustHeaders []string        `json:"trust_headers"`
	TrustProxies []string        `json:"trust_proxies"`
	Headers      []HeaderInspect `json:"headers"`
}

// privateBlocks RFC1918 + loopback + link-local
var privateBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	} {
		_, b, _ := net.ParseCIDR(cidr)
		privateBlocks = append(privateBlocks, b)
	}
}

func isPrivate(ip net.IP) bool {
	for _, b := range privateBlocks {
		if b.Contains(ip) {
			return true
		}
	}
	return false
}

// ExtractClientIP 根据 trust_headers + trust_proxies 提取真实 IP。
// 若 RemoteAddr 不在 trust_proxies 列表里,直接信 RemoteAddr。
//
// 规则:
//   - 单值 header(如 X-Real-IP / CF-Connecting-IP) → 取首个有效 IP,不区分公私网
//   - 多值 header(X-Forwarded-For 或值含逗号)→ 从左往右取第一个非私网 IP
func ExtractClientIP(r *http.Request, cfg *config.RealIP) string {
	return InspectClientIP(r, cfg).ClientIP
}

func InspectClientIP(r *http.Request, cfg *config.RealIP) RealIPInspect {
	remoteIP := remoteAddrIP(r.RemoteAddr)
	out := RealIPInspect{
		RemoteAddr:   r.RemoteAddr,
		RemoteIP:     remoteIP,
		ClientIP:     remoteIP,
		Source:       "remote_addr",
		Cloudflare:   cfg.Cloudflare,
		TrustHeaders: append([]string(nil), cfg.TrustHeaders...),
		TrustProxies: append([]string(nil), cfg.TrustProxies...),
	}
	trusted := isTrustedProxy(remoteIP, cfg.TrustProxies)
	out.TrustedProxy = trusted
	if !trusted {
		return out
	}
	for _, h := range cfg.TrustHeaders {
		v := r.Header.Get(h)
		hi := HeaderInspect{Name: h, Value: v}
		if v == "" {
			hi.Reason = "empty"
			out.Headers = append(out.Headers, hi)
			continue
		}
		if strings.Contains(v, ",") {
			// 多值 header,取左侧第一个非私网
			for _, p := range strings.Split(v, ",") {
				cand := strings.TrimSpace(p)
				if cand != "" {
					hi.IPs = append(hi.IPs, cand)
				}
				ip := net.ParseIP(cand)
				if ip != nil && !isPrivate(ip) {
					out.ClientIP = ip.String()
					out.Source = h
					hi.Selected = true
					hi.Reason = "first_public_ip"
					out.Headers = append(out.Headers, hi)
					return out
				}
			}
			hi.Reason = "no_public_ip"
			out.Headers = append(out.Headers, hi)
			continue
		}
		// 单值 header,只要是合法 IP 就用
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			out.ClientIP = ip.String()
			out.Source = h
			hi.Selected = true
			hi.Reason = "single_ip"
			hi.IPs = []string{ip.String()}
			out.Headers = append(out.Headers, hi)
			return out
		}
		hi.Reason = "invalid_ip"
		out.Headers = append(out.Headers, hi)
	}
	return out
}

func remoteAddrIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func isTrustedProxy(ip string, list []string) bool {
	if len(list) == 0 {
		// 没配置就不信任 header
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, x := range list {
		if strings.Contains(x, "/") {
			_, b, err := net.ParseCIDR(x)
			if err == nil && b.Contains(parsed) {
				return true
			}
			continue
		}
		if x == ip {
			return true
		}
	}
	return false
}

// MatchSubscribePath 已废弃: 路径匹配改为按租户的 SubscribePath 严格比对。
// 保留函数签名以免外部依赖,但永远返回 false。
func MatchSubscribePath(path string, patterns []string) (bool, string) {
	return false, ""
}

// Parse 入口字段抽取。Tenant 字段不在这里填,由调用方(Gateway)
// 用 LookupTenant 在自己的快照里查,避免并发读 cfg.Tenants。
func Parse(r *http.Request, cfg *config.Config) *Request {
	ip := ExtractClientIP(r, &cfg.RealIP)
	ua := r.Header.Get("User-Agent")
	flag := r.URL.Query().Get("flag")
	token := r.URL.Query().Get("token")
	return &Request{
		ClientIP: ip,
		UA:       ua,
		Token:    token,
		Flag:     strings.ToLower(flag),
		Path:     r.URL.Path,
	}
}
