package config

// Cloudflare 官方 IP 段(v4 + v6)。
// 来源:https://www.cloudflare.com/ips-v4 / ips-v6
// 截至 2024-10 最新发布,几年才会加新段。若 CF 加了新段而本程序没更新,
// 可手动在 real_ip.trust_proxies 里追加。
//
// 启用方式:
//   real_ip:
//     cloudflare: true
//     trust_headers:
//       - "CF-Connecting-IP"   # CF 给的真实客户端 IP,首选(自动追加)
//       - "X-Forwarded-For"
var CloudflareIPv4 = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

var CloudflareIPv6 = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// applyCloudflare 把 CF IP 段追加到 trust_proxies,把 CF-Connecting-IP 放到
// trust_headers 最前面(只有未包含时才追加,幂等)。
func applyCloudflare(c *Config) {
	if !c.RealIP.Cloudflare {
		return
	}
	// 1) trust_headers 首位插 CF-Connecting-IP
	const cfHdr = "CF-Connecting-IP"
	hasCFHdr := false
	for _, h := range c.RealIP.TrustHeaders {
		if h == cfHdr {
			hasCFHdr = true
			break
		}
	}
	if !hasCFHdr {
		c.RealIP.TrustHeaders = append([]string{cfHdr}, c.RealIP.TrustHeaders...)
	}
	// 2) trust_proxies 合并 CF IP 段
	seen := map[string]bool{}
	for _, p := range c.RealIP.TrustProxies {
		seen[p] = true
	}
	for _, p := range append(CloudflareIPv4, CloudflareIPv6...) {
		if !seen[p] {
			c.RealIP.TrustProxies = append(c.RealIP.TrustProxies, p)
			seen[p] = true
		}
	}
}
