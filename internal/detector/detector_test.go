package detector

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/config"
)

func TestSetRulesUpdatesMaxWindow(t *testing.T) {
	cfg := &config.DetectorCfg{Rules: []config.Rule{{
		Name: "short",
		When: config.When{TokenFreq: &config.Cond{
			Window: config.Duration(5 * time.Minute),
			GTE:    2,
		}},
	}}}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.MaxWindow(); got != time.Hour {
		t.Fatalf("initial max window=%s, want 1h", got)
	}

	d.SetRules([]config.Rule{{
		Name: "long",
		When: config.When{TokenDistinctIPs: &config.Cond{
			Window: config.Duration(24 * time.Hour),
			GTE:    5,
		}},
	}})
	if got := d.MaxWindow(); got != 24*time.Hour {
		t.Fatalf("hot-reloaded max window=%s, want 24h", got)
	}
}

func TestCloudTokenDistinctUAsRequiresSameTokenIPAndCloud(t *testing.T) {
	cfg := &config.DetectorCfg{Rules: []config.Rule{{
		Name: "cloud_ua_probe",
		When: config.When{CloudTokenDistinctUAs: &config.Cond{
			Window: config.Duration(time.Minute), GTE: 4,
		}},
	}}}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d.SetCloudLookup(func(ip string) (bool, string) {
		return ip == "47.1.2.3", "aliyun"
	})

	for i := 1; i <= 3; i++ {
		d.Observe("47.1.2.3", "token-a", fmt.Sprintf("client/%d", i))
		if got := d.Evaluate("47.1.2.3", "token-a", ""); got.Hit {
			t.Fatalf("triggered too early at UA %d: %+v", i, got)
		}
	}
	d.Observe("47.1.2.3", "token-a", "client/4")
	got := d.Evaluate("47.1.2.3", "token-a", "")
	if !got.Hit || len(got.Tags) != 1 || got.Tags[0] != "cloud_ua_probe" {
		t.Fatalf("expected cloud UA probe hit: %+v", got)
	}

	for i := 1; i <= 12; i++ {
		d.Observe("8.8.8.8", "token-b", fmt.Sprintf("client/%d", i))
	}
	if got := d.Evaluate("8.8.8.8", "token-b", ""); got.Hit {
		t.Fatalf("non-cloud IP must not trigger: %+v", got)
	}

	for i := 1; i <= 4; i++ {
		d.Observe("47.1.2.3", "token-c", "same-client")
	}
	if got := d.Evaluate("47.1.2.3", "token-c", ""); got.Hit {
		t.Fatalf("duplicate UA values must count once: %+v", got)
	}
}

func TestUncommonUARuleAndDynamicWhitelist(t *testing.T) {
	cfg := &config.DetectorCfg{Rules: []config.Rule{{
		Name: "uncommon_ua", Action: "fake", When: config.When{UncommonUA: true},
	}}}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Evaluate("1.2.3.4", "tok", "FlClash/v0.8.90"); got.Hit {
		t.Fatalf("known subscription UA must not trigger: %+v", got)
	}
	if got := d.Evaluate("1.2.3.4", "tok", "Mozilla/5.0"); !got.Hit || got.Action != "fake" {
		t.Fatalf("uncommon UA should trigger fake: %+v", got)
	}
	d.SetDynamicUAWhitelist(func(ua string) bool { return strings.Contains(ua, "InternalFetcher") })
	if got := d.Evaluate("1.2.3.4", "tok", "InternalFetcher/1.0"); got.Hit {
		t.Fatalf("dynamic UA whitelist must exempt uncommon rule: %+v", got)
	}
}

func TestDenyActionWinsWhenMultipleRulesMatch(t *testing.T) {
	cfg := &config.DetectorCfg{Rules: []config.Rule{
		{Name: "poison", Action: "fake", When: config.When{IPFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 1}}},
		{Name: "block", Action: "deny", When: config.When{IPFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 1}}},
	}}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d.Observe("1.2.3.4", "token", "client")
	got := d.Evaluate("1.2.3.4", "token", "client")
	if !got.Hit || got.Action != "deny" || len(got.Tags) != 2 {
		t.Fatalf("expected deny precedence, got %+v", got)
	}
}

func TestRateLimitActionAndPrecedence(t *testing.T) {
	cfg := &config.DetectorCfg{Rules: []config.Rule{
		{Name: "poison", Action: "fake", When: config.When{IPFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 1}}},
		{Name: "throttle", Action: "rate_limit", When: config.When{IPFreq: &config.Cond{Window: config.Duration(10 * time.Minute), GTE: 1}}},
	}}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d.Observe("1.2.3.4", "token", "client")
	got := d.Evaluate("1.2.3.4", "token", "client")
	if !got.Hit || got.Action != "rate_limit" || got.RetryAfter != 10*time.Minute {
		t.Fatalf("result=%+v, want rate_limit with 10m retry", got)
	}
}

func TestIPWhitelistExemptsIPClassificationButKeepsFrequencyRule(t *testing.T) {
	cfg := &config.DetectorCfg{Rules: []config.Rule{
		{Name: "ip_freq_burst", Action: "rate_limit", When: config.When{IPFreq: &config.Cond{Window: config.Duration(time.Minute), GTE: 2}}},
		{Name: "ip_multi_token", Action: "rate_limit", When: config.When{IPDistinctTokens: &config.Cond{Window: config.Duration(10 * time.Minute), GTE: 2}}},
		{Name: "cloud_deny", Action: "deny", When: config.When{FromCloudIP: true}},
		{Name: "oversea_deny", Action: "deny", When: config.When{CountryNotIn: []string{"CN"}}},
	}}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d.SetDynamicIPWhitelist(func(ip string) bool { return ip == "1.2.3.4" })
	d.SetCloudLookup(func(ip string) (bool, string) { return true, "cloudflare" })
	d.SetGeoLookup(func(ip string) *GeoInfo {
		return &GeoInfo{Country: "美国", ISOCode: "US", UsageType: "CDN", ISP: "Cloudflare"}
	})
	d.Observe("1.2.3.4", "token-a", "clash")
	if got := d.Evaluate("1.2.3.4", "token-a", "clash"); got.Hit {
		t.Fatalf("first whitelisted request triggered unexpectedly: %+v", got)
	}
	d.Observe("1.2.3.4", "token-b", "clash")
	got := d.Evaluate("1.2.3.4", "token-b", "clash")
	if !got.Hit || got.Action != "rate_limit" || len(got.Tags) != 1 || got.Tags[0] != "ip_freq_burst" {
		t.Fatalf("whitelisted IP must still hit frequency rule only: %+v", got)
	}
}

func TestNonWhitelistedIPStillHitsNetworkDenyRule(t *testing.T) {
	cfg := &config.DetectorCfg{Rules: []config.Rule{{
		Name: "cloud_deny", Action: "deny", When: config.When{FromCloudIP: true},
	}}}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d.SetCloudLookup(func(ip string) (bool, string) { return true, "cloudflare" })
	d.Observe("1.2.3.5", "token", "clash")
	if got := d.Evaluate("1.2.3.5", "token", "clash"); !got.Hit || got.Action != "deny" {
		t.Fatalf("non-whitelisted cloud IP should still be denied: %+v", got)
	}
}

func TestObserveCapsRandomTokensPerIPWithoutStoppingIPFrequency(t *testing.T) {
	cfg := &config.DetectorCfg{Rules: []config.Rule{{
		Name: "ip_flood", Action: "rate_limit",
		When: config.When{IPFreq: &config.Cond{Window: config.Duration(time.Hour), GTE: 20}},
	}}}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	const ip = "104.28.198.10"
	for i := 0; i < maxTokenObservationsPerIPWindow+5000; i++ {
		d.Observe(ip, fmt.Sprintf("random-token-%d", i), "script/1.0")
	}
	if got := d.ipTokenSet.Count(ip, time.Hour); got != maxTokenObservationsPerIPWindow {
		t.Fatalf("tracked random tokens=%d, want capped at %d", got, maxTokenObservationsPerIPWindow)
	}
	if got := d.ipFreq.Sum(ip, time.Hour); got != maxTokenObservationsPerIPWindow+5000 {
		t.Fatalf("IP frequency=%d, want all requests retained", got)
	}
	if got := d.tokenFreq.Sum("random-token-5000", time.Hour); got != 0 {
		t.Fatalf("late random token should not allocate tracking state, got count=%d", got)
	}
	if got := d.Evaluate(ip, "random-token-5000", "script/1.0"); !got.Hit || got.Action != "rate_limit" {
		t.Fatalf("IP flood must remain rate-limited after token cap: %+v", got)
	}
}
