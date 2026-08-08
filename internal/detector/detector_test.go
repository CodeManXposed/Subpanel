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
