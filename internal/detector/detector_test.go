package detector

import (
	"fmt"
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
