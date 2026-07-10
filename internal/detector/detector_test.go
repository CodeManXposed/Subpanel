package detector

import (
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
