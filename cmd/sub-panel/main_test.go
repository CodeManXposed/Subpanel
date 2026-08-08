package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

func TestEnsureAbuseRateLimitRulesMigratesOnce(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"), 10*time.Millisecond, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	originalWhen := `{"IPFreq":{"Window":120000000000,"GTE":25}}`
	if err := st.UpsertDetectRule(store.DetectRuleRow{
		Name: "ip_freq_burst", Desc: "custom", Action: "fake", WhenJSON: originalWhen, Enabled: false, SortOrder: 7,
	}); err != nil {
		t.Fatal(err)
	}
	if err := ensureAbuseRateLimitRules(st); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListDetectRules()
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]store.DetectRuleRow, len(rows))
	for _, row := range rows {
		byName[row.Name] = row
	}
	got := byName["ip_freq_burst"]
	if got.Action != "rate_limit" || got.WhenJSON != originalWhen || got.Enabled || got.SortOrder != 7 {
		t.Fatalf("existing rule was not safely migrated: %+v", got)
	}
	if added := byName["ip_multi_token"]; added.Action != "rate_limit" || !added.Enabled {
		t.Fatalf("missing default multi-token limiter: %+v", added)
	}

	// 管理员后续改回其他动作后，重启不能再次覆盖。
	got.Action = "fake"
	if err := st.UpsertDetectRule(got); err != nil {
		t.Fatal(err)
	}
	if err := ensureAbuseRateLimitRules(st); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.ListDetectRules()
	for _, row := range rows {
		if row.Name == "ip_freq_burst" && row.Action != "fake" {
			t.Fatalf("one-time migration unexpectedly overwrote admin action: %+v", row)
		}
	}
}
