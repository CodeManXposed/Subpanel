package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "test.db"), 100*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSubmitAndQueryEvent(t *testing.T) {
	st := newTestStore(t)
	st.SubmitEvent(Event{
		TS: time.Now(), Tenant: "t1", ClientIP: "1.1.1.1", UA: "curl/8",
		TokenHash: "abc", Flag: "clash", Path: "/api/v1/client/subscribe",
		Status: 200, Action: "pass", RuleTags: []string{}, UpstreamMS: 12, RespSize: 1234,
		Country: "US", UsageType: "CDN", ISP: "Cloudflare",
	})
	// 等待 flush
	time.Sleep(400 * time.Millisecond)

	evs, err := st.QueryEvents(context.Background(), EventFilter{Tenant: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	if evs[0].ClientIP != "1.1.1.1" || evs[0].Action != "pass" {
		t.Errorf("unexpected event: %+v", evs[0])
	}
	if evs[0].Country != "US" || evs[0].UsageType != "CDN" || evs[0].ISP != "Cloudflare" {
		t.Errorf("geo fields were not restored: %+v", evs[0])
	}
}

func TestAddAndListBans(t *testing.T) {
	st := newTestStore(t)
	exp := time.Now().Add(time.Hour)
	if err := st.AddBan(Ban{
		Kind: "ip", Target: "1.2.3.4", Reason: "scan", CreatedTS: time.Now(),
		ExpiresTS: &exp, CreatedBy: "test", RuleTags: []string{"x"},
	}); err != nil {
		t.Fatal(err)
	}
	bs, err := st.ListActiveBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 1 {
		t.Fatalf("want 1 ban, got %d", len(bs))
	}
	if bs[0].Target != "1.2.3.4" || bs[0].Kind != "ip" {
		t.Errorf("unexpected ban: %+v", bs[0])
	}
	if bs[0].ExpiresTS == nil {
		t.Error("expires should not be nil")
	}
	if len(bs[0].RuleTags) != 1 || bs[0].RuleTags[0] != "x" {
		t.Errorf("rule tags: %+v", bs[0].RuleTags)
	}

	// 过期的不应当被列出
	past := time.Now().Add(-time.Hour)
	_ = st.AddBan(Ban{Kind: "ip", Target: "9.9.9.9", CreatedTS: time.Now(), ExpiresTS: &past})
	bs, _ = st.ListActiveBans(context.Background())
	for _, b := range bs {
		if b.Target == "9.9.9.9" {
			t.Error("expired ban should not be listed")
		}
	}
}

func TestRemoveBan(t *testing.T) {
	st := newTestStore(t)
	_ = st.AddBan(Ban{Kind: "ip", Target: "1.2.3.4", CreatedTS: time.Now()})
	if err := st.RemoveBan("ip", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	bs, _ := st.ListActiveBans(context.Background())
	if len(bs) != 0 {
		t.Errorf("want 0, got %d", len(bs))
	}
}

func TestSummary(t *testing.T) {
	st := newTestStore(t)
	now := time.Now()
	for i := 0; i < 5; i++ {
		st.SubmitEvent(Event{
			TS: now, Tenant: "t1", ClientIP: "1.1.1.1", TokenHash: "h1",
			Action: "pass", Status: 200,
		})
	}
	st.SubmitEvent(Event{TS: now, Tenant: "t1", ClientIP: "2.2.2.2", TokenHash: "h2", Action: "deny", Status: 403})
	time.Sleep(400 * time.Millisecond)

	s, err := st.Summary(context.Background(), "t1", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if s.TotalEvents != 6 {
		t.Errorf("total: %d", s.TotalEvents)
	}
	if s.PassCount != 5 || s.DenyCount != 1 {
		t.Errorf("pass=%d deny=%d", s.PassCount, s.DenyCount)
	}
	if s.UniqueIPs != 2 {
		t.Errorf("unique ips: %d", s.UniqueIPs)
	}
	if s.UniqueTokens != 2 {
		t.Errorf("unique tokens: %d", s.UniqueTokens)
	}
}

func TestQuerySuspectsFromEventsWithoutReports(t *testing.T) {
	st := newTestStore(t)
	now := time.Now()
	events := []Event{
		{TS: now, Tenant: "t1", ClientIP: "1.1.1.1", UA: "clash", TokenHash: "tok-a", Action: "pass"},
		{TS: now, Tenant: "t1", ClientIP: "2.2.2.2", UA: "shadowrocket", TokenHash: "tok-a", Action: "pass"},
		{TS: now, Tenant: "t1", ClientIP: "2.2.2.2", UA: "shadowrocket", TokenHash: "tok-a", Action: "fake"},
		{TS: now, Tenant: "t1", ClientIP: "3.3.3.3", UA: "clash", TokenHash: "tok-b", Action: "pass"},
	}
	for _, e := range events {
		st.SubmitEvent(e)
	}
	time.Sleep(400 * time.Millisecond)

	rows, err := st.QuerySuspects("t1", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 suspects, got %d: %+v", len(rows), rows)
	}
	if rows[0].Token != "tok-a" {
		t.Fatalf("want tok-a first, got %+v", rows[0])
	}
	if rows[0].PullCount != 3 || rows[0].DistinctIPs != 2 || rows[0].DistinctUAs != 2 {
		t.Fatalf("unexpected tok-a stats: %+v", rows[0])
	}
	if rows[0].Email != "" {
		t.Fatalf("event-only suspect should not require report profile: %+v", rows[0])
	}
	if rows[0].LastIP != "2.2.2.2" || rows[0].LastUA != "shadowrocket" {
		t.Fatalf("event-only suspect should expose latest ip/ua: %+v", rows[0])
	}

	if err := st.AddResolvedToken(context.Background(), "tok-a", "t1", "done"); err != nil {
		t.Fatal(err)
	}
	rows, err = st.QuerySuspects("t1", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Token != "tok-b" {
		t.Fatalf("resolved token should be hidden, got %+v", rows)
	}
}

func TestQuerySuspectsEnrichesEventStatsWithReportProfile(t *testing.T) {
	st := newTestStore(t)
	now := time.Now()
	if err := st.UpsertUserReport(UserReport{
		Token:        "tok-a",
		Tenant:       "t1",
		Email:        "user@example.com",
		TrafficUsed:  123,
		TrafficTotal: 456,
	}); err != nil {
		t.Fatal(err)
	}
	st.SubmitEvent(Event{TS: now, Tenant: "t1", ClientIP: "1.1.1.1", UA: "clash", TokenHash: "tok-a", Action: "pass"})
	st.SubmitEvent(Event{TS: now, Tenant: "t1", ClientIP: "2.2.2.2", UA: "clash", TokenHash: "tok-a", Action: "pass"})
	time.Sleep(400 * time.Millisecond)

	rows, err := st.QuerySuspects("t1", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 suspect, got %d: %+v", len(rows), rows)
	}
	if rows[0].Email != "user@example.com" || rows[0].TrafficTotal != 456 {
		t.Fatalf("missing report profile: %+v", rows[0])
	}
	if rows[0].PullCount != 2 || rows[0].DistinctIPs != 2 {
		t.Fatalf("missing event stats: %+v", rows[0])
	}
}
