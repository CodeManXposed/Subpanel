package store

import (
	"context"
	"fmt"
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

func TestCloudASNEventFiltersAndSuspectStats(t *testing.T) {
	st := newTestStore(t)
	now := time.Now()
	st.SubmitEvent(Event{
		TS: now, Tenant: "t1", ClientIP: "3.5.140.1", TokenHash: "cloud-user", Action: "pass",
		ASN: "AS16509", ASNOrg: "Amazon.com, Inc.", CloudProvider: "aws", UsageType: "IDC",
	})
	st.SubmitEvent(Event{
		TS: now, Tenant: "t1", ClientIP: "8.8.8.8", TokenHash: "normal-user", Action: "pass",
		ASN: "AS15169", ASNOrg: "Google LLC",
	})
	time.Sleep(400 * time.Millisecond)

	for name, filter := range map[string]EventFilter{
		"cloud":    {Tenant: "t1", Cloud: "yes"},
		"provider": {Tenant: "t1", Provider: "AWS"},
		"asn":      {Tenant: "t1", ASN: "as16509"},
	} {
		evs, err := st.QueryEvents(context.Background(), filter)
		if err != nil {
			t.Fatalf("%s filter: %v", name, err)
		}
		if len(evs) != 1 || evs[0].TokenHash != "cloud-user" || evs[0].ASNOrg != "Amazon.com, Inc." {
			t.Fatalf("%s filter returned %+v", name, evs)
		}
	}

	rows, err := st.QuerySuspects("t1", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var cloud SuspectRow
	for _, row := range rows {
		if row.Token == "cloud-user" {
			cloud = row
		}
	}
	if cloud.CloudPullCount != 1 || len(cloud.CloudProviders) != 1 || cloud.CloudProviders[0] != "aws" || len(cloud.CloudASNs) != 1 || cloud.CloudASNs[0] != "AS16509" {
		t.Fatalf("unexpected cloud suspect stats: %+v", cloud)
	}
}

func TestClientSuffixUAMatchFilters(t *testing.T) {
	st := newTestStore(t)
	now := time.Now()
	for _, event := range []Event{
		{TS: now, Tenant: "t1", TokenHash: "bad", Flag: "clash", UA: "Shadowrocket/2.2.63", Action: "pass"},
		{TS: now, Tenant: "t1", TokenHash: "good", Flag: "clash", UA: "Stash/2.5.0", Action: "pass"},
		{TS: now, Tenant: "t1", TokenHash: "unknown", Flag: "ss", UA: "curl/8", Action: "pass"},
	} {
		st.SubmitEvent(event)
	}
	time.Sleep(400 * time.Millisecond)

	tests := []struct {
		filter string
		token  string
		state  string
	}{
		{filter: "mismatch", token: "bad", state: "mismatch"},
		{filter: "match", token: "good", state: "match"},
		{filter: "unknown", token: "unknown", state: ""},
	}
	for _, test := range tests {
		events, err := st.QueryEvents(context.Background(), EventFilter{Tenant: "t1", ClientMatch: test.filter})
		if err != nil {
			t.Fatalf("%s filter: %v", test.filter, err)
		}
		if len(events) != 1 || events[0].TokenHash != test.token || events[0].ClientMatch != test.state {
			t.Fatalf("%s filter returned %+v", test.filter, events)
		}
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
	if bs[0].Action != "fake" {
		t.Errorf("IP ban action should normalize to fake, got %q", bs[0].Action)
	}

	if err := st.AddBan(Ban{Kind: "token", Target: "leaked-token", Action: "deny", CreatedTS: time.Now()}); err != nil {
		t.Fatal(err)
	}
	bs, err = st.ListActiveBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var foundToken bool
	for _, b := range bs {
		if b.Kind == "token" && b.Target == "leaked-token" {
			foundToken = true
			if b.Action != "deny" {
				t.Errorf("token action=%q, want deny", b.Action)
			}
		}
	}
	if !foundToken {
		t.Error("token ban was not listed")
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

func TestSummaryTopTokensIncludeTenantAndStaySeparate(t *testing.T) {
	st := newTestStore(t)
	now := time.Now()
	st.SubmitEvent(Event{TS: now, Tenant: "sled", ClientIP: "1.1.1.1", TokenHash: "same-token", Action: "pass"})
	st.SubmitEvent(Event{TS: now, Tenant: "rfs", ClientIP: "2.2.2.2", TokenHash: "same-token", Action: "pass"})
	time.Sleep(400 * time.Millisecond)

	s, err := st.Summary(context.Background(), "", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.TopTokens) != 2 {
		t.Fatalf("same token from two tenants must stay separate: %+v", s.TopTokens)
	}
	seen := map[string]bool{}
	for _, row := range s.TopTokens {
		if row.Key != "same-token" || row.Count != 1 {
			t.Fatalf("unexpected top token row: %+v", row)
		}
		seen[row.Tenant] = true
	}
	if !seen["sled"] || !seen["rfs"] {
		t.Fatalf("tenant missing from top tokens: %+v", s.TopTokens)
	}
}

func TestAWSIPChangeSnapshotsPriorWindowByTenant(t *testing.T) {
	st := newTestStore(t)
	actionAt := time.Now().Truncate(time.Second)
	events := []Event{
		{TS: actionAt.Add(-21 * time.Minute), Tenant: "sled", ClientIP: "1.1.1.1", TokenHash: "too-old", Action: "pass"},
		{TS: actionAt.Add(-19 * time.Minute), Tenant: "sled", ClientIP: "2.2.2.2", UA: "clash", TokenHash: "sled-token", Action: "pass", CloudProvider: "aws", ASN: "AS16509", ASNOrg: "Amazon.com, Inc."},
		{TS: actionAt.Add(-18 * time.Minute), Tenant: "sled", ClientIP: "2.2.2.2", UA: "clash", TokenHash: "sled-token", Action: "pass", CloudProvider: "aws", ASN: "AS16509", ASNOrg: "Amazon.com, Inc."},
		{TS: actionAt.Add(-10 * time.Minute), Tenant: "rfs", ClientIP: "3.3.3.3", UA: "sing-box", TokenHash: "rfs-token", Action: "pass"},
		{TS: actionAt.Add(time.Minute), Tenant: "rfs", ClientIP: "4.4.4.4", TokenHash: "too-new", Action: "pass"},
	}
	for _, e := range events {
		st.SubmitEvent(e)
	}
	time.Sleep(400 * time.Millisecond)

	change, err := st.AddAWSIPChange(context.Background(), AWSIPChange{
		OccurredTS: actionAt.UnixMilli(), DNSName: "entry.example.com", Tenant: "sled",
		OldIP: "10.0.0.1", NewIP: "10.0.0.2", LookbackMinutes: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if change.SiteCount != 1 || change.SubscriberCount != 1 || change.PullCount != 2 {
		t.Fatalf("unexpected snapshot stats: %+v", change)
	}
	rows, err := st.ListAWSIPChangeSubscribers(context.Background(), change.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("site-scoped watcher must only capture sled, got %+v", rows)
	}
	var sled AWSIPChangeSubscriber
	for _, row := range rows {
		if row.Tenant == "sled" {
			sled = row
		}
		if row.TokenHash == "too-old" || row.TokenHash == "too-new" {
			t.Fatalf("out-of-window event was captured: %+v", row)
		}
	}
	if sled.TokenHash != "sled-token" || sled.PullCount != 2 || sled.CloudProvider != "aws" || sled.ASN != "AS16509" {
		t.Fatalf("unexpected sled snapshot: %+v", sled)
	}

	// 后续新日志不能改变已冻结的快照。
	st.SubmitEvent(Event{TS: actionAt.Add(-5 * time.Minute), Tenant: "sled", ClientIP: "5.5.5.5", TokenHash: "late-write", Action: "pass"})
	time.Sleep(400 * time.Millisecond)
	rows, err = st.ListAWSIPChangeSubscribers(context.Background(), change.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("snapshot should remain frozen: rows=%+v err=%v", rows, err)
	}

	allSites, err := st.AddAWSIPChange(context.Background(), AWSIPChange{
		OccurredTS: actionAt.UnixMilli(), DNSName: "shared.example.com",
		OldIP: "10.0.0.3", NewIP: "10.0.0.4", LookbackMinutes: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if allSites.SiteCount != 2 || allSites.SubscriberCount != 3 || allSites.PullCount != 4 {
		t.Fatalf("empty tenant must capture every site: %+v", allSites)
	}
}

func TestAWSIPChangeTokenHistoryCorrelatesSameDNSAndTenant(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Now().Add(-30 * time.Minute).Truncate(time.Second)
	for _, event := range []Event{
		{TS: base.Add(-time.Minute), Tenant: "sled", TokenHash: "repeat-token", ClientIP: "1.1.1.1", Action: "pass"},
		{TS: base.Add(24 * time.Minute), Tenant: "sled", TokenHash: "repeat-token", ClientIP: "2.2.2.2", Action: "pass"},
		{TS: base.Add(24 * time.Minute), Tenant: "rfs", TokenHash: "repeat-token", ClientIP: "3.3.3.3", Action: "pass"},
		{TS: base.Add(24 * time.Minute), Tenant: "sled", TokenHash: "once-token", ClientIP: "4.4.4.4", Action: "pass"},
	} {
		st.SubmitEvent(event)
	}
	time.Sleep(150 * time.Millisecond)
	if _, err := st.AddAWSIPChange(ctx, AWSIPChange{
		OccurredTS: base.UnixMilli(), DNSName: "entry.example.com", Tenant: "sled",
		OldIP: "10.0.0.1", NewIP: "10.0.0.2", LookbackMinutes: 5,
	}); err != nil {
		t.Fatal(err)
	}
	second, err := st.AddAWSIPChange(ctx, AWSIPChange{
		OccurredTS: base.Add(25 * time.Minute).UnixMilli(), DNSName: "entry.example.com", Tenant: "sled",
		OldIP: "10.0.0.2", NewIP: "10.0.0.3", LookbackMinutes: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	history, err := st.AWSIPChangeTokenHistory(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	repeated := history["sled\x00repeat-token"]
	if repeated.Hits != 2 || repeated.Total != 2 {
		t.Fatalf("same DNS/site token must correlate across changes: %+v", history)
	}
	if once := history["sled\x00once-token"]; once.Hits != 1 || once.Total != 2 {
		t.Fatalf("single appearance must not look repeated: %+v", history)
	}
	if _, leaked := history["rfs\x00repeat-token"]; leaked {
		t.Fatalf("other tenant must not enter site-scoped snapshots: %+v", history)
	}
}

func TestDNSWatcherLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Now().Add(-10 * time.Minute).UnixMilli()
	w, err := st.AddDNSWatcher(ctx, DNSWatcher{
		DNSName: "entry.example.com", Tenant: "sled", LookbackMinutes: 20,
		Enabled: true, LastIPs: "1.2.3.4", LastCheckedTS: base, LastChangedTS: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !w.Enabled || w.Tenant != "sled" || w.LastIPs != "1.2.3.4" {
		t.Fatalf("unexpected watcher: %+v", w)
	}
	if _, err := st.AddAWSIPChange(ctx, AWSIPChange{
		DNSName: "entry.example.com", Tenant: "sled", OldIP: "1.2.3.4", NewIP: "1.2.3.5",
		LookbackMinutes: 20,
	}); err != nil {
		t.Fatal(err)
	}
	current := *w
	for i := 1; i <= 6; i++ {
		changed := base + int64(i)*60_000
		newIP := fmt.Sprintf("10.0.0.%d", i)
		if err := st.RecordDNSIPTransition(ctx, current, newIP, changed); err != nil {
			t.Fatal(err)
		}
		current.LastIPs = newIP
		current.LastChangedTS = changed
	}
	if err := st.SetDNSWatcherEnabled(ctx, w.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateDNSWatcherNote(ctx, w.ID, "新加坡入口"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateDNSWatcherLookback(ctx, w.ID, 7); err != nil {
		t.Fatal(err)
	}
	changes, err := st.ListAWSIPChanges(ctx, 10)
	if err != nil || len(changes) != 1 || changes[0].Note != "新加坡入口" {
		t.Fatalf("watcher note must sync historical changes: rows=%+v err=%v", changes, err)
	}
	rows, err := st.ListDNSWatchers(ctx, false)
	if err != nil || len(rows) != 1 || rows[0].Enabled || rows[0].LastIPs != "10.0.0.6" || rows[0].LastChangedTS != base+6*60_000 || rows[0].Note != "新加坡入口" || rows[0].LookbackMinutes != 7 {
		t.Fatalf("unexpected persisted watcher: rows=%+v err=%v", rows, err)
	}
	history, err := st.ListDNSIPHistory(ctx, w.ID, 5)
	if err != nil || len(history) != 5 {
		t.Fatalf("history must retain last 5 rows: rows=%+v err=%v", history, err)
	}
	if history[0].IP != "10.0.0.5" || history[0].AliveSec != 60 || history[4].IP != "10.0.0.1" {
		t.Fatalf("unexpected history order/duration: %+v", history)
	}
	active, err := st.ListDNSWatchers(ctx, true)
	if err != nil || len(active) != 0 {
		t.Fatalf("disabled watcher returned as active: rows=%+v err=%v", active, err)
	}
	if err := st.DeleteDNSWatcher(ctx, w.ID); err != nil {
		t.Fatal(err)
	}
}

func TestDNSWatcherFailureKeepsEarliestSignalAndAnchorsSnapshot(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	w, err := st.AddDNSWatcher(ctx, DNSWatcher{
		DNSName: "entry.example.com", Tenant: "sled", LookbackMinutes: 20,
		Enabled: true, LastIPs: "1.2.3.4", LastCheckedTS: now.Add(-time.Minute).UnixMilli(),
		LastChangedTS: now.Add(-time.Hour).UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	failureAt := now.Add(-2 * time.Minute)
	first, err := st.MarkDNSWatcherFailure(ctx, w.DNSName, w.Tenant, "1.2.3.4", failureAt.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.MarkDNSWatcherFailure(ctx, w.DNSName, w.Tenant, "1.2.3.4", failureAt.Add(30*time.Second).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	current, _ := st.GetDNSWatcher(ctx, w.ID)
	if first.PendingFailureTS != failureAt.UnixMilli() || current.PendingFailureTS != failureAt.UnixMilli() {
		t.Fatalf("first failure signal must win: first=%+v current=%+v", first, current)
	}
	if _, err := st.MarkDNSWatcherFailure(ctx, w.DNSName, w.Tenant, "9.9.9.9", failureAt.UnixMilli()); err == nil {
		t.Fatal("mismatched old IP must be rejected")
	}

	st.SubmitEvent(Event{TS: failureAt.Add(-30 * time.Second), Tenant: "sled", TokenHash: "likely-trigger", ClientIP: "8.8.8.8", Action: "pass"})
	st.SubmitEvent(Event{TS: failureAt.Add(30 * time.Second), Tenant: "sled", TokenHash: "after-failure", ClientIP: "8.8.4.4", Action: "pass"})
	time.Sleep(150 * time.Millisecond)
	change, err := st.AddAWSIPChange(ctx, AWSIPChange{
		OccurredTS: now.UnixMilli(), FailureTS: failureAt.UnixMilli(), DNSName: w.DNSName,
		Tenant: w.Tenant, OldIP: "1.2.3.4", NewIP: "1.2.3.5", LookbackMinutes: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListAWSIPChangeSubscribers(ctx, change.ID)
	if err != nil || len(rows) != 1 || rows[0].TokenHash != "likely-trigger" {
		t.Fatalf("snapshot must end at failure signal: rows=%+v err=%v", rows, err)
	}
	if err := st.RecordDNSIPTransition(ctx, *current, "1.2.3.5", now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	current, _ = st.GetDNSWatcher(ctx, w.ID)
	if current.PendingFailureTS != 0 || current.PendingFailureIP != "" {
		t.Fatalf("transition must clear pending failure: %+v", current)
	}
}

func TestVacuumExpiresAWSIPChangeSnapshots(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	old, err := st.AddAWSIPChange(ctx, AWSIPChange{
		OccurredTS: time.Now().Add(-48 * time.Hour).UnixMilli(), OldIP: "1.1.1.1", NewIP: "2.2.2.2", LookbackMinutes: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO aws_ip_change_subscribers
		(change_id,tenant,token_hash,client_ip,ua,pull_count,first_seen_ts,last_seen_ts,cloud_provider,asn,asn_org)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`, old.ID, "sled", "old-token", "1.1.1.1", "clash", 1,
		time.Now().Add(-48*time.Hour).UnixMilli(), time.Now().Add(-48*time.Hour).UnixMilli(), "", "", ""); err != nil {
		t.Fatal(err)
	}
	newer, err := st.AddAWSIPChange(ctx, AWSIPChange{
		OccurredTS: time.Now().UnixMilli(), OldIP: "2.2.2.2", NewIP: "3.3.3.3", LookbackMinutes: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Vacuum(ctx, 24*time.Hour, 24*time.Hour, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var oldChanges, oldSubscribers int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM aws_ip_changes WHERE id=?`, old.ID).Scan(&oldChanges); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM aws_ip_change_subscribers WHERE change_id=?`, old.ID).Scan(&oldSubscribers); err != nil {
		t.Fatal(err)
	}
	if oldChanges != 0 || oldSubscribers != 0 {
		t.Fatalf("expired snapshot not removed: changes=%d subscribers=%d", oldChanges, oldSubscribers)
	}
	if _, err := st.GetAWSIPChange(ctx, newer.ID); err != nil {
		t.Fatalf("current snapshot was removed: %v", err)
	}
}

func TestFocusTokenMarksNewBehaviorAndLeavesSuspects(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	st.SubmitEvent(Event{TS: now.Add(-time.Minute), Tenant: "sled", ClientIP: "1.1.1.1", UA: "clash", TokenHash: "watch-me", Action: "pass"})
	time.Sleep(200 * time.Millisecond)
	if err := st.AddFocusToken(ctx, "watch-me", "sled", ""); err != nil {
		t.Fatal(err)
	}
	st.SubmitEvent(Event{TS: time.Now().Add(time.Millisecond), Tenant: "sled", ClientIP: "2.2.2.2", UA: "v2rayN", TokenHash: "watch-me", Action: "pass"})
	time.Sleep(200 * time.Millisecond)

	events, err := st.QueryEvents(ctx, EventFilter{TokenHash: "watch-me", IncludeResolved: true})
	if err != nil || len(events) != 2 || !events[0].Focused || events[1].Focused {
		t.Fatalf("focus behavior flags: events=%+v err=%v", events, err)
	}
	focus, err := st.ListFocusTokens(ctx, "sled")
	if err != nil || len(focus) != 1 || focus[0].ActivityCount != 1 || focus[0].LastIP != "2.2.2.2" {
		t.Fatalf("focus list: rows=%+v err=%v", focus, err)
	}
	suspects, err := st.QuerySuspects("sled", now.Add(-time.Hour))
	if err != nil || len(suspects) != 0 {
		t.Fatalf("focused token must leave ordinary suspects: rows=%+v err=%v", suspects, err)
	}
	if err := st.AddResolvedToken(ctx, "watch-me", "sled", ""); err != nil {
		t.Fatal(err)
	}
	focus, err = st.ListFocusTokens(ctx, "sled")
	if err != nil || len(focus) != 0 {
		t.Fatalf("resolved token must leave focus list: rows=%+v err=%v", focus, err)
	}
}

func TestTokenAssociationSurvivesUUIDReset(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	oldToken, newToken := "token-before-reset", "token-after-reset"
	if err := st.UpsertUserReport(UserReport{Token: oldToken, Tenant: "sled", UUID: "uuid-old", Email: " User@Example.com "}); err != nil {
		t.Fatal(err)
	}
	beforeFocus := time.Now().Add(-time.Second)
	st.SubmitEvent(Event{TS: beforeFocus, Tenant: "sled", ClientIP: "1.1.1.1", UA: "Clash/1", TokenHash: oldToken, Action: "pass"})
	time.Sleep(150 * time.Millisecond)
	if err := st.AddFocusToken(ctx, oldToken, "sled", "watch account"); err != nil {
		t.Fatal(err)
	}
	afterFocus := time.Now().Add(time.Millisecond)
	st.SubmitEvent(Event{TS: afterFocus, Tenant: "sled", ClientIP: "2.2.2.2", UA: "v2rayN/1", TokenHash: oldToken, Action: "pass"})
	if err := st.UpsertUserReport(UserReport{Token: newToken, Tenant: "sled", UUID: "uuid-new", Email: "user@example.com"}); err != nil {
		t.Fatal(err)
	}
	st.SubmitEvent(Event{TS: time.Now().Add(2 * time.Millisecond), Tenant: "sled", ClientIP: "3.3.3.3", UA: "Shadowrocket/1", TokenHash: newToken, Action: "pass"})
	time.Sleep(250 * time.Millisecond)

	linked, err := st.ListAssociatedTokens(ctx, "sled", newToken)
	if err != nil || len(linked) != 2 || linked[0].Token != newToken || linked[1].Token != oldToken {
		t.Fatalf("linked tokens: rows=%+v err=%v", linked, err)
	}
	focus, err := st.ListFocusTokens(ctx, "sled")
	if err != nil || len(focus) != 1 || focus[0].Token != newToken || focus[0].ActivityCount != 2 {
		t.Fatalf("focus must move to latest token and include aliases: rows=%+v err=%v", focus, err)
	}
	detail, err := st.QuerySuspectDetail(newToken, "sled", time.Now().Add(-time.Hour))
	if err != nil || len(detail.Tokens) != 2 || len(detail.IPs) != 3 || len(detail.UAs) != 3 {
		t.Fatalf("associated behavior detail: detail=%+v err=%v", detail, err)
	}
	oldEvents, err := st.QueryEvents(ctx, EventFilter{TokenHash: oldToken, IncludeResolved: true})
	if err != nil || len(oldEvents) != 2 || !oldEvents[0].Focused || oldEvents[1].Focused {
		t.Fatalf("old token focus timeline must survive reset: events=%+v err=%v", oldEvents, err)
	}
	newEvents, err := st.QueryEvents(ctx, EventFilter{TokenHash: newToken, IncludeResolved: true})
	if err != nil || len(newEvents) != 1 || !newEvents[0].Focused {
		t.Fatalf("new token must inherit focus: events=%+v err=%v", newEvents, err)
	}

	// 已处理状态同样迁移到新 token，且历史旧 token 仍按同一账户归档。
	if err := st.RemoveFocusToken(ctx, newToken); err != nil {
		t.Fatal(err)
	}
	if err := st.AddResolvedToken(ctx, oldToken, "sled", "done"); err != nil {
		t.Fatal(err)
	}
	thirdToken := "token-second-reset"
	if err := st.UpsertUserReport(UserReport{Token: thirdToken, Tenant: "sled", UUID: "uuid-third", Email: "USER@example.com"}); err != nil {
		t.Fatal(err)
	}
	resolved, err := st.ListResolvedTokens(ctx, "sled")
	if err != nil || len(resolved) != 1 || resolved[0].Token != thirdToken {
		t.Fatalf("resolved state must move to latest token: rows=%+v err=%v", resolved, err)
	}
	visible, err := st.QueryEvents(ctx, EventFilter{Tenant: "sled"})
	if err != nil || len(visible) != 0 {
		t.Fatalf("old aliases must stay archived with current resolved token: events=%+v err=%v", visible, err)
	}

	// 站点隔离且空邮箱不关联，避免误合并。
	if err := st.UpsertUserReport(UserReport{Token: "other-site", Tenant: "rfs", Email: "user@example.com"}); err != nil {
		t.Fatal(err)
	}
	if rows, err := st.ListAssociatedTokens(ctx, "rfs", "other-site"); err != nil || len(rows) != 1 {
		t.Fatalf("association must be tenant scoped: rows=%+v err=%v", rows, err)
	}
	if err := st.UpsertUserReport(UserReport{Token: "anonymous", Tenant: "sled"}); err != nil {
		t.Fatal(err)
	}
	if rows, err := st.ListAssociatedTokens(ctx, "sled", "anonymous"); err != nil || len(rows) != 0 {
		t.Fatalf("empty email must not auto-associate: rows=%+v err=%v", rows, err)
	}
}

func TestManualTokenAssociationWithoutUserReport(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.AddFocusToken(ctx, "old-token", "sled", "manual watch"); err != nil {
		t.Fatal(err)
	}
	if err := st.AssociateTokens(ctx, "sled", "new-token", "old-token"); err != nil {
		t.Fatal(err)
	}
	linked, err := st.ListAssociatedTokens(ctx, "sled", "new-token")
	if err != nil || len(linked) != 2 {
		t.Fatalf("manual association: rows=%+v err=%v", linked, err)
	}
	focus, err := st.ListFocusTokens(ctx, "sled")
	if err != nil || len(focus) != 1 || focus[0].Token != "new-token" || focus[0].Note != "manual watch" {
		t.Fatalf("manual association must move focus: rows=%+v err=%v", focus, err)
	}
	if err := st.AssociateTokens(ctx, "sled", "newest-token", "new-token"); err != nil {
		t.Fatal(err)
	}
	linked, err = st.ListAssociatedTokens(ctx, "sled", "newest-token")
	if err != nil || len(linked) != 3 {
		t.Fatalf("manual groups must merge transitively: rows=%+v err=%v", linked, err)
	}
	if rows, err := st.ListAssociatedTokens(ctx, "other", "old-token"); err != nil || len(rows) != 0 {
		t.Fatalf("manual association must remain tenant scoped: rows=%+v err=%v", rows, err)
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

	// 已处理后再次出现的新请求必须重新进入列表，并标记为重点关注。
	st.SubmitEvent(Event{TS: time.Now().Add(time.Second), Tenant: "t1", ClientIP: "9.9.9.9", UA: "clash", TokenHash: "tok-a", Action: "fake"})
	time.Sleep(400 * time.Millisecond)
	rows, err = st.QuerySuspects("t1", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Token != "tok-a" || !rows[0].ReTriggered || rows[0].PullCount != 1 {
		t.Fatalf("retriggered token should return as first priority: %+v", rows)
	}
	evs, err := st.QueryEvents(context.Background(), EventFilter{Tenant: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || evs[0].TokenHash != "tok-a" || !evs[0].ReTriggered {
		t.Fatalf("events should hide archived rows and show retrigger: %+v", evs)
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
