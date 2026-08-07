package dnswatch

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

func TestNormalizeName(t *testing.T) {
	if got := NormalizeName(" Entry.Example.COM. "); got != "entry.example.com" {
		t.Fatalf("NormalizeName() = %q", got)
	}
}

func TestManagerRecordsDNSChangeForSelectedTenant(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "dnswatch.db"), 20*time.Millisecond, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().Truncate(time.Second)
	st.SubmitEvent(store.Event{TS: now.Add(-5 * time.Minute), Tenant: "sled", TokenHash: "sled-token", ClientIP: "1.1.1.1", Action: "pass"})
	st.SubmitEvent(store.Event{TS: now.Add(-5 * time.Minute), Tenant: "rfs", TokenHash: "rfs-token", ClientIP: "2.2.2.2", Action: "pass"})
	time.Sleep(100 * time.Millisecond)

	w, err := st.AddDNSWatcher(context.Background(), store.DNSWatcher{
		DNSName: "entry.example.com", Tenant: "sled", LookbackMinutes: 20,
		Enabled: true, LastIPs: "10.0.0.1", LastCheckedTS: now.Add(-time.Minute).UnixMilli(),
		LastChangedTS: now.Add(-5 * time.Minute).UnixMilli(),
		Note:          "新加坡入口",
	})
	if err != nil {
		t.Fatal(err)
	}
	failureAt := now.Add(-2 * time.Minute)
	if _, err := st.MarkDNSWatcherFailure(context.Background(), w.DNSName, w.Tenant, "10.0.0.1", failureAt.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	w, err = st.GetDNSWatcher(context.Background(), w.ID)
	if err != nil {
		t.Fatal(err)
	}
	m := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Minute)
	m.now = func() time.Time { return now }
	m.resolve = func(context.Context, string) ([]string, error) { return []string{"10.0.0.2"}, nil }
	m.checkOne(context.Background(), *w)

	changes, err := st.ListAWSIPChanges(context.Background(), 10)
	if err != nil || len(changes) != 1 {
		t.Fatalf("changes=%+v err=%v", changes, err)
	}
	change := changes[0]
	if change.DNSName != "entry.example.com" || change.Tenant != "sled" || change.OldIP != "10.0.0.1" || change.NewIP != "10.0.0.2" {
		t.Fatalf("unexpected change: %+v", change)
	}
	if change.Note != "新加坡入口" {
		t.Fatalf("change did not inherit watcher note: %+v", change)
	}
	if change.FailureTS != failureAt.UnixMilli() {
		t.Fatalf("change did not use TCP failure anchor: %+v", change)
	}
	if change.SiteCount != 1 || change.SubscriberCount != 1 || change.PullCount != 1 {
		t.Fatalf("snapshot was not scoped to sled: %+v", change)
	}
	updated, err := st.GetDNSWatcher(context.Background(), w.ID)
	if err != nil || updated.LastIPs != "10.0.0.2" || updated.LastError != "" || updated.PendingFailureTS != 0 {
		t.Fatalf("watcher=%+v err=%v", updated, err)
	}
	history, err := st.ListDNSIPHistory(context.Background(), w.ID, 5)
	if err != nil || len(history) != 1 || history[0].IP != "10.0.0.1" || history[0].AliveSec != 300 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
}
