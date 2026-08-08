package banlist

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

func newTestList(t *testing.T) (*List, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "banlist.db"), time.Hour, 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st), st
}

func TestTokenBanActionsAndReload(t *testing.T) {
	l, st := newTestList(t)
	if err := l.AddToken("token-fake", "fake", "leaked", 0, "test"); err != nil {
		t.Fatal(err)
	}
	if err := l.AddToken("token-deny", "deny", "abuse", time.Hour, "test"); err != nil {
		t.Fatal(err)
	}
	if hit, action, reason := l.CheckToken("token-fake"); !hit || action != "fake" || reason != "leaked" {
		t.Fatalf("fake token check=(%v,%q,%q)", hit, action, reason)
	}
	if hit, action, reason := l.CheckToken("token-deny"); !hit || action != "deny" || reason != "abuse" {
		t.Fatalf("deny token check=(%v,%q,%q)", hit, action, reason)
	}

	reloaded := New(st)
	if err := reloaded.LoadFromStore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hit, action, _ := reloaded.CheckToken("token-deny"); !hit || action != "deny" {
		t.Fatalf("reloaded token check=(%v,%q)", hit, action)
	}
	if err := reloaded.RemoveToken("token-deny"); err != nil {
		t.Fatal(err)
	}
	if hit, _, _ := reloaded.CheckToken("token-deny"); hit {
		t.Error("removed token remains banned")
	}
}

func TestExpiredTokenBan(t *testing.T) {
	l, st := newTestList(t)
	past := time.Now().Add(-time.Minute)
	if err := st.AddBan(store.Ban{Kind: "token", Target: "expired", Action: "deny", CreatedTS: time.Now().Add(-time.Hour), ExpiresTS: &past}); err != nil {
		t.Fatal(err)
	}
	if err := l.LoadFromStore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hit, _, _ := l.CheckToken("expired"); hit {
		t.Error("expired token should not be loaded")
	}
}

func TestIPRejectActionAndReload(t *testing.T) {
	l, st := newTestList(t)
	if err := l.AddIPWithAction("1.2.3.4", "deny", "scanner", time.Hour, nil, "test"); err != nil {
		t.Fatal(err)
	}
	if hit, action, reason := l.CheckIPAction("1.2.3.4"); !hit || action != "deny" || reason != "scanner" {
		t.Fatalf("IP action check=(%v,%q,%q)", hit, action, reason)
	}
	reloaded := New(st)
	if err := reloaded.LoadFromStore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hit, action, _ := reloaded.CheckIPAction("1.2.3.4"); !hit || action != "deny" {
		t.Fatalf("reloaded IP action=(%v,%q)", hit, action)
	}
}
