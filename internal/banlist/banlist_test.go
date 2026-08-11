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

func TestCIDRIPBanMatchesReloadsAndRemoves(t *testing.T) {
	l, st := newTestList(t)
	if err := l.AddIPWithAction("192.0.2.123/24", "deny", "range abuse", time.Hour, nil, "test"); err != nil {
		t.Fatal(err)
	}
	if hit, action, reason := l.CheckIPAction("192.0.2.8"); !hit || action != "deny" || reason != "range abuse" {
		t.Fatalf("CIDR action check=(%v,%q,%q)", hit, action, reason)
	}
	if hit, _, _ := l.CheckIPAction("192.0.3.8"); hit {
		t.Fatal("address outside CIDR should not be banned")
	}
	entries := l.Snapshot()
	if len(entries) != 1 || entries[0].Target != "192.0.2.0/24" {
		t.Fatalf("CIDR should be canonicalized in snapshot: %+v", entries)
	}

	reloaded := New(st)
	if err := reloaded.LoadFromStore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hit, action, _ := reloaded.CheckIPAction("192.0.2.254"); !hit || action != "deny" {
		t.Fatalf("reloaded CIDR check=(%v,%q)", hit, action)
	}
	if err := reloaded.RemoveIP("192.0.2.99/24"); err != nil {
		t.Fatal(err)
	}
	if hit, _, _ := reloaded.CheckIPAction("192.0.2.254"); hit {
		t.Fatal("removed CIDR remains banned")
	}
}

func TestIPBanPrefersExactThenMostSpecificCIDR(t *testing.T) {
	l, _ := newTestList(t)
	if err := l.AddIPWithAction("198.51.100.0/24", "deny", "wide", 0, nil, "test"); err != nil {
		t.Fatal(err)
	}
	if err := l.AddIPWithAction("198.51.100.128/25", "fake", "narrow", 0, nil, "test"); err != nil {
		t.Fatal(err)
	}
	if err := l.AddIPWithAction("198.51.100.200", "deny", "exact", 0, nil, "test"); err != nil {
		t.Fatal(err)
	}
	if _, action, reason := l.CheckIPAction("198.51.100.10"); action != "deny" || reason != "wide" {
		t.Fatalf("wide CIDR got action=%q reason=%q", action, reason)
	}
	if _, action, reason := l.CheckIPAction("198.51.100.150"); action != "fake" || reason != "narrow" {
		t.Fatalf("narrow CIDR got action=%q reason=%q", action, reason)
	}
	if _, action, reason := l.CheckIPAction("198.51.100.200"); action != "deny" || reason != "exact" {
		t.Fatalf("exact IP got action=%q reason=%q", action, reason)
	}
}
