package rules

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

func TestDomainWhitelistResolvedIPsReload(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "rules.db"), time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.AddDomainWhitelist("node.example.com", "dynamic"); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListDomainWhitelist()
	if err != nil || len(rows) != 1 {
		t.Fatalf("domain rows=%+v err=%v", rows, err)
	}
	if err := st.SetDomainWhitelistResolution(rows[0].ID, []string{"203.0.113.8", "2001:db8::8"}, ""); err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(st)
	if err := mgr.Reload(); err != nil {
		t.Fatal(err)
	}
	if !mgr.IPWhitelisted("203.0.113.8") || !mgr.IPWhitelisted("2001:db8::8") || mgr.IPWhitelisted("203.0.113.9") {
		t.Fatal("resolved domain IPs were not loaded into whitelist")
	}
	if err := mgr.DeleteDomainWhitelist(rows[0].ID); err != nil {
		t.Fatal(err)
	}
	if mgr.IPWhitelisted("203.0.113.8") {
		t.Fatal("deleted domain IP remained whitelisted")
	}
}

func TestNormalizeDomainAcceptsNodePort(t *testing.T) {
	got, err := normalizeDomain(" Node.Example.com:10030 ")
	if err != nil || got != "node.example.com" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	for _, invalid := range []string{"1.2.3.4", "bad_domain.example", "-bad.example.com"} {
		if _, err := normalizeDomain(invalid); err == nil {
			t.Fatalf("accepted invalid domain %q", invalid)
		}
	}
}

func TestUAWhitelistCaseInsensitiveRegex(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ua-rules.db"), time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := NewManager(st)
	if err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := m.AddUAWhitelist(`^MyClient/\d+\.\d+ \(iOS\)$`, "internal"); err != nil {
		t.Fatal(err)
	}
	if !m.UAWhitelisted("myclient/2.0 (ios)") {
		t.Fatal("expected case-insensitive regex match")
	}
	if m.UAWhitelisted("prefix myclient/2.0 (ios)") || m.UAWhitelisted("Mozilla/5.0") {
		t.Fatal("unrelated UA must not match")
	}
	if err := m.AddUAWhitelist(`[invalid`, "bad"); err == nil {
		t.Fatal("invalid regex must be rejected")
	}
}
