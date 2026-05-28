package token

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHasherDeterministic(t *testing.T) {
	salt := []byte("01234567890123456789012345678901")
	h := NewHasher(salt)
	a := h.Hash("user-token-abc")
	b := h.Hash("user-token-abc")
	if a != b {
		t.Fatal("hash should be deterministic")
	}
	if len(a) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(a))
	}
	c := h.Hash("user-token-xyz")
	if a == c {
		t.Fatal("different inputs must yield different hashes")
	}
}

func TestHasherEmptyToken(t *testing.T) {
	h := NewHasher([]byte("salt"))
	if got := h.Hash(""); got != "" {
		t.Errorf("empty token must hash to empty, got %q", got)
	}
}

func TestLoadOrCreateSalt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "salt")

	s1, err := LoadOrCreateSalt(p)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if len(s1) < 16 {
		t.Fatalf("salt too short: %d", len(s1))
	}

	// 二次加载应当读出相同 salt
	s2, err := LoadOrCreateSalt(p)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if string(s1) != string(s2) {
		t.Fatal("salt changed between loads")
	}

	// 文件权限 600
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("salt file should be 0600, got %v", info.Mode().Perm())
	}
}

func TestLoadOrCreateSaltInvalidContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "salt")
	if err := os.WriteFile(p, []byte("not-hex"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrCreateSalt(p)
	if err == nil || !strings.Contains(err.Error(), "valid hex") {
		t.Errorf("expected hex error, got %v", err)
	}
}
