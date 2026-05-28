package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const baseYML = `
listen: "127.0.0.1:8443"
admin_listen: "127.0.0.1:9090"
hmac_salt_file: "/tmp/salt"
storage:
  sqlite_path: "/tmp/x.db"
tenants:
  - name: t1
    host: sub.example.com
    subscribe_path: /sub/cat
    upstream: http://127.0.0.1:7001
actions:
  yellow: slow
  orange: fake
  red: deny
`

func TestLoadValid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	if err := os.WriteFile(p, []byte(baseYML), 0644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8443" {
		t.Errorf("listen: %s", c.Listen)
	}
	if len(c.Tenants) != 1 {
		t.Errorf("tenants: %d", len(c.Tenants))
	}
	if c.Tenants[0].SubscribePath != "/sub/cat" {
		t.Errorf("subscribe_path: %q", c.Tenants[0].SubscribePath)
	}
	if c.Storage.BatchFlushSize == 0 {
		t.Error("defaults not applied")
	}
	if c.Faker.NodeCount == 0 {
		t.Error("faker defaults not applied")
	}
}

func TestDurationParseDays(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	yml := `
listen: ":1"
hmac_salt_file: "/tmp/salt"
storage:
  sqlite_path: "/tmp/x.db"
  retention:
    events: 7d
tenants:
  - name: t
    host: h.example.com
    subscribe_path: /x
    upstream: http://127.0.0.1:1
actions:
  yellow: pass
  orange: pass
  red: pass
`
	_ = os.WriteFile(p, []byte(yml), 0644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage.Retention.Events.Std() != 7*24*time.Hour {
		t.Errorf("retention: %v", c.Storage.Retention.Events.Std())
	}
}

func TestLoadEmptyTenantsAllowed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	yml := `
listen: ":1"
hmac_salt_file: "/tmp/salt"
storage:
  sqlite_path: "/tmp/x.db"
actions: {yellow: pass, orange: pass, red: pass}
`
	_ = os.WriteFile(p, []byte(yml), 0644)
	_, err := Load(p)
	if err != nil {
		t.Errorf("空 tenants 应允许(仅起管理面),got err: %v", err)
	}
}

func TestLoadMissingSubscribePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	yml := `
listen: ":1"
hmac_salt_file: "/tmp/salt"
storage:
  sqlite_path: "/tmp/x.db"
tenants:
  - {name: a, host: h.example.com, upstream: http://127.0.0.1:1}
actions: {yellow: pass, orange: pass, red: pass}
`
	_ = os.WriteFile(p, []byte(yml), 0644)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "subscribe_path") {
		t.Errorf("应报 subscribe_path 缺失,实际: %v", err)
	}
}

func TestLoadDuplicateHostPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	yml := `
listen: ":1"
hmac_salt_file: "/tmp/salt"
storage:
  sqlite_path: "/tmp/x.db"
tenants:
  - {name: a, host: h.example.com, subscribe_path: /sub/x, upstream: http://127.0.0.1:1}
  - {name: b, host: h.example.com, subscribe_path: /sub/x, upstream: http://127.0.0.1:2}
actions: {yellow: pass, orange: pass, red: pass}
`
	_ = os.WriteFile(p, []byte(yml), 0644)
	_, err := Load(p)
	if err == nil {
		t.Error("expected duplicate host+path error")
	}
}

func TestLoadSameHostDifferentPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	yml := `
listen: ":1"
hmac_salt_file: "/tmp/salt"
storage:
  sqlite_path: "/tmp/x.db"
tenants:
  - {name: cat, host: h.example.com, subscribe_path: /sub/cat, upstream: http://127.0.0.1:1}
  - {name: dog, host: h.example.com, subscribe_path: /sub/dog, upstream: http://127.0.0.1:2}
actions: {yellow: pass, orange: pass, red: pass}
`
	_ = os.WriteFile(p, []byte(yml), 0644)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("同 host 不同 path 应被接受: %v", err)
	}
	if len(c.Tenants) != 2 {
		t.Errorf("tenants: %d", len(c.Tenants))
	}
}

func TestLoadRejectLegacyPaths(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	yml := `
listen: ":1"
hmac_salt_file: "/tmp/salt"
storage:
  sqlite_path: "/tmp/x.db"
tenants:
  - {name: a, host: h.example.com, subscribe_path: /sub/x, upstream: http://127.0.0.1:1}
paths:
  subscribe: ["/api/v1/client/subscribe"]
actions: {yellow: pass, orange: pass, red: pass}
`
	_ = os.WriteFile(p, []byte(yml), 0644)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "paths.subscribe") {
		t.Errorf("应拒绝旧 paths.subscribe,实际: %v", err)
	}
}

func TestTenantByPath(t *testing.T) {
	c := &Config{Tenants: []Tenant{
		{Name: "cat", SubscribePath: "/sub/cat", Upstream: "x"},
		{Name: "dog", SubscribePath: "/sub/dog", Upstream: "y"},
	}}
	if got, ok := c.TenantByPath("/sub/cat"); !ok || got == nil || got.Name != "cat" {
		t.Errorf("cat 未匹配: got=%+v ok=%v", got, ok)
	}
	// 尾斜杠归一
	if got, ok := c.TenantByPath("/sub/dog/"); !ok || got == nil || got.Name != "dog" {
		t.Errorf("dog 未匹配(尾斜杠): got=%+v ok=%v", got, ok)
	}
	// 子路径前缀命中
	if got, ok := c.TenantByPath("/sub/cat/extra/token"); !ok || got == nil || got.Name != "cat" {
		t.Errorf("cat 子路径前缀未匹配: got=%+v ok=%v", got, ok)
	}
	// 完全无关路径不匹配
	if got, ok := c.TenantByPath("/sub/other"); ok || got != nil {
		t.Errorf("路径不匹配时应返回 nil/false: got=%+v ok=%v", got, ok)
	}
	// Host 头不参与:重复调用,任何 Host 表现一致(此 API 已无 host 参数)
	if got, ok := c.TenantByPath("/sub/cat"); !ok || got.Name != "cat" {
		t.Errorf("Host 不应影响路由")
	}
}

func TestTenantByPathLongestPrefix(t *testing.T) {
	c := &Config{Tenants: []Tenant{
		{Name: "a", SubscribePath: "/sub", Upstream: "x"},
		{Name: "b", SubscribePath: "/sub/cat", Upstream: "y"},
	}}
	if got, ok := c.TenantByPath("/sub/cat/x"); !ok || got.Name != "b" {
		t.Errorf("最长前缀应命中 b, got=%+v", got)
	}
	if got, ok := c.TenantByPath("/sub/dog"); !ok || got.Name != "a" {
		t.Errorf("短前缀兜底应命中 a, got=%+v", got)
	}
}
