// Package banlist 在内存中维护 IP 与 Token 黑名单，启动从 store 加载，运行时增量更新。
package banlist

import (
	"context"
	"sync"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

type entry struct {
	expires time.Time // 零值 = 永久
	reason  string
	action  string // fake|deny；IP 固定 fake
}

type List struct {
	mu     sync.RWMutex
	ips    map[string]entry
	tokens map[string]entry
	st     *store.Store
}

func New(st *store.Store) *List {
	return &List{
		ips:    map[string]entry{},
		tokens: map[string]entry{},
		st:     st,
	}
}

// LoadFromStore 启动时调用。
func (l *List) LoadFromStore(ctx context.Context) error {
	bans, err := l.st.ListActiveBans(ctx)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, b := range bans {
		e := entry{reason: b.Reason, action: normalizeAction(b.Action)}
		if b.ExpiresTS != nil {
			e.expires = *b.ExpiresTS
		}
		switch b.Kind {
		case "ip":
			e.action = "fake"
			l.ips[b.Target] = e
		case "token":
			l.tokens[b.Target] = e
		}
	}
	return nil
}

func normalizeAction(action string) string {
	if action == "deny" {
		return "deny"
	}
	return "fake"
}

// CheckIP 检查 IP 是否封禁,返回 (banned, reason)。过期会被惰性清理。
func (l *List) CheckIP(ip string) (bool, string) {
	l.mu.RLock()
	e, ok := l.ips[ip]
	l.mu.RUnlock()
	if !ok {
		return false, ""
	}
	if !e.expires.IsZero() && time.Now().After(e.expires) {
		l.mu.Lock()
		delete(l.ips, ip)
		l.mu.Unlock()
		return false, ""
	}
	return true, e.reason
}

// AddIP 立即在内存生效并落库。
func (l *List) AddIP(ip, reason string, ttl time.Duration, ruleTags []string, createdBy string) error {
	now := time.Now()
	e := entry{reason: reason, action: "fake"}
	var expPtr *time.Time
	if ttl > 0 {
		e.expires = now.Add(ttl)
		expPtr = &e.expires
	}
	l.mu.Lock()
	l.ips[ip] = e
	l.mu.Unlock()
	return l.st.AddBan(store.Ban{
		Kind:      "ip",
		Target:    ip,
		Reason:    reason,
		RuleTags:  ruleTags,
		CreatedTS: now,
		ExpiresTS: expPtr,
		CreatedBy: createdBy,
	})
}

// CheckToken 检查 Token 是否封禁，返回 (banned, action, reason)。
func (l *List) CheckToken(token string) (bool, string, string) {
	l.mu.RLock()
	e, ok := l.tokens[token]
	l.mu.RUnlock()
	if !ok {
		return false, "", ""
	}
	if !e.expires.IsZero() && time.Now().After(e.expires) {
		l.mu.Lock()
		delete(l.tokens, token)
		l.mu.Unlock()
		return false, "", ""
	}
	return true, normalizeAction(e.action), e.reason
}

// AddToken 立即在内存生效并落库。
func (l *List) AddToken(target, action, reason string, ttl time.Duration, createdBy string) error {
	now := time.Now()
	action = normalizeAction(action)
	e := entry{reason: reason, action: action}
	var expPtr *time.Time
	if ttl > 0 {
		e.expires = now.Add(ttl)
		expPtr = &e.expires
	}
	l.mu.Lock()
	l.tokens[target] = e
	l.mu.Unlock()
	return l.st.AddBan(store.Ban{
		Kind:      "token",
		Target:    target,
		Reason:    reason,
		CreatedTS: now,
		ExpiresTS: expPtr,
		CreatedBy: createdBy,
		Action:    action,
	})
}

func (l *List) RemoveIP(ip string) error {
	l.mu.Lock()
	delete(l.ips, ip)
	l.mu.Unlock()
	return l.st.RemoveBan("ip", ip)
}

func (l *List) RemoveToken(target string) error {
	l.mu.Lock()
	delete(l.tokens, target)
	l.mu.Unlock()
	return l.st.RemoveBan("token", target)
}

// Snapshot 给 webui/API 统计当前内存中生效的 IP 与 Token 封禁。
type Entry struct {
	Kind    string    `json:"kind"`
	Target  string    `json:"target"`
	Reason  string    `json:"reason"`
	Expires time.Time `json:"expires"`
	Action  string    `json:"action"`
}

func (l *List) Snapshot() []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Entry, 0, len(l.ips)+len(l.tokens))
	for k, e := range l.ips {
		if !e.expires.IsZero() && time.Now().After(e.expires) {
			continue
		}
		out = append(out, Entry{Kind: "ip", Target: k, Reason: e.reason, Expires: e.expires, Action: "fake"})
	}
	for k, e := range l.tokens {
		if !e.expires.IsZero() && time.Now().After(e.expires) {
			continue
		}
		out = append(out, Entry{Kind: "token", Target: k, Reason: e.reason, Expires: e.expires, Action: normalizeAction(e.action)})
	}
	return out
}
