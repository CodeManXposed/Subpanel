// Package banlist 在内存中维护 IP 与 Token 黑名单，启动从 store 加载，运行时增量更新。
package banlist

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/huabanmao168/SubPanel/internal/store"
)

type entry struct {
	expires time.Time // 零值 = 永久
	reason  string
	action  string // fake|deny
}

type prefixEntry struct {
	prefix netip.Prefix
	entry  entry
}

type List struct {
	mu       sync.RWMutex
	ips      map[string]entry
	prefixes map[string]prefixEntry
	tokens   map[string]entry
	st       *store.Store
}

func New(st *store.Store) *List {
	return &List{
		ips:      map[string]entry{},
		prefixes: map[string]prefixEntry{},
		tokens:   map[string]entry{},
		st:       st,
	}
}

func normalizeIPTarget(target string) (string, netip.Prefix, bool, error) {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "/") {
		prefix, err := netip.ParsePrefix(target)
		if err != nil {
			return "", netip.Prefix{}, false, fmt.Errorf("invalid IP/CIDR %q", target)
		}
		prefix = prefix.Masked()
		return prefix.String(), prefix, true, nil
	}
	addr, err := netip.ParseAddr(target)
	if err != nil {
		return "", netip.Prefix{}, false, fmt.Errorf("invalid IP/CIDR %q", target)
	}
	return addr.Unmap().String(), netip.Prefix{}, false, nil
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
			target, prefix, isPrefix, parseErr := normalizeIPTarget(b.Target)
			if parseErr != nil {
				// 旧数据库可能存在手工写入的无效目标；跳过它，避免阻断服务启动。
				continue
			}
			if isPrefix {
				l.prefixes[target] = prefixEntry{prefix: prefix, entry: e}
			} else {
				l.ips[target] = e
			}
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

// CheckIP 检查 IP 是否封禁,保留旧签名给只关心命中的调用方。
func (l *List) CheckIP(ip string) (bool, string) {
	hit, _, reason := l.CheckIPAction(ip)
	return hit, reason
}

// CheckIPAction 检查 IP 黑名单动作,返回 (banned, action, reason)。
// 过期记录会被惰性清理。
func (l *List) CheckIPAction(ip string) (bool, string, string) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false, "", ""
	}
	addr = addr.Unmap()
	now := time.Now()

	l.mu.RLock()
	e, ok := l.ips[addr.String()]
	l.mu.RUnlock()
	if ok && !e.expires.IsZero() && now.After(e.expires) {
		l.mu.Lock()
		delete(l.ips, addr.String())
		l.mu.Unlock()
		ok = false
	}
	if ok {
		return true, normalizeAction(e.action), e.reason
	}

	// 网段命中时选择最具体的前缀；精确 IP 始终优先于 CIDR。
	bestBits := -1
	bestTarget := ""
	var best entry
	var expired []string
	l.mu.RLock()
	for target, candidate := range l.prefixes {
		if !candidate.entry.expires.IsZero() && now.After(candidate.entry.expires) {
			expired = append(expired, target)
			continue
		}
		if !candidate.prefix.Contains(addr) {
			continue
		}
		bits := candidate.prefix.Bits()
		if bits > bestBits || (bits == bestBits && (bestTarget == "" || target < bestTarget)) {
			bestBits = bits
			bestTarget = target
			best = candidate.entry
		}
	}
	l.mu.RUnlock()
	if len(expired) > 0 {
		l.mu.Lock()
		for _, target := range expired {
			if candidate, exists := l.prefixes[target]; exists && !candidate.entry.expires.IsZero() && now.After(candidate.entry.expires) {
				delete(l.prefixes, target)
			}
		}
		l.mu.Unlock()
	}
	if bestBits >= 0 {
		return true, normalizeAction(best.action), best.reason
	}
	return false, "", ""
}

// AddIP 保留旧调用语义：未指定动作时默认投毒。
func (l *List) AddIP(ip, reason string, ttl time.Duration, ruleTags []string, createdBy string) error {
	return l.AddIPWithAction(ip, "fake", reason, ttl, ruleTags, createdBy)
}

// AddIPWithAction 立即在内存生效并落库。
func (l *List) AddIPWithAction(ip, action, reason string, ttl time.Duration, ruleTags []string, createdBy string) error {
	target, prefix, isPrefix, err := normalizeIPTarget(ip)
	if err != nil {
		return err
	}
	now := time.Now()
	action = normalizeAction(action)
	e := entry{reason: reason, action: action}
	var expPtr *time.Time
	if ttl > 0 {
		e.expires = now.Add(ttl)
		expPtr = &e.expires
	}
	l.mu.Lock()
	if isPrefix {
		l.prefixes[target] = prefixEntry{prefix: prefix, entry: e}
	} else {
		l.ips[target] = e
	}
	l.mu.Unlock()
	return l.st.AddBan(store.Ban{
		Kind:      "ip",
		Target:    target,
		Reason:    reason,
		RuleTags:  ruleTags,
		CreatedTS: now,
		ExpiresTS: expPtr,
		CreatedBy: createdBy,
		Action:    action,
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
	target, _, isPrefix, err := normalizeIPTarget(ip)
	if err != nil {
		return err
	}
	l.mu.Lock()
	if isPrefix {
		delete(l.prefixes, target)
	} else {
		delete(l.ips, target)
	}
	l.mu.Unlock()
	return l.st.RemoveBan("ip", target)
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
	out := make([]Entry, 0, len(l.ips)+len(l.prefixes)+len(l.tokens))
	for k, e := range l.ips {
		if !e.expires.IsZero() && time.Now().After(e.expires) {
			continue
		}
		out = append(out, Entry{Kind: "ip", Target: k, Reason: e.reason, Expires: e.expires, Action: normalizeAction(e.action)})
	}
	for k, candidate := range l.prefixes {
		e := candidate.entry
		if !e.expires.IsZero() && time.Now().After(e.expires) {
			continue
		}
		out = append(out, Entry{Kind: "ip", Target: k, Reason: e.reason, Expires: e.expires, Action: normalizeAction(e.action)})
	}
	for k, e := range l.tokens {
		if !e.expires.IsZero() && time.Now().After(e.expires) {
			continue
		}
		out = append(out, Entry{Kind: "token", Target: k, Reason: e.reason, Expires: e.expires, Action: normalizeAction(e.action)})
	}
	return out
}
