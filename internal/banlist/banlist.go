// Package banlist 内存里维护 IP 黑名单,启动从 store 加载,运行时增量更新。
// 注:token 黑名单已废弃(v2board 重置 token 后 hash 失效,封禁无意义)。
// store 里历史 token 行不会再加载到内存,但保留数据库行避免破坏老备份。
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
}

type List struct {
	mu  sync.RWMutex
	ips map[string]entry
	st  *store.Store
}

func New(st *store.Store) *List {
	return &List{
		ips: map[string]entry{},
		st:  st,
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
		if b.Kind != "ip" {
			continue // token 类型已废弃,忽略老数据
		}
		e := entry{reason: b.Reason}
		if b.ExpiresTS != nil {
			e.expires = *b.ExpiresTS
		}
		l.ips[b.Target] = e
	}
	return nil
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
	e := entry{reason: reason}
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

func (l *List) RemoveIP(ip string) error {
	l.mu.Lock()
	delete(l.ips, ip)
	l.mu.Unlock()
	return l.st.RemoveBan("ip", ip)
}

// Snapshot 给 webui 用,只返 IP。
type Entry struct {
	Kind    string    `json:"kind"`
	Target  string    `json:"target"`
	Reason  string    `json:"reason"`
	Expires time.Time `json:"expires"`
}

func (l *List) Snapshot() []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Entry, 0, len(l.ips))
	for k, e := range l.ips {
		if !e.expires.IsZero() && time.Now().After(e.expires) {
			continue
		}
		out = append(out, Entry{Kind: "ip", Target: k, Reason: e.reason, Expires: e.expires})
	}
	return out
}
