// Package slidingwin 实现一组按时间分桶的滑动窗口计数器。
//
// 设计:
//   - 每个桶代表一段时间(默认 1 分钟),value 可以是 int 计数或字符串集合
//   - 查询时把 [now-window, now] 范围内的桶聚合
//   - 老桶由后台 goroutine 周期清理
//
// 提供两种类型:
//   - Counter: 计数累加
//   - DistinctSet: 不同值的集合(用于"某 key 在窗口内出现了多少不同 value")
//
// 线程安全。
package slidingwin

import (
	"sync"
	"sync/atomic"
	"time"
)

const defaultBucketSize = time.Minute

// =========================== Counter ===========================

type counterBuckets struct {
	mu      sync.Mutex
	buckets map[int64]int // bucketStartUnix -> count
}

type Counter struct {
	bucketSize time.Duration
	maxWindow  atomic.Int64
	data       sync.Map // key -> *counterBuckets
	clock      func() time.Time
}

func NewCounter(bucketSize, maxWindow time.Duration) *Counter {
	if bucketSize <= 0 {
		bucketSize = defaultBucketSize
	}
	if maxWindow < bucketSize {
		maxWindow = bucketSize
	}
	c := &Counter{
		bucketSize: bucketSize,
		clock:      time.Now,
	}
	c.maxWindow.Store(int64(maxWindow))
	return c
}

// SetClock 仅供测试。
func (c *Counter) SetClock(f func() time.Time) { c.clock = f }

// SetMaxWindow 热更新保留窗口。缩短后由下一次 GC 释放旧桶。
func (c *Counter) SetMaxWindow(window time.Duration) {
	if window < c.bucketSize {
		window = c.bucketSize
	}
	c.maxWindow.Store(int64(window))
}

func (c *Counter) bucketKey(t time.Time) int64 {
	return t.Unix() / int64(c.bucketSize.Seconds())
}

// Inc 给 key 在当前桶 +1。
func (c *Counter) Inc(key string) { c.IncBy(key, 1) }

// Delete 清掉某个 key 的所有桶,用于"重置滑窗"运维操作。
func (c *Counter) Delete(key string) {
	c.data.Delete(key)
}

// Reset 清空所有 key,用于"清空日志"等全局归零运维。
func (c *Counter) Reset() {
	c.data.Range(func(k, _ any) bool { c.data.Delete(k); return true })
}

func (c *Counter) IncBy(key string, n int) {
	v, _ := c.data.LoadOrStore(key, &counterBuckets{buckets: map[int64]int{}})
	cb := v.(*counterBuckets)
	cb.mu.Lock()
	cb.buckets[c.bucketKey(c.clock())] += n
	cb.mu.Unlock()
}

// Sum 返回 key 在最近 window 内的总数。
func (c *Counter) Sum(key string, window time.Duration) int {
	maxWindow := time.Duration(c.maxWindow.Load())
	if window > maxWindow {
		window = maxWindow
	}
	v, ok := c.data.Load(key)
	if !ok {
		return 0
	}
	cb := v.(*counterBuckets)
	now := c.clock()
	cutoff := c.bucketKey(now.Add(-window))
	currentBucket := c.bucketKey(now)
	cb.mu.Lock()
	defer cb.mu.Unlock()
	total := 0
	for b, n := range cb.buckets {
		if b >= cutoff && b <= currentBucket {
			total += n
		}
	}
	return total
}

// GC 清理超出 maxWindow 的桶。
func (c *Counter) GC() {
	maxWindow := time.Duration(c.maxWindow.Load())
	cutoff := c.bucketKey(c.clock().Add(-maxWindow))
	c.data.Range(func(k, v any) bool {
		cb := v.(*counterBuckets)
		cb.mu.Lock()
		for b := range cb.buckets {
			if b < cutoff {
				delete(cb.buckets, b)
			}
		}
		empty := len(cb.buckets) == 0
		cb.mu.Unlock()
		if empty {
			c.data.Delete(k)
		}
		return true
	})
}

// =========================== DistinctSet ===========================

type distinctBuckets struct {
	mu      sync.Mutex
	buckets map[int64]map[string]struct{}
}

type DistinctSet struct {
	bucketSize time.Duration
	maxWindow  atomic.Int64
	data       sync.Map
	clock      func() time.Time
}

func NewDistinctSet(bucketSize, maxWindow time.Duration) *DistinctSet {
	if bucketSize <= 0 {
		bucketSize = defaultBucketSize
	}
	if maxWindow < bucketSize {
		maxWindow = bucketSize
	}
	d := &DistinctSet{
		bucketSize: bucketSize,
		clock:      time.Now,
	}
	d.maxWindow.Store(int64(maxWindow))
	return d
}

func (d *DistinctSet) SetClock(f func() time.Time) { d.clock = f }

// SetMaxWindow 热更新保留窗口。缩短后由下一次 GC 释放旧桶。
func (d *DistinctSet) SetMaxWindow(window time.Duration) {
	if window < d.bucketSize {
		window = d.bucketSize
	}
	d.maxWindow.Store(int64(window))
}

func (d *DistinctSet) bucketKey(t time.Time) int64 {
	return t.Unix() / int64(d.bucketSize.Seconds())
}

// Delete 清掉某个 key 的所有桶,用于"重置滑窗"运维操作。
func (d *DistinctSet) Delete(key string) {
	d.data.Delete(key)
}

// Reset 清空所有 key。
func (d *DistinctSet) Reset() {
	d.data.Range(func(k, _ any) bool { d.data.Delete(k); return true })
}

// Items 返回 key 在所有桶里出现过的 distinct val 列表(全窗口,不过滤过期)。
// 用于"反查"运维:比如清 token 时顺手清掉它触达过的 IP。
func (d *DistinctSet) Items(key string) []string {
	v, ok := d.data.Load(key)
	if !ok {
		return nil
	}
	db := v.(*distinctBuckets)
	db.mu.Lock()
	defer db.mu.Unlock()
	uniq := map[string]struct{}{}
	for _, set := range db.buckets {
		for k := range set {
			uniq[k] = struct{}{}
		}
	}
	out := make([]string, 0, len(uniq))
	for k := range uniq {
		out = append(out, k)
	}
	return out
}

// Add 给 key 记录一次 val。
func (d *DistinctSet) Add(key, val string) {
	v, _ := d.data.LoadOrStore(key, &distinctBuckets{buckets: map[int64]map[string]struct{}{}})
	db := v.(*distinctBuckets)
	db.mu.Lock()
	bk := d.bucketKey(d.clock())
	set, ok := db.buckets[bk]
	if !ok {
		set = map[string]struct{}{}
		db.buckets[bk] = set
	}
	set[val] = struct{}{}
	db.mu.Unlock()
}

// Count 返回 key 在最近 window 内 distinct val 的数量。
func (d *DistinctSet) Count(key string, window time.Duration) int {
	maxWindow := time.Duration(d.maxWindow.Load())
	if window > maxWindow {
		window = maxWindow
	}
	v, ok := d.data.Load(key)
	if !ok {
		return 0
	}
	db := v.(*distinctBuckets)
	now := d.clock()
	cutoff := d.bucketKey(now.Add(-window))
	currentBucket := d.bucketKey(now)
	db.mu.Lock()
	defer db.mu.Unlock()
	merged := map[string]struct{}{}
	for b, set := range db.buckets {
		if b >= cutoff && b <= currentBucket {
			for v := range set {
				merged[v] = struct{}{}
			}
		}
	}
	return len(merged)
}

func (d *DistinctSet) GC() {
	maxWindow := time.Duration(d.maxWindow.Load())
	cutoff := d.bucketKey(d.clock().Add(-maxWindow))
	d.data.Range(func(k, v any) bool {
		db := v.(*distinctBuckets)
		db.mu.Lock()
		for b := range db.buckets {
			if b < cutoff {
				delete(db.buckets, b)
			}
		}
		empty := len(db.buckets) == 0
		db.mu.Unlock()
		if empty {
			d.data.Delete(k)
		}
		return true
	})
}

// =========================== background GC ===========================

// RunGC 启动后台清理协程,interval 建议 = bucketSize。
func RunGC(stop <-chan struct{}, interval time.Duration, targets ...interface{ GC() }) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				for _, x := range targets {
					x.GC()
				}
			case <-stop:
				return
			}
		}
	}()
}
