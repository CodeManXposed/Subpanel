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
	maxWindow  time.Duration
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
	return &Counter{
		bucketSize: bucketSize,
		maxWindow:  maxWindow,
		clock:      time.Now,
	}
}

// SetClock 仅供测试。
func (c *Counter) SetClock(f func() time.Time) { c.clock = f }

func (c *Counter) bucketKey(t time.Time) int64 {
	return t.Unix() / int64(c.bucketSize.Seconds())
}

// Inc 给 key 在当前桶 +1。
func (c *Counter) Inc(key string) { c.IncBy(key, 1) }

func (c *Counter) IncBy(key string, n int) {
	v, _ := c.data.LoadOrStore(key, &counterBuckets{buckets: map[int64]int{}})
	cb := v.(*counterBuckets)
	cb.mu.Lock()
	cb.buckets[c.bucketKey(c.clock())] += n
	cb.mu.Unlock()
}

// Sum 返回 key 在最近 window 内的总数。
func (c *Counter) Sum(key string, window time.Duration) int {
	if window > c.maxWindow {
		window = c.maxWindow
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
	cutoff := c.bucketKey(c.clock().Add(-c.maxWindow))
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
	maxWindow  time.Duration
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
	return &DistinctSet{
		bucketSize: bucketSize,
		maxWindow:  maxWindow,
		clock:      time.Now,
	}
}

func (d *DistinctSet) SetClock(f func() time.Time) { d.clock = f }

func (d *DistinctSet) bucketKey(t time.Time) int64 {
	return t.Unix() / int64(d.bucketSize.Seconds())
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
	if window > d.maxWindow {
		window = d.maxWindow
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
	cutoff := d.bucketKey(d.clock().Add(-d.maxWindow))
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
