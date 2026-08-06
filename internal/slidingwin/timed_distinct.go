package slidingwin

import (
	"sync"
	"sync/atomic"
	"time"
)

// TimedDistinctSet 按每个 value 的最后出现时间计算精确滚动窗口，
// 适用于 60 秒等不能容忍分桶边界误差的不同值计数。
type TimedDistinctSet struct {
	mu        sync.Mutex
	data      map[string]map[string]int64
	maxWindow atomic.Int64
	clock     func() time.Time
}

func NewTimedDistinctSet(maxWindow time.Duration) *TimedDistinctSet {
	if maxWindow <= 0 {
		maxWindow = time.Hour
	}
	d := &TimedDistinctSet{data: make(map[string]map[string]int64), clock: time.Now}
	d.maxWindow.Store(int64(maxWindow))
	return d
}

func (d *TimedDistinctSet) SetClock(f func() time.Time) { d.clock = f }

func (d *TimedDistinctSet) SetMaxWindow(window time.Duration) {
	if window <= 0 {
		window = time.Second
	}
	d.maxWindow.Store(int64(window))
}

func (d *TimedDistinctSet) Add(key, value string) {
	d.mu.Lock()
	values := d.data[key]
	if values == nil {
		values = make(map[string]int64)
		d.data[key] = values
	}
	values[value] = d.clock().UnixNano()
	d.mu.Unlock()
}

func (d *TimedDistinctSet) Count(key string, window time.Duration) int {
	maxWindow := time.Duration(d.maxWindow.Load())
	if window > maxWindow {
		window = maxWindow
	}
	cutoff := d.clock().Add(-window).UnixNano()
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, seen := range d.data[key] {
		if seen >= cutoff {
			n++
		}
	}
	return n
}

func (d *TimedDistinctSet) Delete(key string) {
	d.mu.Lock()
	delete(d.data, key)
	d.mu.Unlock()
}

func (d *TimedDistinctSet) Reset() {
	d.mu.Lock()
	d.data = make(map[string]map[string]int64)
	d.mu.Unlock()
}

func (d *TimedDistinctSet) GC() {
	cutoff := d.clock().Add(-time.Duration(d.maxWindow.Load())).UnixNano()
	d.mu.Lock()
	defer d.mu.Unlock()
	for key, values := range d.data {
		for value, seen := range values {
			if seen < cutoff {
				delete(values, value)
			}
		}
		if len(values) == 0 {
			delete(d.data, key)
		}
	}
}
