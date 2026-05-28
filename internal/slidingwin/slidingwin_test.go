package slidingwin

import (
	"testing"
	"time"
)

func TestCounterSumInWindow(t *testing.T) {
	c := NewCounter(time.Minute, 10*time.Minute)
	base := time.Now().Truncate(time.Minute)
	now := base
	c.SetClock(func() time.Time { return now })

	// 在 t0 加 3
	for i := 0; i < 3; i++ {
		c.Inc("a")
	}
	// 推进 2 分钟,加 5
	now = base.Add(2 * time.Minute)
	for i := 0; i < 5; i++ {
		c.Inc("a")
	}

	// 当前 = base+2min,1min 窗口只能看到 5
	if got := c.Sum("a", time.Minute); got != 5 {
		t.Errorf("1m window: want 5 got %d", got)
	}
	// 5min 窗口看到 3+5=8
	if got := c.Sum("a", 5*time.Minute); got != 8 {
		t.Errorf("5m window: want 8 got %d", got)
	}
}

func TestCounterGC(t *testing.T) {
	c := NewCounter(time.Minute, 2*time.Minute)
	base := time.Now()
	now := base
	c.SetClock(func() time.Time { return now })

	c.Inc("k")
	now = base.Add(10 * time.Minute)
	c.GC()

	if got := c.Sum("k", 5*time.Minute); got != 0 {
		t.Errorf("after GC: want 0 got %d", got)
	}
}

func TestDistinctSet(t *testing.T) {
	d := NewDistinctSet(time.Minute, 10*time.Minute)
	base := time.Now()
	now := base
	d.SetClock(func() time.Time { return now })

	d.Add("token1", "1.1.1.1")
	d.Add("token1", "2.2.2.2")
	d.Add("token1", "1.1.1.1") // 重复

	if got := d.Count("token1", 5*time.Minute); got != 2 {
		t.Errorf("want 2 distinct IPs, got %d", got)
	}

	now = base.Add(3 * time.Minute)
	d.Add("token1", "3.3.3.3")
	if got := d.Count("token1", 5*time.Minute); got != 3 {
		t.Errorf("want 3 distinct IPs, got %d", got)
	}

	// 收窄窗口
	if got := d.Count("token1", 1*time.Minute); got != 1 {
		t.Errorf("1m window want 1, got %d", got)
	}
}
