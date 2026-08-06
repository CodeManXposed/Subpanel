package slidingwin

import (
	"testing"
	"time"
)

func TestTimedDistinctSetUsesExactWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	d := NewTimedDistinctSet(time.Hour)
	d.SetClock(func() time.Time { return now })
	d.Add("token-ip", "ua-1")

	now = now.Add(59 * time.Second)
	d.Add("token-ip", "ua-2")
	if got := d.Count("token-ip", time.Minute); got != 2 {
		t.Fatalf("inside 60 seconds: got %d", got)
	}

	now = now.Add(2 * time.Second)
	if got := d.Count("token-ip", time.Minute); got != 1 {
		t.Fatalf("61-second-old UA must expire exactly: got %d", got)
	}
}
