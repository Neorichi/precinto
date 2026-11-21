package fakeplatform_test

import (
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
)

var epoch = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

// hasMono reports whether t carries a monotonic clock reading (time.Time
// String documents the trailing "m=±<value>" field).
func hasMono(t time.Time) bool { return strings.Contains(t.String(), " m=") }

func wantReadings(t *testing.T, c *fakeplatform.Clock, wall time.Time, mono time.Duration) {
	t.Helper()
	if got := c.Now(); !got.Equal(wall) {
		t.Errorf("Now = %v, want %v", got, wall)
	}
	if got := c.Mono(); got != mono {
		t.Errorf("Mono = %v, want %v", got, mono)
	}
}

func TestNewClock(t *testing.T) {
	var _ platform.Clock = fakeplatform.NewClock(epoch)

	c := fakeplatform.NewClock(epoch)
	wantReadings(t, c, epoch, 0)
	if got := c.Now(); got.Location() != time.UTC || hasMono(got) {
		t.Errorf("Now = %v (location %v)", got, got.Location())
	}

	now := time.Now()
	if !hasMono(now) {
		t.Skip("time.Now carries no monotonic reading on this platform")
	}
	c = fakeplatform.NewClock(now)
	if got := c.Now(); hasMono(got) || !got.Equal(now) {
		t.Errorf("Now = %v, want %v without a monotonic reading", got, now.Round(0))
	}
}

func TestNewClockKeepsTheLocation(t *testing.T) {
	loc := time.FixedZone("UTC+1", 3600)
	start := time.Date(2026, 3, 29, 1, 30, 0, 0, loc)
	c := fakeplatform.NewClock(start)
	c.Advance(time.Hour)
	if got := c.Now(); got.Location() != loc || !got.Equal(start.Add(time.Hour)) {
		t.Errorf("Now = %v, want %v", got, start.Add(time.Hour))
	}
}

func TestZeroValueClock(t *testing.T) {
	var c fakeplatform.Clock
	if !c.Now().IsZero() || c.Mono() != 0 {
		t.Fatalf("zero Clock reads %v, %v", c.Now(), c.Mono())
	}
	c.Advance(time.Second)
	wantReadings(t, &c, time.Time{}.Add(time.Second), time.Second)
}

// TestClockOperations checks the effect of each operation on both readings
// as WatchJumps-style deltas: wall delta and monotonic delta.
func TestClockOperations(t *testing.T) {
	for _, c := range []struct {
		name       string
		op         func(*fakeplatform.Clock)
		wall, mono time.Duration
	}{
		{"Advance", func(c *fakeplatform.Clock) { c.Advance(90 * time.Second) }, 90 * time.Second, 90 * time.Second},
		{"Advance zero", func(c *fakeplatform.Clock) { c.Advance(0) }, 0, 0},
		{"Advance negative is a no-op", func(c *fakeplatform.Clock) { c.Advance(-time.Hour) }, 0, 0},
		{"StepWall forward", func(c *fakeplatform.Clock) { c.StepWall(time.Hour) }, time.Hour, 0},
		{"StepWall backward", func(c *fakeplatform.Clock) { c.StepWall(-2 * time.Hour) }, -2 * time.Hour, 0},
		{"StepWall zero", func(c *fakeplatform.Clock) { c.StepWall(0) }, 0, 0},
		{"Sleep", func(c *fakeplatform.Clock) { c.Sleep(8 * time.Hour) }, 8 * time.Hour, 0},
		{"Sleep zero", func(c *fakeplatform.Clock) { c.Sleep(0) }, 0, 0},
		{"Sleep negative is a no-op", func(c *fakeplatform.Clock) { c.Sleep(-time.Hour) }, 0, 0},
		{"sequence", func(c *fakeplatform.Clock) {
			c.Advance(time.Minute)
			c.Sleep(time.Hour)
			c.StepWall(-30 * time.Minute)
			c.Advance(time.Second)
		}, time.Minute + time.Hour - 30*time.Minute + time.Second, time.Minute + time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			clk := fakeplatform.NewClock(epoch)
			clk.Advance(time.Hour) // a non-zero starting point for both readings
			wall0, mono0 := clk.Now(), clk.Mono()
			c.op(clk)
			if got := clk.Now().Sub(wall0); got != c.wall {
				t.Errorf("wall moved %v, want %v", got, c.wall)
			}
			if got := clk.Mono() - mono0; got != c.mono {
				t.Errorf("monotonic moved %v, want %v", got, c.mono)
			}
			if hasMono(clk.Now()) {
				t.Error("Now carries a monotonic reading")
			}
		})
	}
}

// TestSleepNeverBlocks: Sleep simulates the machine sleeping, so it returns
// at once and a test that only calls Sleep cannot deadlock.
func TestSleepNeverBlocks(t *testing.T) {
	c := fakeplatform.NewClock(epoch)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Sleep(24 * time.Hour)
		c.Sleep(time.Nanosecond)
		c.Sleep(math.MaxInt64)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Sleep blocked the caller")
	}
	if c.Mono() != 0 {
		t.Errorf("Sleep moved the monotonic reading to %v", c.Mono())
	}
}

func TestMonoSaturatesInsteadOfWrapping(t *testing.T) {
	c := fakeplatform.NewClock(epoch)
	c.Advance(math.MaxInt64 - 10)
	c.Advance(time.Hour)
	c.Advance(1)
	if got := c.Mono(); got != math.MaxInt64 {
		t.Errorf("Mono = %d, want the largest Duration", got)
	}
}

func TestClockConcurrentUse(t *testing.T) {
	c := fakeplatform.NewClock(epoch)
	const writers, steps = 8, 400
	stop := make(chan struct{})
	backwards := make(chan time.Duration, 1)
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			last := c.Mono()
			for {
				select {
				case <-stop:
					return
				default:
				}
				m := c.Mono()
				if m < last {
					select {
					case backwards <- m - last:
					default:
					}
				}
				last = m
				_ = c.Now()
			}
		}()
	}
	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range steps {
				c.Advance(time.Millisecond)
				c.StepWall(time.Second)
				c.StepWall(-time.Second)
				c.Sleep(time.Microsecond)
			}
		}()
	}
	wg.Wait()
	close(stop)
	readers.Wait()
	select {
	case d := <-backwards:
		t.Fatalf("Mono ran backwards by %v", d)
	default:
	}
	n := time.Duration(writers * steps)
	wantReadings(t, c, epoch.Add(n*(time.Millisecond+time.Microsecond)), n*time.Millisecond)
}
