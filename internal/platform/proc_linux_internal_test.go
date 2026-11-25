//go:build linux

package platform

import (
	"errors"
	"os"
	"testing"
	"time"
)

// D66: a wall-clock step moves /proc/stat btime, but a measured identity
// never changes; StartTime follows the current btime.
func TestStartUSIgnoresBtime(t *testing.T) {
	a, _, err := sysIdentifyState(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	bt, err := sysBootTimeUS()
	if err != nil {
		t.Fatal(err)
	}
	restore := setBootTime(func() (int64, error) { return bt + 1_000_000, nil }) // a 1 s step
	defer restore()
	b, _, err := sysIdentifyState(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("identity changed across a btime step: %v → %v", a, b)
	}
	if got, want := startTime(b), time.UnixMicro(bt+1_000_000+b.StartUS); !got.Equal(want) {
		t.Fatalf("StartTime = %v, want %v", got, want)
	}
	setBootTime(func() (int64, error) { return 0, errors.New("no btime") })
	if !startTime(b).IsZero() {
		t.Fatal("StartTime without btime is not the zero time")
	}
}
