package capslog

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/fsx"
)

// within fails the test if fn does not return within 5 s (a reader that
// blocked on a FIFO).
func within(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reader blocked (FIFO opened without O_NONBLOCK?)")
	}
}

// FX-G4-20: the log reader never blocks on a FIFO, refuses non-regular
// files and files above maxLogBytes.
func TestReadLogRefusesFIFOsAndOversizeLogs(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "capsules.log")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	within(t, func() {
		if _, err := Open(fifo).All(); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("FIFO log: %v, want ErrUnsafe", err)
		}
		if err := Open(fifo).Append(Entry{Path: "x/y"}); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("append to a FIFO log: %v, want ErrUnsafe", err)
		}
	})
	defer func(n int64) { maxLogBytes = n }(maxLogBytes)
	maxLogBytes = 64
	big := filepath.Join(dir, "big.log")
	if err := os.WriteFile(big, make([]byte, 65), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(big).All(); !errors.Is(err, errTooLarge) {
		t.Fatalf("oversize log: %v, want errTooLarge", err)
	}
}
