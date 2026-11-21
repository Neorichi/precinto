package testkit_test

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// recorder is a testing.TB that records failures instead of failing the
// test it wraps, so the self-tests can check that a helper fails when it
// should. Fatal* end the calling goroutine, as the real methods do;
// everything else (TempDir, Cleanup, Setenv, Chdir) goes to the wrapped T.
type recorder struct {
	testing.TB
	mu    sync.Mutex
	msgs  []string
	fatal bool
}

func (r *recorder) record(fatal bool, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, msg)
	r.fatal = r.fatal || fatal
}

func (r *recorder) Helper()                         {}
func (r *recorder) Log(args ...any)                 {}
func (r *recorder) Logf(format string, args ...any) {}
func (r *recorder) Error(args ...any)               { r.record(false, fmt.Sprint(args...)) }
func (r *recorder) Errorf(format string, args ...any) {
	r.record(false, fmt.Sprintf(format, args...))
}
func (r *recorder) Fail() { r.record(false, "Fail") }
func (r *recorder) Fatal(args ...any) {
	r.record(true, fmt.Sprint(args...))
	runtime.Goexit()
}
func (r *recorder) Fatalf(format string, args ...any) {
	r.record(true, fmt.Sprintf(format, args...))
	runtime.Goexit()
}
func (r *recorder) FailNow() {
	r.record(true, "FailNow")
	runtime.Goexit()
}
func (r *recorder) Failed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.msgs) > 0
}

// text returns every recorded message.
func (r *recorder) text() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.msgs, "\n")
}

// record runs f against a recorder in its own goroutine (so Fatal can end
// it) and returns the recorder.
func record(t *testing.T, f func(tb testing.TB)) *recorder {
	t.Helper()
	r := &recorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f(r)
	}()
	<-done
	return r
}

// mustFatal fails t unless f calls Fatal with a message containing want.
func mustFatal(t *testing.T, want string, f func(tb testing.TB)) {
	t.Helper()
	r := record(t, f)
	if !r.fatal || !strings.Contains(r.text(), want) {
		t.Errorf("want a fatal failure containing %q, got fatal=%v %q", want, r.fatal, r.text())
	}
}
