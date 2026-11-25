//go:build darwin || linux

package ui_test

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/ui"
)

// waitTimeout bounds every wait of these tests, so a broken prompt fails
// instead of hanging.
const waitTimeout = 10 * time.Second

// pty is a pseudo-terminal pair driven by a test: keys are typed into the
// master, everything the slave side writes is collected from the master.
type pty struct {
	t      *testing.T
	master *os.File
	slave  *os.File
	name   string
	mfd    int

	mu  sync.Mutex
	out bytes.Buffer

	stop atomic.Bool
	done chan struct{}
}

// newPTY opens a pty pair (skipping the test where none is available); it
// is never the controlling terminal of the test process (O_NOCTTY).
func newPTY(t *testing.T) *pty {
	t.Helper()
	mfd, name, err := openPTYFds()
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	sfd, err := syscall.Open(name, syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = syscall.Close(mfd)
		t.Skipf("cannot open the pty slave: %v", err)
	}
	p := &pty{
		t:      t,
		master: os.NewFile(uintptr(mfd), "ptmx"),
		slave:  os.NewFile(uintptr(sfd), name),
		name:   name,
		mfd:    mfd,
		done:   make(chan struct{}),
	}
	go p.readLoop()
	t.Cleanup(p.close)
	return p
}

func (p *pty) readLoop() {
	defer close(p.done)
	buf := make([]byte, 4096)
	for !p.stop.Load() {
		ready, err := ui.WaitReadable(p.mfd, 20*time.Millisecond)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return
		}
		if !ready {
			continue
		}
		n, err := syscall.Read(p.mfd, buf)
		if n > 0 {
			p.mu.Lock()
			p.out.Write(buf[:n])
			p.mu.Unlock()
		}
		switch {
		case err == syscall.EINTR || err == syscall.EAGAIN:
		case err != nil, n == 0:
			return // the slave side hung up
		}
	}
}

func (p *pty) close() {
	p.stop.Store(true)
	select {
	case <-p.done:
	case <-time.After(waitTimeout):
		p.t.Error("pty reader did not stop")
	}
	_ = p.slave.Close()
	_ = p.master.Close()
}

// typeKeys writes keys into the terminal, as if typed.
func (p *pty) typeKeys(keys string) {
	p.t.Helper()
	for len(keys) > 0 {
		chunk := keys
		if len(chunk) > 256 {
			chunk = chunk[:256]
		}
		if _, err := p.master.Write([]byte(chunk)); err != nil {
			p.t.Fatalf("typing into the pty: %v", err)
		}
		keys = keys[len(chunk):]
	}
}

// output returns everything written to the terminal so far.
func (p *pty) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

// waitOutput waits until the terminal output contains want n times.
func (p *pty) waitOutputN(want string, n int) {
	p.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for strings.Count(p.output(), want) < n {
		if time.Now().After(deadline) {
			p.t.Fatalf("timed out waiting for %q (x%d); terminal output: %q", want, n, p.output())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (p *pty) waitOutput(want string) {
	p.t.Helper()
	p.waitOutputN(want, 1)
}

// termios returns the slave's terminal attributes.
func (p *pty) termios() syscall.Termios {
	p.t.Helper()
	var ts syscall.Termios
	var terr error
	rc, err := p.slave.SyscallConn()
	if err == nil {
		err = rc.Control(func(fd uintptr) { ts, terr = getTermios(int(fd)) })
	}
	if err == nil {
		err = terr
	}
	if err != nil {
		p.t.Fatalf("tcgetattr: %v", err)
	}
	return ts
}

// setTermios sets the slave's terminal attributes (as a shell does when it
// takes the terminal back from a stopped job).
func (p *pty) setTermios(ts syscall.Termios) {
	p.t.Helper()
	var serr error
	rc, err := p.slave.SyscallConn()
	if err == nil {
		err = rc.Control(func(fd uintptr) { serr = setTermios(int(fd), &ts) })
	}
	if err == nil {
		err = serr
	}
	if err != nil {
		p.t.Fatalf("tcsetattr: %v", err)
	}
}

// sameMode reports whether two terminal attribute sets are the same mode,
// ignoring the PENDIN state bit.
func sameMode(a, b syscall.Termios) bool {
	a.Lflag &^= pendinFlag
	b.Lflag &^= pendinFlag
	return a == b
}

// checkRestored fails the test when the slave's mode differs from before.
func (p *pty) checkRestored(before syscall.Termios) {
	p.t.Helper()
	if after := p.termios(); !sameMode(before, after) {
		p.t.Errorf("terminal mode not restored:\n before %+v\n after  %+v", before, after)
	}
}

// waitEcho waits until the terminal's ECHO flag is on (true) or off.
func (p *pty) waitEcho(on bool) {
	p.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for (p.termios().Lflag&echoFlag != 0) != on {
		if time.Now().After(deadline) {
			p.t.Fatalf("timed out waiting for ECHO=%v", on)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// outcome is the result of a prompt run in its own goroutine.
type outcome[T any] struct {
	v   T
	err error
}

func async[T any](fn func() (T, error)) <-chan outcome[T] {
	ch := make(chan outcome[T], 1)
	go func() {
		v, err := fn()
		ch <- outcome[T]{v, err}
	}()
	return ch
}

func await[T any](t *testing.T, ch <-chan outcome[T]) (T, error) {
	t.Helper()
	select {
	case o := <-ch:
		return o.v, o.err
	case <-time.After(waitTimeout):
		t.Fatal("the prompt did not return")
	}
	var zero T
	return zero, nil
}
