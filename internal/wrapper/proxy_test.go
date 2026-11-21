//go:build darwin || linux

package wrapper_test

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/wrapper"
)

// proxyRig runs the scripted child on a PTY behind a test terminal.
type proxyRig struct {
	t     *testing.T
	term  *termPair
	p     *wrapper.Proxy
	ready ready

	mu    sync.Mutex
	human []bool // OnHuman calls (enter flag)
}

func startRig(t *testing.T, o wrapper.ProxyOptions, extra []*os.File, args ...string) *proxyRig {
	t.Helper()
	bins := helpers(t)
	r := &proxyRig{t: t, term: newTerm(t, 100, 30)}
	o.OnHuman = func(enter bool) {
		r.mu.Lock()
		r.human = append(r.human, enter)
		r.mu.Unlock()
	}
	cmd := exec.Command(bins.tui, args...)
	cmd.Env = childEnv(t).Environ()
	cmd.ExtraFiles = extra
	p, err := wrapper.StartProxy(cmd, r.term.slave, o)
	if err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	r.p = p
	t.Cleanup(func() {
		if !r.exited() {
			_ = p.Terminate(wrapper.TerminateOptions{Grace: 200 * time.Millisecond})
		}
		_, _ = p.Wait()
	})
	r.ready = parseReady(r.term.waitForRe(readyRe, 0))
	return r
}

func (r *proxyRig) exited() bool {
	done := make(chan struct{})
	go func() { _, _ = r.p.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(20 * time.Millisecond):
		return false
	}
}

func (r *proxyRig) humanCalls() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.human...)
}

func (r *proxyRig) wait() int {
	r.t.Helper()
	type res struct {
		code int
		err  error
	}
	ch := make(chan res, 1)
	go func() { c, err := r.p.Wait(); ch <- res{c, err} }()
	select {
	case v := <-ch:
		if v.err != nil {
			r.t.Fatalf("Wait: %v", v.err)
		}
		return v.code
	case <-time.After(waitTimeout):
		r.t.Fatal("child did not exit")
		return -1
	}
}

func TestProxyForwardsIOAndExitCode(t *testing.T) {
	r := startRig(t, wrapper.ProxyOptions{}, nil)
	if !r.ready.tty {
		t.Fatal("the child does not run on a terminal")
	}
	if r.p.Child().PID != r.ready.pid || r.p.PID() != r.ready.pid {
		t.Fatalf("Child() = %+v, child reports pid %d", r.p.Child(), r.ready.pid)
	}
	// The PTY child leads a session of its own (D57).
	if r.ready.sid != r.ready.pid || r.ready.pgid != r.ready.pid {
		t.Fatalf("child pid %d has sid %d pgid %d: not a session leader", r.ready.pid, r.ready.sid, r.ready.pgid)
	}
	if own, _ := syscall.Getpgid(0); own == r.ready.pgid {
		t.Fatal("the child shares the test's process group")
	}
	m := r.term.mark()
	r.term.typeKeys("o")
	r.term.waitFor("OUT-1", m)
	r.term.typeKeys("x")
	if code := r.wait(); code != 7 {
		t.Fatalf("exit code = %d, want 7", code)
	}
	if out := r.term.output(); !strings.Contains(out, "BYE-7") {
		t.Fatalf("the child's last output was not drained:\n%q", tail(out, 500))
	}
}

func TestProxyLockDropsInputRecordsOutputAndReplays(t *testing.T) {
	r := startRig(t, wrapper.ProxyOptions{ClearScrollback: true}, nil)
	m := r.term.mark()
	r.term.typeKeys("o")
	r.term.waitFor("OUT-1", m)

	lockMark := r.term.mark()
	if err := r.p.Lock(wrapper.Overlay{Folder: "~/work/acme", Reason: "idle 15 min", Factor: "passphrase"}); err != nil {
		t.Fatal(err)
	}
	if !r.p.Locked() {
		t.Fatal("Locked() = false after Lock")
	}
	r.term.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), lockMark)
	locked := r.term.since(lockMark)
	for _, seq := range []string{"\x1b[H\x1b[2J", "\x1b[3J", "\x1b[?1049h"} {
		if !strings.Contains(locked, seq) {
			t.Errorf("lock output lacks %q", seq)
		}
	}
	// Keys typed on the lock screen never reach the child.
	r.term.typeKeys("o")
	// Output produced while locked is recorded, not shown.
	r.term.resize(90, 30)
	r.p.Resize()
	r.term.never("WINCH", lockMark, 300*time.Millisecond)
	r.term.never("OUT-2", lockMark, 0)

	unlockMark := r.term.mark()
	if err := r.p.Unlock(); err != nil {
		t.Fatal(err)
	}
	after := r.term.waitFor("WINCH 90x30", unlockMark) // replayed from the ring
	replay := r.term.since(unlockMark)
	if !strings.Contains(replay, "\x1b[?1049l") {
		t.Error("unlock did not leave the overlay's alternate screen")
	}
	if !strings.Contains(replay, "OUT-1") {
		t.Errorf("pre-lock output not replayed after unlock:\n%q", tail(replay, 1000))
	}
	if strings.Contains(replay, "OUT-2") || strings.Contains(replay, "IN:6f\r\nOUT-2") {
		t.Fatal("a key typed while locked reached the child")
	}
	// The forced repaint resizes to cols−1 and back (D30).
	r.term.waitFor("WINCH 89x30", after)
	r.term.waitFor("WINCH 90x30", after)
	// Input flows again.
	m = r.term.mark()
	r.term.typeKeys("o")
	r.term.waitFor("OUT-2", m)
	if r.p.Locked() {
		t.Fatal("Locked() = true after Unlock")
	}
}

func TestProxyOverlayKeys(t *testing.T) {
	r := startRig(t, wrapper.ProxyOptions{}, nil)
	if err := r.p.Lock(wrapper.Overlay{Folder: "f", Reason: "manual"}); err != nil {
		t.Fatal(err)
	}
	before := len(r.humanCalls())
	r.term.typeKeys("abc\x1b[I\x1b[<0;3;4M")
	r.term.typeKeys("\r")
	expectKey(t, r.p, '\r')
	r.term.typeKeys("\x04")
	expectKey(t, r.p, 0x04)
	r.term.typeKeys("\x1b[100;5u") // kitty Ctrl-D
	expectKey(t, r.p, 0x04)
	select {
	case k := <-r.p.OverlayKeys():
		t.Fatalf("unexpected overlay key %q", k)
	case <-time.After(200 * time.Millisecond):
	}
	if n := len(r.humanCalls()); n != before {
		t.Fatalf("keys on the lock screen were reported as activity (%d calls)", n-before)
	}
	if err := r.p.Unlock(); err != nil {
		t.Fatal(err)
	}
	// Overlay keys are not queued for after the unlock either.
	select {
	case k := <-r.p.OverlayKeys():
		t.Fatalf("stale overlay key %q after unlock", k)
	default:
	}
}

func expectKey(t *testing.T, p *wrapper.Proxy, want byte) {
	t.Helper()
	select {
	case k := <-p.OverlayKeys():
		if k != want {
			t.Fatalf("overlay key %q, want %q", k, want)
		}
	case <-time.After(waitTimeout):
		t.Fatalf("no overlay key, want %q", want)
	}
}

func TestProxyReportsHumanInputOnly(t *testing.T) {
	r := startRig(t, wrapper.ProxyOptions{}, nil)
	m := r.term.mark()
	reports := "\x1b[I" + "\x1b[24;80R" + "\x1b[<0;1;1m" + "\x1b]11;rgb:0/0/0\x07"
	r.term.typeKeys(reports) // focus, cursor, mouse and colour reports
	r.term.waitReceived(reports, m)
	if calls := r.humanCalls(); len(calls) != 0 {
		t.Fatalf("terminal reports counted as human input: %v", calls)
	}
	r.term.typeKeys("a")
	r.term.waitReceived("a", m)
	r.term.typeKeys("\r")
	r.term.waitReceived("a\r", m)
	calls := r.humanCalls()
	if len(calls) != 2 || calls[0] || !calls[1] {
		t.Fatalf("OnHuman calls = %v, want [false true]", calls)
	}
}

func TestProxyModesAroundTheLock(t *testing.T) {
	r := startRig(t, wrapper.ProxyOptions{}, nil)
	m := r.term.mark()
	r.term.typeKeys("M")
	r.term.waitFor("MOUSE-ON", m)
	r.term.typeKeys("P")
	r.term.waitFor("PASTE-ON", m)
	r.term.typeKeys("H")
	r.term.waitFor("CURSOR-OFF", m)
	r.term.typeKeys("K")
	r.term.waitFor("KITTY-ON", m)

	lockMark := r.term.mark()
	if err := r.p.Lock(wrapper.Overlay{Folder: "f", Reason: "manual"}); err != nil {
		t.Fatal(err)
	}
	r.term.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), lockMark)
	lock := r.term.since(lockMark)
	for _, seq := range []string{"\x1b[?1000l", "\x1b[?1006l", "\x1b[?2004l", "\x1b[?25h", "\x1b[<99u"} {
		if !strings.Contains(lock, seq) {
			t.Errorf("lock did not turn off the child's mode: missing %q", seq)
		}
	}
	unlockMark := r.term.mark()
	if err := r.p.Unlock(); err != nil {
		t.Fatal(err)
	}
	r.term.waitFor("WINCH 99x30", unlockMark)
	unlock := r.term.since(unlockMark)
	// After the replay the tracked modes are re-established exactly once.
	for _, seq := range []string{"\x1b[?1000h", "\x1b[?1006h", "\x1b[?2004h", "\x1b[?25l", "\x1b[>1u"} {
		if !strings.Contains(unlock, seq) {
			t.Errorf("unlock did not restore %q:\n%q", seq, tail(unlock, 400))
		}
	}
	if n := strings.Count(unlock, "\x1b[>1u"); n != 1 {
		t.Errorf("kitty flags pushed %d times at unlock, want exactly once", n)
	}
}

func TestProxyReplayDropsQueries(t *testing.T) {
	r := startRig(t, wrapper.ProxyOptions{}, nil)
	m := r.term.mark()
	r.term.typeKeys("Q")
	r.term.waitFor("QUERIED", m)
	if err := r.p.Lock(wrapper.Overlay{Folder: "f"}); err != nil {
		t.Fatal(err)
	}
	unlockMark := r.term.mark()
	if err := r.p.Unlock(); err != nil {
		t.Fatal(err)
	}
	r.term.waitFor("QUERIED", unlockMark)
	replay := r.term.since(unlockMark)
	for _, q := range []string{"\x1b[c", "\x1b[6n", "\x1b]11;?"} {
		if strings.Contains(replay, q) {
			t.Errorf("the replay re-sent the query %q (the terminal would answer into the child)", q)
		}
	}
}

func TestProxyRingWrapReplaysTailOnly(t *testing.T) {
	r := startRig(t, wrapper.ProxyOptions{ScrollbackBytes: 4096}, nil, "-burst", "300")
	m := r.term.mark()
	r.term.typeKeys("b")
	r.term.waitFor("BURST-END", m)
	if err := r.p.Lock(wrapper.Overlay{Folder: "f"}); err != nil {
		t.Fatal(err)
	}
	unlockMark := r.term.mark()
	if err := r.p.Unlock(); err != nil {
		t.Fatal(err)
	}
	r.term.waitFor("BURST-END", unlockMark)
	replay := r.term.since(unlockMark)
	if strings.Contains(replay, "BURST-00000") || strings.Contains(replay, "READY") {
		t.Fatal("output older than the ring was replayed")
	}
	if !strings.Contains(replay, "\x1b[0mBURST-") {
		t.Errorf("a wrapped replay must start at a line start after an SGR reset:\n%q", replay[:min(len(replay), 300)])
	}
	r.term.waitFor("WINCH 99x30", unlockMark) // the forced repaint
}

func TestProxyAltScreenChild(t *testing.T) {
	r := startRig(t, wrapper.ProxyOptions{}, nil)
	m := r.term.mark()
	r.term.typeKeys("A")
	r.term.waitFor("ALT-SCREEN", m)
	lockMark := r.term.mark()
	if err := r.p.Lock(wrapper.Overlay{Folder: "f"}); err != nil {
		t.Fatal(err)
	}
	r.term.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), lockMark)
	unlockMark := r.term.mark()
	if err := r.p.Unlock(); err != nil {
		t.Fatal(err)
	}
	r.term.waitFor("WINCH 99x30", unlockMark)
	unlock := r.term.since(unlockMark)
	// The child is back on its alternate screen, and its output since start
	// was replayed in order (the main-screen part before the switch).
	assertInOrder(t, "unlock", unlock, []string{"READY", "\x1b[?1049h", "ALT-SCREEN"})
}

func TestProxyTerminateQuitKeys(t *testing.T) {
	r := startRig(t, wrapper.ProxyOptions{}, nil, "-ignore-term")
	m := r.term.mark()
	start := time.Now()
	err := r.p.Terminate(wrapper.TerminateOptions{QuitKeys: []byte{0x03, 0x03}, KeysWait: 5 * time.Second, Grace: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Terminate took %v: the quit keys did not end the child", d)
	}
	r.term.waitFor("CTRL-C 2", m)
	if code := r.wait(); code != 0 {
		t.Fatalf("exit code %d, want 0 (clean exit on the quit keys)", code)
	}
	if strings.Contains(r.term.since(m), "TERM-IGNORED") {
		t.Fatal("SIGTERM was sent although the quit keys ended the child")
	}
}

// TestProxyTerminateEndsOnlyTheChildSession is SEC-30 for the PTY child: the
// child ignores SIGTERM, so it is SIGKILLed after the grace; the helper it
// left in its session is killed too; a process of the test's own session
// (the "user's shell job") survives.
func TestProxyTerminateEndsOnlyTheChildSession(t *testing.T) {
	bins := helpers(t)
	child := newLifeline(t)
	sibling := newLifeline(t)
	sib := testSibling(t, bins.tui, sibling)
	t.Cleanup(func() { _ = sib.Process.Kill(); _ = sib.Wait() })

	r := startRig(t, wrapper.ProxyOptions{}, []*os.File{child.w}, "-ignore-term")
	child.handOff()
	m := r.term.mark()
	r.term.typeKeys("g")
	r.term.waitFor("GRANDCHILD pid=", m)

	start := time.Now()
	if err := r.p.Terminate(wrapper.TerminateOptions{Grace: 300 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	r.term.waitFor("TERM-IGNORED", m)
	if code := r.wait(); code != 128+int(syscall.SIGKILL) {
		t.Fatalf("exit code %d, want %d (SIGKILL after the grace)", code, 128+int(syscall.SIGKILL))
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatal("SIGKILL came before the grace")
	}
	if !child.closedWithin(waitTimeout) {
		t.Fatal("the helper left in the child's session survived")
	}
	if sibling.closedWithin(300 * time.Millisecond) {
		t.Fatal("a process outside the child's session was killed")
	}
}

func TestProxyResizePropagates(t *testing.T) {
	r := startRig(t, wrapper.ProxyOptions{}, nil)
	m := r.term.mark()
	r.term.resize(120, 40)
	r.p.Resize()
	r.term.waitFor("WINCH 120x40", m)
}

func TestProxyPromptSecretOnTheLockScreen(t *testing.T) {
	r := startRig(t, wrapper.ProxyOptions{}, nil)
	if _, _, err := r.p.Prompt("x", true, nil); err == nil {
		t.Fatal("a prompt without the lock screen was accepted")
	}
	if err := r.p.Lock(wrapper.Overlay{Folder: "f"}); err != nil {
		t.Fatal(err)
	}
	secret := "s3cr3t-" + strings.Repeat("q", 5) // synthetic
	type res struct {
		v   string
		err error
	}
	ch := make(chan res, 1)
	m := r.term.mark()
	go func() {
		lb, _, err := r.p.Prompt("precinto passphrase:", true, nil)
		if err != nil {
			ch <- res{err: err}
			return
		}
		defer lb.Destroy()
		ch <- res{v: string(lb.Bytes())}
	}()
	r.term.waitFor("precinto passphrase:", m)
	r.term.typeKeys(secret + "\x7fq\r")
	select {
	case v := <-ch:
		if v.err != nil || v.v != secret {
			t.Fatalf("Prompt = %q, %v", v.v, v.err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("prompt did not return")
	}
	if strings.Contains(r.term.since(m), "s3cr3t") {
		t.Fatal("the secret was echoed on the terminal")
	}
	// The child never saw the typed secret.
	if strings.Contains(r.term.output(), "IN:7333") {
		t.Fatal("the secret reached the child")
	}
	// Ctrl-C cancels; a visible prompt echoes.
	go func() {
		_, _, err := r.p.Prompt("again:", true, nil)
		ch <- res{err: err}
	}()
	r.term.waitFor("again:", m)
	r.term.typeKeys("ab\x03")
	if v := <-ch; !errors.Is(v.err, ui.ErrCancelled) {
		t.Fatalf("Ctrl-C: err = %v, want ui.ErrCancelled", v.err)
	}
	m = r.term.mark()
	go func() {
		_, line, err := r.p.Prompt("type yes:", false, nil)
		ch <- res{v: line, err: err}
	}()
	r.term.waitFor("type yes:", m)
	r.term.typeKeys("yes\r")
	if v := <-ch; v.err != nil || v.v != "yes" {
		t.Fatalf("visible prompt = %q, %v", v.v, v.err)
	}
}

func TestProxyRefusesBadInput(t *testing.T) {
	bins := helpers(t)
	tp := newTerm(t, 80, 24)
	if _, err := wrapper.StartProxy(nil, tp.slave, wrapper.ProxyOptions{}); err == nil {
		t.Error("nil command accepted")
	}
	cmd := exec.Command(bins.tui)
	if _, err := wrapper.StartProxy(cmd, tp.slave, wrapper.ProxyOptions{}); err == nil {
		t.Error("a command without an explicit environment was accepted")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	cmd = exec.Command(bins.tui)
	cmd.Env = []string{}
	if _, err := wrapper.StartProxy(cmd, r, wrapper.ProxyOptions{}); err == nil {
		t.Error("a pipe was accepted as the terminal")
	}
	var zero *wrapper.Proxy
	if zero.Locked() || zero.Lock(wrapper.Overlay{}) == nil || zero.Unlock() == nil || zero.Terminate(wrapper.TerminateOptions{}) == nil {
		t.Error("a nil Proxy did not fail safely")
	}
	if _, err := zero.Wait(); err == nil || !zero.Child().IsZero() || zero.OverlayKeys() != nil {
		t.Error("a nil Proxy did not fail safely")
	}
}
