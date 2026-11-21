//go:build darwin || linux

package wrapper_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/wrapper"
)

// runRig is one in-process wrapper.Run on a test terminal, with fakes.
type runRig struct {
	t      *testing.T
	term   *termPair
	b      *fakeBackend
	stderr *syncBuffer
	res    <-chan runResult
	ready  ready
	cancel context.CancelFunc
}

func runOptions(t *testing.T, tp *termPair, b *fakeBackend, stderr *syncBuffer) wrapper.Options {
	return wrapper.Options{
		Harness: b.plan.Harness,
		Argv:    b.plan.Argv,
		Cwd:     t.TempDir(),
		Env:     childEnv(t),
		Stdin:   tp.slave,
		Stdout:  tp.slave,
		Stderr:  stderr,
		Policy:  config.Default().Policy,
		Backend: b,
	}
}

func startRunRig(t *testing.T, b *fakeBackend, tweak func(*wrapper.Options)) *runRig {
	t.Helper()
	r := &runRig{t: t, term: newTerm(t, 100, 30), b: b, stderr: &syncBuffer{}}
	o := runOptions(t, r.term, b, r.stderr)
	if tweak != nil {
		tweak(&o)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.res = startRun(ctx, o)
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.res:
		case <-time.After(3 * waitTimeout):
			t.Error("Run did not end after cancel")
		}
	})
	r.ready = parseReady(r.term.waitForRe(readyRe, 0))
	return r
}

func (r *runRig) finish() runResult {
	r.t.Helper()
	res := waitRun(r.t, r.res)
	r.res = closedResult(res)
	return res
}

func closedResult(res runResult) <-chan runResult {
	ch := make(chan runResult, 1)
	ch <- res
	return ch
}

// waitSubscribed waits until the wrapper subscribed (and, after the child
// started, registered).
func (b *fakeBackend) waitRegistered(t *testing.T) ipc.RegisterReq {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if regs := b.srv.registrations(); len(regs) > 0 {
			return regs[len(regs)-1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the wrapper never registered")
	return ipc.RegisterReq{}
}

func TestRunOrchestratesAndPropagatesExitCode(t *testing.T) {
	bins := helpers(t)
	plan := managedPlan("generic", bins.tui)
	plan.Sync = []harness.Selector{{Kind: "claude-session"}}
	plan.Notices = []string{"precinto: synthetic notice"}
	b := newFakeBackend(plan)
	b.seal = wrapper.SealSummary{SID: "00000000-0000-4000-8000-000000000001", Files: 3, Bytes: 2048}
	finished := false
	b.plan.Finish = func(ctx context.Context, code int) error { finished = code == 7; return nil }
	r := startRunRig(t, b, nil)

	if r.ready.active != "1" {
		t.Fatalf("PRECINTO_ACTIVE=%q in the child, want 1", r.ready.active)
	}
	if r.ready.sid != r.ready.pid {
		t.Fatal("the PTY child does not lead its own session")
	}
	reg := b.waitRegistered(t)
	if !reg.Wrapper || reg.WrapperPID != os.Getpid() || reg.PID != r.ready.pid {
		t.Fatalf("register = %+v, want wrapper=true, wrapper_pid=%d (self), pid=%d (child)", reg, os.Getpid(), r.ready.pid)
	}
	if len(reg.RootIDs) != 1 || reg.RootIDs[0] != "root-acme" {
		t.Fatalf("register roots = %v", reg.RootIDs)
	}
	m := r.term.mark()
	r.term.typeKeys("x")
	r.term.waitFor("BYE-7", m)
	res := r.finish()
	if res.code != 7 || res.err != nil {
		t.Fatalf("Run = %d, %v; want the child's exit code 7", res.code, res.err)
	}
	calls := strings.Join(b.callList(), ",")
	for _, want := range []string{
		"Plan,EnsureUnlocked,Daemon,AcquireLease,RestoreSync",
		"RecordLaunch",
		"RestoreBackground",
		"SealAfterExit,HooksSeen",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("calls %s lack %s", calls, want)
		}
	}
	if i, j := strings.Index(calls, "RestoreSync"), strings.Index(calls, "RecordLaunch"); i > j {
		t.Errorf("RecordLaunch before RestoreSync: %s", calls)
	}
	child, released := b.lease.state()
	if child.PID != r.ready.pid || !released {
		t.Fatalf("lease child=%+v released=%v", child, released)
	}
	if b.launched.PID != r.ready.pid || b.sealed.PID != r.ready.pid {
		t.Fatalf("RecordLaunch/SealAfterExit child = %+v / %+v", b.launched, b.sealed)
	}
	if !finished {
		t.Error("plan.Finish did not run with the exit code")
	}
	if len(b.srv.unregisters) != 1 || b.srv.unregisters[0].PID != r.ready.pid {
		t.Errorf("unregister = %+v", b.srv.unregisters)
	}
	errOut := r.stderr.String()
	if !strings.Contains(errOut, "precinto: synthetic notice") {
		t.Errorf("plan notice not printed: %q", errOut)
	}
	want := ui.Format(ui.MsgSealedOK, ui.Vars{SID: b.seal.SID, Files: 3, Bytes: 2048, Folder: "/nonexistent/fixture/work/acme", Idle: config.Default().Policy.IdleSoft.D()})
	if !strings.Contains(errOut, want) {
		t.Errorf("stderr %q lacks the C6 line %q", errOut, want)
	}
	// The terminal was reset at exit (SPEC §15.4), without a clear.
	r.term.waitFor(specReset, m)
	r.term.never("\x1b[3J", m, 50*time.Millisecond)
}

func TestRunLockAndUnlockEvents(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan("generic", bins.tui))
	r := startRunRig(t, b, nil)
	b.waitRegistered(t)
	m := r.term.mark()
	r.term.typeKeys("o")
	r.term.waitFor("OUT-1", m)

	lockMark := r.term.mark()
	b.srv.publish(ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{"root-acme"}, Reason: string(ui.ReasonIdle), Busy: true})
	r.term.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), lockMark)
	locked := r.term.since(lockMark)
	if !strings.Contains(locked, "locked after idle 15 min") {
		t.Errorf("overlay reason missing:\n%q", locked)
	}
	if !strings.Contains(locked, ui.Format(ui.MsgOverlayBusy, ui.Vars{Harness: "generic"})) {
		t.Errorf("busy line missing:\n%q", locked)
	}
	r.term.typeKeys("o") // dropped
	// A lock of another folder changes nothing; an unlock of another does
	// not unlock this one.
	b.srv.publish(ipc.Event{Kind: ipc.EventUnlocked, RootIDs: []string{"root-other"}})
	r.term.never("OUT-2", lockMark, 300*time.Millisecond)

	unlockMark := r.term.mark()
	b.srv.publish(ipc.Event{Kind: ipc.EventUnlocked, RootIDs: []string{"root-acme"}})
	r.term.waitFor("WINCH 99x30", unlockMark)
	if replay := r.term.since(unlockMark); !strings.Contains(replay, "OUT-1") || strings.Contains(replay, "OUT-2") {
		t.Fatalf("after unlock: pre-lock output must be replayed and locked input dropped:\n%q", tail(replay, 800))
	}
	m = r.term.mark()
	r.term.typeKeys("q")
	r.term.waitFor("BYE", m)
	if res := r.finish(); res.code != 0 {
		t.Fatalf("exit code %d", res.code)
	}
}

func TestRunOverlayEnterUnlocksInThisTerminal(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan("generic", bins.tui))
	gotSecret := make(chan string, 1)
	b.srv.unlockFn = func(ctx context.Context, req ipc.UnlockReq, h ipc.UIHandler) (ipc.UnlockResp, error) {
		if err := h.Display("precinto: relayed message"); err != nil {
			return ipc.UnlockResp{}, err
		}
		lb, err := h.Secret("precinto passphrase for ~/work/acme (Ctrl-C to cancel):")
		if err != nil {
			return ipc.UnlockResp{}, &ipc.Error{Code: ipc.CodeCancelled, Msg: "cancelled"}
		}
		gotSecret <- string(lb.Bytes())
		lb.Destroy()
		go b.srv.publish(ipc.Event{Kind: ipc.EventUnlocked, RootIDs: req.RootIDs})
		return ipc.UnlockResp{Unlocked: req.RootIDs}, nil
	}
	r := startRunRig(t, b, nil)
	b.waitRegistered(t)
	lockMark := r.term.mark()
	b.srv.publish(ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{"root-acme"}, Reason: string(ui.ReasonScreen)})
	r.term.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), lockMark)

	r.term.typeKeys("\r")
	r.term.waitFor("precinto passphrase for", lockMark)
	unlockMark := r.term.mark() // before the answer: the unlock may follow at once
	r.term.typeKeys("pw-synthetic\r")
	select {
	case s := <-gotSecret:
		if s != "pw-synthetic" {
			t.Fatalf("relayed secret = %q", s)
		}
	case <-time.After(waitTimeout):
		t.Fatal("the unlock prompt never returned the secret")
	}
	r.term.waitFor("WINCH 99x30", unlockMark) // overlay gone, repaint
	if strings.Contains(r.term.output(), "pw-synthetic") {
		t.Fatal("the passphrase was echoed or reached the child")
	}
	b.srv.mu.Lock()
	unlocks := append([]ipc.UnlockReq(nil), b.srv.unlocks...)
	b.srv.mu.Unlock()
	if len(unlocks) != 1 || !unlocks[0].TTY || len(unlocks[0].RootIDs) != 1 || unlocks[0].RootIDs[0] != "root-acme" {
		t.Fatalf("unlock requests = %+v", unlocks)
	}
	r.term.typeKeys("q")
	r.finish()
}

func TestRunOverlayUnlockCancelledStaysLocked(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan("generic", bins.tui))
	b.srv.unlockFn = func(ctx context.Context, req ipc.UnlockReq, h ipc.UIHandler) (ipc.UnlockResp, error) {
		_, err := h.Secret("secret:")
		if errors.Is(err, ui.ErrCancelled) {
			return ipc.UnlockResp{}, &ipc.Error{Code: ipc.CodeCancelled, Msg: "cancelled"}
		}
		return ipc.UnlockResp{}, errors.New("unexpected")
	}
	r := startRunRig(t, b, nil)
	b.waitRegistered(t)
	lockMark := r.term.mark()
	b.srv.publish(ipc.Event{Kind: ipc.EventLocked, Reason: string(ui.ReasonManual)})
	r.term.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), lockMark)
	r.term.typeKeys("\r")
	r.term.waitFor("secret:", lockMark)
	r.term.typeKeys("\x03")
	r.term.waitFor(ui.Format(ui.MsgUnlockCancelled, ui.Vars{Folder: "/nonexistent/fixture/work/acme"}), lockMark)
	// Still locked: keys are dropped.
	r.term.typeKeys("o")
	r.term.never("OUT-1", lockMark, 300*time.Millisecond)
	b.srv.publish(ipc.Event{Kind: ipc.EventEnd})
	res := r.finish()
	if res.code != 143 {
		t.Fatalf("exit code %d, want 143 (SIGTERM)", res.code)
	}
}

// TestRunEndEventEndsTheChildSession covers the end event (SPEC §12.7 step
// 4) and SEC-30 for the PTY child: the child and the helper it left in its
// session end; a process of the test's own session survives; the terminal
// is reset and cleared; C5 is printed.
func TestRunEndEventEndsTheChildSession(t *testing.T) {
	bins := helpers(t)
	childLife, sibLife := newLifeline(t), newLifeline(t)
	sib := testSibling(t, bins.tui, sibLife)
	t.Cleanup(func() { _ = sib.Process.Kill(); _ = sib.Wait() })

	plan := managedPlan(harness.ClaudeCode, bins.tui)
	plan.Resume = harness.Resume{Kind: harness.ResumeSID, Value: "00000000-0000-4000-8000-0000000000aa"}
	b := newFakeBackend(plan)
	b.lease = &fakeLease{files: []*os.File{childLife.w}}
	b.seal = wrapper.SealSummary{SID: plan.Resume.Value, Files: 2, Bytes: 10}
	r := startRunRig(t, b, nil)
	b.waitLaunched(t)
	childLife.handOff()
	b.waitRegistered(t)
	m := r.term.mark()
	r.term.typeKeys("g")
	r.term.waitFor("GRANDCHILD pid=", m)

	b.srv.publish(ipc.Event{Kind: ipc.EventLocked, Reason: string(ui.ReasonIdle)})
	r.term.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), m)
	endMark := r.term.mark()
	// An end for another session is ignored.
	b.srv.publish(ipc.Event{Kind: ipc.EventEnd, SIDs: []string{"00000000-0000-4000-8000-0000000000bb"}})
	time.Sleep(200 * time.Millisecond)
	b.srv.publish(ipc.Event{Kind: ipc.EventEnd, SIDs: []string{plan.Resume.Value}, Reason: string(ui.ReasonIdle)})
	r.term.waitFor(ui.Format(ui.MsgOverlayEnding, ui.Vars{}), endMark)
	res := r.finish()
	if res.code != 143 {
		t.Fatalf("exit code %d, want 143 (the child exits on SIGTERM)", res.code)
	}
	if !childLife.closedWithin(waitTimeout) {
		t.Fatal("the helper in the child's session survived the end")
	}
	if sibLife.closedWithin(300 * time.Millisecond) {
		t.Fatal("a process outside the child's session was killed")
	}
	// clear_terminal_on_end: reset and clear, so nothing of it stays.
	r.term.waitFor(specReset+"\x1b[H\x1b[2J\x1b[3J", endMark)
	errOut := r.stderr.String()
	c5 := ui.Format(ui.MsgEnded, ui.Vars{Folder: "/nonexistent/fixture/work/acme", N: 1, Reason: ui.ReasonIdle,
		Idle: config.Default().Policy.IdleSoft.D(), Resume: "claude --resume " + plan.Resume.Value})
	if !strings.Contains(errOut, c5) {
		t.Errorf("stderr %q lacks C5 %q", errOut, c5)
	}
	if strings.Contains(errOut, "stays unlocked") {
		t.Errorf("C6.ok printed for an ended session: %q", errOut)
	}
}

func TestRunCtrlDOnTheOverlayEndsTheSession(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan("generic", bins.tui))
	r := startRunRig(t, b, nil)
	b.waitRegistered(t)
	m := r.term.mark()
	b.srv.publish(ipc.Event{Kind: ipc.EventLocked, Reason: string(ui.ReasonManual)})
	r.term.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), m)
	r.term.typeKeys("\x04")
	res := r.finish()
	if res.code != 143 {
		t.Fatalf("exit code %d, want 143", res.code)
	}
	if !b.called("SealAfterExit") {
		t.Fatal("Ctrl-D did not seal the session")
	}
	if !strings.Contains(r.stderr.String(), "ended 1 session(s) after locked by you") {
		t.Errorf("C5 missing: %q", r.stderr.String())
	}
}

func TestRunSubscriptionLossLocksUntilUnlocked(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan("generic", bins.tui))
	r := startRunRig(t, b, nil)
	b.waitRegistered(t)
	m := r.term.mark()
	b.srv.dropSubscriptions() // the stream closes: a daemon restart
	r.term.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), m)
	r.term.waitFor("agent isn't running", m)
	// The overlay names the cause (CC-38: ReasonAgent).
	r.term.waitFor(ui.ReasonText(ui.ReasonAgent, 0), m)
	r.term.typeKeys("o")
	deadline := time.Now().Add(waitTimeout)
	for len(b.srv.registrations()) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(b.srv.registrations()) < 2 {
		t.Fatal("the wrapper did not register again after reconnecting")
	}
	// Reconnected, yet still locked until an unlocked event (SPEC §15.3).
	r.term.never("OUT-1", m, 400*time.Millisecond)
	unlockMark := r.term.mark()
	b.srv.publish(ipc.Event{Kind: ipc.EventUnlocked})
	r.term.waitFor("WINCH 99x30", unlockMark)
	r.term.typeKeys("o")
	r.term.waitFor("OUT-1", unlockMark)
	r.term.typeKeys("q")
	r.finish()
}

func TestRunHeartbeatTimeoutLocksLocally(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the heartbeat timeout")
	}
	bins := helpers(t)
	b := newFakeBackend(managedPlan("generic", bins.tui))
	r := startRunRig(t, b, nil)
	b.waitRegistered(t)
	m := r.term.mark()
	start := time.Now()
	b.srv.heartbeats.Store(false) // the daemon hangs: no event for 2 s (1 s in tests)
	r.term.waitFor("agent isn't running", m)
	if d := time.Since(start); d < 900*time.Millisecond {
		t.Fatalf("locked after %v, before the heartbeat timeout", d)
	}
	b.srv.heartbeats.Store(true)
	r.cancel()
	r.finish()
}

// TestRunLockDuringRestoreSyncAborts is the wrapper's part of REST-8: a
// lock during the synchronous restore closes abort at once, and the child
// is never started.
func TestRunLockDuringRestoreSyncAborts(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan("generic", bins.tui))
	aborted := make(chan time.Duration, 1)
	inRestore := make(chan struct{})
	b.restoreSync = func(ctx context.Context, abort <-chan struct{}) (wrapper.RestoreSummary, error) {
		close(inRestore)
		start := time.Now()
		select {
		case <-abort:
			aborted <- time.Since(start)
			return wrapper.RestoreSummary{}, context.Canceled
		case <-time.After(waitTimeout):
			return wrapper.RestoreSummary{}, nil
		}
	}
	tp := newTerm(t, 100, 30)
	res := startRun(context.Background(), runOptions(t, tp, b, &syncBuffer{}))
	<-inRestore
	b.srv.publish(ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{"root-acme"}, Reason: string(ui.ReasonScreen)})
	select {
	case d := <-aborted:
		if d > 2*time.Second {
			t.Fatalf("abort closed after %v, want within 2 s", d)
		}
	case <-time.After(waitTimeout):
		t.Fatal("abort was never closed")
	}
	out := waitRun(t, res)
	var ie *ipc.Error
	if out.code != wrapper.ExitNotStarted || !errors.As(out.err, &ie) || ie.Code != ipc.CodeLocked || ie.ExitCode() != 3 {
		t.Fatalf("Run = %d, %v; want ExitNotStarted with ipc.CodeLocked (exit 3)", out.code, out.err)
	}
	if b.called("RecordLaunch") || strings.Contains(tp.output(), "READY") {
		t.Fatal("the child started after a lock during the restore")
	}
	if _, released := b.lease.state(); !released {
		t.Fatal("the lease was not released")
	}
}

var errConflict = errors.New("synthetic conflict")

// TestRunRestoreErrorRefusesTheLaunch is the wrapper's part of CODX-7: a
// RestoreSync failure (a Codex conflict) refuses the launch; the error
// reaches cmd/precinto, which maps it to the exit code.
func TestRunRestoreErrorRefusesTheLaunch(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan(harness.Codex, bins.tui))
	b.restoreSync = func(ctx context.Context, abort <-chan struct{}) (wrapper.RestoreSummary, error) {
		return wrapper.RestoreSummary{}, errConflict
	}
	tp := newTerm(t, 100, 30)
	out := waitRun(t, startRun(context.Background(), runOptions(t, tp, b, &syncBuffer{})))
	if !errors.Is(out.err, errConflict) || out.code == 0 {
		t.Fatalf("Run = %d, %v; want the restore error", out.code, out.err)
	}
	if b.called("RecordLaunch") || strings.Contains(tp.output(), "READY") {
		t.Fatal("the child started although the restore failed")
	}
	if _, released := b.lease.state(); !released {
		t.Fatal("the lease was not released")
	}
}

func TestRunPassthroughSkipsGateAndRestore(t *testing.T) {
	bins := helpers(t)
	plan := managedPlan(harness.ClaudeCode, bins.tui)
	plan.Mode = harness.LaunchPassthrough
	b := newFakeBackend(plan)
	tp := newTerm(t, 100, 30)
	res := startRun(context.Background(), runOptions(t, tp, b, &syncBuffer{}))
	m := parseReady(tp.waitForRe(readyRe, 0))
	if m.active != "1" {
		t.Fatalf("PRECINTO_ACTIVE = %q", m.active)
	}
	if m.sid == m.pid {
		t.Fatal("a passthrough child must stay in the user's session (no Setsid)")
	}
	tp.typeKeys("x")
	out := waitRun(t, res)
	if out.code != 7 {
		t.Fatalf("exit code %d, want 7", out.code)
	}
	if calls := strings.Join(b.callList(), ","); calls != "Plan" {
		t.Fatalf("passthrough calls = %s, want only Plan", calls)
	}
	if strings.Contains(tp.output(), "--settings") {
		t.Fatal("settings injected into a passthrough launch")
	}
}

// TestRunDirectModeSetsidAndEnd covers --no-pty (D57, SEC-30 direct): the
// child leads its own session, gets no PTY, and an end event ends it and
// what it left in its session, nothing else.
func TestRunDirectModeSetsidAndEnd(t *testing.T) {
	bins := helpers(t)
	childLife, sibLife := newLifeline(t), newLifeline(t)
	sib := testSibling(t, bins.tui, sibLife)
	t.Cleanup(func() { _ = sib.Process.Kill(); _ = sib.Wait() })

	b := newFakeBackend(managedPlan("generic", bins.tui))
	b.lease = &fakeLease{files: []*os.File{childLife.w}}
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()
	o := runOptions(t, newTerm(t, 80, 24), b, &syncBuffer{})
	o.NoPTY = true
	o.Stdin, o.Stdout = inR, outW
	res := startRun(context.Background(), o)
	defer inR.Close()
	defer outW.Close()
	pr := newPipeReader(t, outR)
	rd := parseReady(pr.waitForRe(readyRe))
	b.waitLaunched(t)
	childLife.handOff()
	if rd.tty {
		t.Fatal("direct mode gave the child a terminal")
	}
	if rd.sid != rd.pid || rd.pgid != rd.pid {
		t.Fatalf("direct child pid %d sid %d pgid %d: not started with Setsid", rd.pid, rd.sid, rd.pgid)
	}
	if _, err := inW.Write([]byte("g")); err != nil {
		t.Fatal(err)
	}
	pr.waitFor("GRANDCHILD pid=")
	b.waitRegistered(t)
	b.srv.publish(ipc.Event{Kind: ipc.EventEnd})
	out := waitRun(t, res)
	if out.code != 143 {
		t.Fatalf("exit code %d, want 143", out.code)
	}
	if !childLife.closedWithin(waitTimeout) {
		t.Fatal("the helper in the direct child's session survived")
	}
	if sibLife.closedWithin(300 * time.Millisecond) {
		t.Fatal("a process outside the child's session was killed")
	}
}

func TestRunConfirmDeclinedRefuses(t *testing.T) {
	bins := helpers(t)
	plan := managedPlan(harness.ClaudeCode, bins.tui)
	plan.Confirm = string(ui.MsgBareWarning) // a ui.MsgID the wrapper renders (CC-20)
	b := newFakeBackend(plan)
	fp := &fakePrompt{yes: false}
	defer wrapper.SetPromptUI(func() (wrapper.PromptUI, error) { return fp, nil })()
	tp := newTerm(t, 80, 24)
	out := waitRun(t, startRun(context.Background(), runOptions(t, tp, b, &syncBuffer{})))
	if out.code != wrapper.ExitNotStarted || !errors.Is(out.err, ui.ErrCancelled) {
		t.Fatalf("Run = %d, %v; want ExitNotStarted, ui.ErrCancelled (exit 3)", out.code, out.err)
	}
	if len(fp.asked) != 1 || fp.asked[0] != ui.Format(ui.MsgBareWarning, ui.Vars{}) || !fp.closed {
		t.Fatalf("prompt asked %q closed=%v", fp.asked, fp.closed)
	}
	if b.called("EnsureUnlocked") || b.called("AcquireLease") {
		t.Fatalf("calls after a declined confirmation: %v", b.callList())
	}
}

func TestRunConfirmWithoutTerminalFailsClosed(t *testing.T) {
	bins := helpers(t)
	plan := managedPlan(harness.ClaudeCode, bins.tui)
	plan.Confirm = string(ui.MsgBareWarning) // a ui.MsgID the wrapper renders (CC-20)
	b := newFakeBackend(plan)
	tp := newTerm(t, 80, 24)
	out := waitRun(t, startRun(context.Background(), runOptions(t, tp, b, &syncBuffer{})))
	if out.code == 0 || out.err == nil || b.called("EnsureUnlocked") {
		t.Fatalf("Run = %d, %v with calls %v; want a refusal", out.code, out.err, b.callList())
	}
}

func TestRunEnsureUnlockedRelaysAndFailsClosed(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan("generic", bins.tui))
	fp := &fakePrompt{secret: "x"}
	defer wrapper.SetPromptUI(func() (wrapper.PromptUI, error) { return fp, nil })()
	b.ensureFn = func(h ipc.UIHandler) error {
		if err := h.Display("precinto: unlock ~/work/acme"); err != nil {
			return err
		}
		return &ipc.Error{Code: ipc.CodeCancelled, Msg: "unlock cancelled"}
	}
	tp := newTerm(t, 80, 24)
	out := waitRun(t, startRun(context.Background(), runOptions(t, tp, b, &syncBuffer{})))
	var ce *ipc.Error
	if out.code != wrapper.ExitNotStarted || !errors.As(out.err, &ce) || ce.ExitCode() != 3 {
		t.Fatalf("Run = %d, %v; want ExitNotStarted with an exit-3 error", out.code, out.err)
	}
	if len(fp.displays) != 1 || !fp.closed {
		t.Fatalf("relayed UI: displays=%q closed=%v", fp.displays, fp.closed)
	}
	if b.called("AcquireLease") || b.called("RestoreSync") {
		t.Fatalf("restore after a failed unlock: %v", b.callList())
	}
}

func TestRunInjectsClaudeSettings(t *testing.T) {
	bins := helpers(t)
	t.Run("injected when the plan lacks it", func(t *testing.T) {
		b := newFakeBackend(managedPlan(harness.ClaudeCode, bins.tui, "--resume", "x"))
		r := startRunRig(t, b, nil)
		out := r.term.output()
		if !strings.Contains(out, "ARGV --settings "+wrapper.ClaudeSettings+" --resume x") {
			t.Errorf("argv without D32 settings:\n%q", tail(out, 500))
		}
		if !strings.Contains(out, "AWAY=0") {
			t.Errorf("CLAUDE_CODE_ENABLE_AWAY_SUMMARY not 0:\n%q", tail(out, 500))
		}
		r.term.typeKeys("q")
		r.finish()
	})
	t.Run("a user's own --settings wins", func(t *testing.T) {
		b := newFakeBackend(managedPlan(harness.ClaudeCode, bins.tui, "--settings", "{}"))
		r := startRunRig(t, b, nil)
		out := r.term.output()
		if strings.Contains(out, wrapper.ClaudeSettings) || !strings.Contains(out, "ARGV --settings {}") {
			t.Errorf("settings changed:\n%q", tail(out, 500))
		}
		r.term.typeKeys("q")
		r.finish()
	})
	t.Run("not for other harnesses or unmanaged launches", func(t *testing.T) {
		plan := managedPlan(harness.ClaudeCode, bins.tui)
		plan.Roots = nil
		b := newFakeBackend(plan)
		r := startRunRig(t, b, nil)
		if out := r.term.output(); strings.Contains(out, "--settings") || strings.Contains(out, "AWAY=0") {
			t.Errorf("unmanaged launch got D32:\n%q", tail(out, 500))
		}
		r.term.typeKeys("q")
		r.finish()
		if b.called("Daemon") || b.called("EnsureUnlocked") {
			t.Fatalf("an unmanaged launch used the daemon: %v", b.callList())
		}
	})
}

func TestRunReportsHumanActivityOnly(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan("generic", bins.tui))
	r := startRunRig(t, b, nil)
	b.waitRegistered(t)
	m := r.term.mark()
	r.term.typeKeys("\x1b[I\x1b[24;80R") // terminal reports only
	r.term.waitReceived("\x1b[I\x1b[24;80R", m)
	time.Sleep(100 * time.Millisecond)
	if acts := b.srv.activities(); len(acts) != 0 {
		t.Fatalf("terminal reports became activity: %+v", acts)
	}
	r.term.typeKeys("a")
	r.term.waitReceived("a", m)
	r.term.typeKeys("\r")
	waitActivity(t, b.srv, ipc.ActEnter)
	waitActivity(t, b.srv, ipc.ActInput)
	for _, a := range b.srv.activities() {
		if a.Harness != "generic" || a.At.IsZero() {
			t.Fatalf("activity %+v", a)
		}
	}
	// Keys on the lock screen are never activity.
	b.srv.publish(ipc.Event{Kind: ipc.EventLocked})
	r.term.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), m)
	before := len(b.srv.activities())
	r.term.typeKeys("abc\r")
	time.Sleep(300 * time.Millisecond)
	if n := len(b.srv.activities()); n != before {
		t.Fatalf("lock-screen keys became activity (%d new)", n-before)
	}
	b.srv.publish(ipc.Event{Kind: ipc.EventEnd})
	r.finish()
}

func waitActivity(t *testing.T, srv *fakeServer, kind ipc.ActivityKind) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		for _, a := range srv.activities() {
			if a.Kind == kind {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %s activity in %+v", kind, srv.activities())
}

func TestRunPrintsHookAndSealLines(t *testing.T) {
	bins := helpers(t)
	cases := []struct {
		name  string
		setup func(b *fakeBackend)
		want  string
	}{
		{"hooks not seen", func(b *fakeBackend) { b.hooksSeen = false }, ui.Format(ui.MsgClaudeNoHooks, ui.Vars{})},
		{"seal deferred", func(b *fakeBackend) { b.seal = wrapper.SealSummary{Deferred: true} },
			ui.Format(ui.MsgSealDeferred, ui.Vars{Harness: "Claude"})},
		{"seal failed", func(b *fakeBackend) {
			b.seal = wrapper.SealSummary{SID: "00000000-0000-4000-8000-000000000002", Failed: "disk full"}
		}, ui.Format(ui.MsgSealFailed, ui.Vars{SID: "00000000-0000-4000-8000-000000000002", Cause: "disk full"})},
		{"seal error", func(b *fakeBackend) { b.sealErr = &ipc.Error{Code: ipc.CodeLive, Msg: "x"} },
			ui.Format(ui.MsgSealFailed, ui.Vars{Cause: "live"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newFakeBackend(managedPlan(harness.ClaudeCode, bins.tui))
			tc.setup(b)
			r := startRunRig(t, b, nil)
			r.term.typeKeys("q")
			r.finish()
			if got := r.stderr.String(); !strings.Contains(got, tc.want) {
				t.Fatalf("stderr %q lacks %q", got, tc.want)
			}
		})
	}
}

func TestRunExpiringNotifies(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan("generic", bins.tui))
	r := startRunRig(t, b, nil)
	b.waitRegistered(t)
	m := r.term.mark()
	b.srv.publish(ipc.Event{Kind: ipc.EventExpiring})
	want := "\x1b]9;" + ui.Format(ui.MsgExpiry, ui.Vars{Folder: "/nonexistent/fixture/work/acme", Limit: config.Default().Policy.MaxUnlock.D()}) + "\x1b\\"
	r.term.waitFor(want, m)
	r.term.typeKeys("q")
	r.finish()
}

func TestRunCancelledContextEndsTheChild(t *testing.T) {
	bins := helpers(t)
	b := newFakeBackend(managedPlan("generic", bins.tui))
	r := startRunRig(t, b, nil)
	b.waitRegistered(t)
	r.cancel()
	res := r.finish()
	if res.code != 143 {
		t.Fatalf("exit code %d, want 143", res.code)
	}
	if !b.called("SealAfterExit") {
		t.Fatal("no seal after a cancelled run")
	}
	if strings.Contains(r.stderr.String(), "ended 1 session") {
		t.Fatal("C5 printed although precinto did not end the session")
	}
}

func TestRunRefusesBadOptions(t *testing.T) {
	if code, err := wrapper.Run(context.Background(), wrapper.Options{}); err == nil || code == 0 {
		t.Fatalf("Run without a backend = %d, %v", code, err)
	}
	// The child never started: ExitNotStarted with the reason (CC-42);
	// cmd/precinto maps the error.
	b := newFakeBackend(harness.LaunchPlan{})
	if code, err := wrapper.Run(context.Background(), wrapper.Options{Backend: b}); err == nil || code != wrapper.ExitNotStarted {
		t.Fatalf("Run without argv = %d, %v", code, err)
	}
	b.planErr = &ipc.Error{Code: ipc.CodeBadRequest, Msg: "x"}
	code, err := wrapper.Run(context.Background(), wrapper.Options{Backend: b, Argv: []string{"x"}})
	var ie *ipc.Error
	if code != wrapper.ExitNotStarted || !errors.As(err, &ie) || ie.ExitCode() != 2 {
		t.Fatalf("Run with a failing plan = %d, %v", code, err)
	}
	// An executable that does not exist: not started, nothing left running.
	bins := helpers(t)
	plan := managedPlan("generic", bins.tui+"-missing")
	b = newFakeBackend(plan)
	tp := newTerm(t, 80, 24)
	out := waitRun(t, startRun(context.Background(), runOptions(t, tp, b, &syncBuffer{})))
	if out.code != wrapper.ExitNotStarted || !errors.Is(out.err, fs.ErrNotExist) {
		t.Fatalf("missing executable: %d, %v", out.code, out.err)
	}
	if _, released := b.lease.state(); !released {
		t.Fatal("lease not released after a failed start")
	}
}

// pipeReader collects a direct-mode child's stdout.
type pipeReader struct {
	t   *testing.T
	buf *syncBuffer
}

func newPipeReader(t *testing.T, r *os.File) *pipeReader {
	p := &pipeReader{t: t, buf: &syncBuffer{}}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := r.Read(b)
			if n > 0 {
				_, _ = p.buf.Write(b[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	return p
}

func (p *pipeReader) waitFor(sub string) {
	p.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if strings.Contains(p.buf.String(), sub) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	p.t.Fatalf("timed out waiting for %q in %q", sub, p.buf.String())
}

func (p *pipeReader) waitForRe(re interface{ FindStringSubmatch(string) []string }) []string {
	p.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(p.buf.String()); m != nil {
			return m
		}
		time.Sleep(10 * time.Millisecond)
	}
	p.t.Fatalf("timed out; output %q", p.buf.String())
	return nil
}
