package sweep

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/live"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/sweep/queue"
)

// D131 (L-1): a run that holds the sweep lock seals, during its D63 quiet
// wait, the queued requests whose writer has exited, then waits out the
// rest of the window for the units it looked at first.

// heldQuiet is an Env.Sleep that holds every quiet-window wait until the
// test releases it (or the wait's context ends: the drain's wake) and
// returns at once for every shorter wait (rescue grace, polling).
type heldQuiet struct {
	mu      sync.Mutex
	waits   int // quiet-window waits begun
	woken   int // quiet-window waits ended by their context
	inWait  chan struct{}
	release chan struct{}
	once    sync.Once
}

func newHeldQuiet() *heldQuiet {
	return &heldQuiet{inWait: make(chan struct{}), release: make(chan struct{})}
}

func (h *heldQuiet) sleep(ctx context.Context, d time.Duration) error {
	if d < d63Quiet/2 {
		return ctx.Err()
	}
	h.mu.Lock()
	h.waits++
	h.mu.Unlock()
	h.once.Do(func() { close(h.inWait) })
	select {
	case <-h.release:
		return ctx.Err()
	case <-ctx.Done():
		h.mu.Lock()
		h.woken++
		h.mu.Unlock()
		return ctx.Err()
	}
}

func (h *heldQuiet) counts() (waits, woken int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.waits, h.woken
}

// reapedEnv is d63Env with a held quiet wait and a fast queue poll.
func reapedEnv(t *testing.T) (*testEnv, *lookingLive, *heldQuiet) {
	te, l, _ := d63Env(t)
	hq := newHeldQuiet()
	te.e.Sleep = hq.sleep
	old := reapedPoll
	reapedPoll = 20 * time.Millisecond
	t.Cleanup(func() { reapedPoll = old })
	return te, l, hq
}

// gonePID is a writer that is not in the fake process table: exited.
var gonePID = platform.ProcID{PID: 999999, StartUS: 1}

func enqueueEnd(t *testing.T, te *testEnv, sid string, writer platform.ProcID) {
	t.Helper()
	_, err := queue.Enqueue(te.h.Layout.QueueDir, queue.Request{Harness: "claude-code", SID: sid, Reason: "other",
		WaitFor: writer, At: te.run().now()})
	mustNoErr(t, err)
}

// startHolder runs fn (a sweep or a queue drain) and waits until it sits
// in its quiet wait.
func startHolder(t *testing.T, hq *heldQuiet, fn func(ctx context.Context) (*Report, error)) (<-chan *Report, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	done := make(chan *Report, 1)
	go func() {
		rep, err := fn(ctx)
		if err != nil {
			t.Errorf("holder: %v", err)
		}
		done <- rep
	}()
	select {
	case <-hq.inWait:
	case <-time.After(20 * time.Second):
		cancel()
		t.Fatal("the run never reached its quiet wait")
	}
	return done, cancel
}

// until polls cond for up to d of real time.
// reapedWait bounds the waits for something the quiet wait does in the
// background. It returns as soon as that happens, so a generous bound costs
// nothing on a fast machine; under WSL 2 on a CI runner the package runs
// about eight times slower than on ubuntu, and 5 s was not always enough.
const reapedWait = 30 * time.Second

func until(d time.Duration, cond func() bool) bool {
	limit := time.Now().Add(d)
	for time.Now().Before(limit) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

func countUnit(rep *Report, key string) (n int, last UnitResult) {
	for _, u := range rep.Units {
		if u.Unit == key {
			n++
			last = u
		}
	}
	return n, last
}

// The E2E-2 case: the lock sweep waits on a session it saw first; that
// session ends (its writer exits) and is queued: it is sealed at once,
// while the sweep still waits, and is not decided again after the wait.
func TestD131QueuedSessionTheSweepWaitsOnIsSealedDuringTheWait(t *testing.T) {
	te, l, hq := reapedEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	done, cancel := startHolder(t, hq, func(ctx context.Context) (*Report, error) {
		return te.run().sweep(ctx, Options{Reason: "lock", Lock: true})
	})
	defer cancel()
	enqueueEnd(t, te, sid1, gonePID)
	if !until(reapedWait, func() bool { return !exists(transcriptOf(u)) }) {
		t.Fatal("the queued session whose writer exited stayed plaintext during the other run's quiet wait")
	}
	// The wait resumes after the drain, for what is left of the window.
	if !until(reapedWait, func() bool { w, _ := hq.counts(); return w == 2 }) {
		w, k := hq.counts()
		t.Fatalf("quiet waits %d (woken %d), want the wait resumed once after the drain", w, k)
	}
	select {
	case <-done:
		t.Fatal("the sweep ended before its quiet window")
	default:
	}
	if _, woken := hq.counts(); woken != 1 {
		t.Fatalf("woken %d times, want once", woken)
	}
	close(hq.release)
	rep := <-done
	if n, res := countUnit(rep, u.Key); n != 1 || res.Outcome != OutSealed {
		t.Fatalf("session reported %d times (%+v), want sealed once", n, res)
	}
	if n := len(te.logged(u.Key)); n != 1 {
		t.Fatalf("session sealed %d times", n)
	}
	l.mu.Lock()
	seen := l.seen[u.Key]
	l.mu.Unlock()
	if seen != 2 {
		t.Fatalf("session decided %d times, want its first look and the request's seal only", seen)
	}
	if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 0 {
		t.Fatalf("queue left %+v", reqs)
	}
}

// A session that did not exist at the sweep's first look ends while the
// sweep waits; its writer was still running when it was queued and exits
// later: sealed as soon as the writer is gone. The session the sweep
// waits on is sealed after the full window, as before.
func TestD131WriterExitingDuringTheWaitIsSealedThen(t *testing.T) {
	te, _, hq := reapedEnv(t)
	te.writeSession(sid1, "", nil)
	u1 := te.scanSession(sid1)
	done, cancel := startHolder(t, hq, func(ctx context.Context) (*Report, error) {
		return te.run().sweep(ctx, Options{Reason: "lock", Lock: true})
	})
	defer cancel()
	te.writeSession(sid2, "", nil)
	u2 := te.scanSession(sid2)
	writer := platform.ProcID{PID: 4321, StartUS: 7}
	te.h.Procs.Add(procInfo(writer.PID, writer.StartUS))
	enqueueEnd(t, te, sid2, writer)
	time.Sleep(200 * time.Millisecond) // ten polls with the writer alive
	if !exists(transcriptOf(u2)) {
		t.Fatal("sealed while its writer was still running")
	}
	te.h.Procs.Exit(writer.PID, false)
	if !until(reapedWait, func() bool { return !exists(transcriptOf(u2)) }) {
		t.Fatal("the session stayed plaintext after its writer exited, during the other run's quiet wait")
	}
	if !exists(transcriptOf(u1)) {
		t.Fatal("the session the sweep waits on was sealed before its window ended")
	}
	close(hq.release)
	rep := <-done
	for _, u := range []string{u1.Key, u2.Key} {
		if n, res := countUnit(rep, u); n != 1 || res.Outcome != OutSealed {
			t.Fatalf("%s reported %d times (%+v)", short(u), n, res)
		}
		if n := len(te.logged(u)); n != 1 {
			t.Fatalf("%s sealed %d times", short(u), n)
		}
	}
}

// A request without a writer needs two looks of its own: the wait does
// not take it (it waits for the next drain).
func TestD131RequestWithoutWriterWaitsForTheNextDrain(t *testing.T) {
	te, _, hq := reapedEnv(t)
	te.writeSession(sid1, "", nil)
	done, cancel := startHolder(t, hq, func(ctx context.Context) (*Report, error) {
		return te.run().sweep(ctx, Options{Reason: "lock", Lock: true})
	})
	defer cancel()
	te.writeSession(sid2, "", nil)
	u2 := te.scanSession(sid2)
	enqueueEnd(t, te, sid2, platform.ProcID{})
	time.Sleep(200 * time.Millisecond)
	if _, woken := hq.counts(); woken != 0 || !exists(transcriptOf(u2)) {
		t.Fatalf("a request without a writer woke the wait (%d) or was sealed", woken)
	}
	close(hq.release)
	<-done
	if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 1 {
		t.Fatalf("queue %+v, want the request left for the next drain", reqs)
	}
}

// A drained request whose unit is still held by other evidence is backed
// off like any drain's, once: the wait does not wake for it again and
// resumes.
func TestD131HeldRequestIsTriedOnce(t *testing.T) {
	te, _, hq := reapedEnv(t)
	te.writeSession(sid1, "", nil)
	done, cancel := startHolder(t, hq, func(ctx context.Context) (*Report, error) {
		return te.run().sweep(ctx, Options{Reason: "lock", Lock: true})
	})
	defer cancel()
	te.writeSession(sid2, "", nil)
	u2 := te.scanSession(sid2)
	te.claude.probe[u2.Key] = []live.Evidence{{Reason: live.ReasonLease, Detail: "lease held"}}
	enqueueEnd(t, te, sid2, gonePID)
	if !until(reapedWait, func() bool {
		reqs, _ := queue.List(te.h.Layout.QueueDir)
		return len(reqs) == 1 && reqs[0].Attempts == 1
	}) {
		t.Fatal("the held request was not tried during the wait")
	}
	time.Sleep(200 * time.Millisecond)
	if waits, woken := hq.counts(); woken != 1 || waits != 2 {
		t.Fatalf("quiet waits %d (woken %d): the wait woke again for a request it tried", waits, woken)
	}
	close(hq.release)
	<-done
	if !exists(transcriptOf(u2)) {
		t.Fatal("a unit held by a lease was sealed")
	}
}

// The queue worker (seal --queue) that holds the lock and waits for a
// request of its own drains the reaped-writer requests that come meanwhile.
func TestD131QueueWorkerWaitDrainsReapedRequests(t *testing.T) {
	te, _, hq := reapedEnv(t)
	te.writeSession(sid1, "", nil)
	enqueueEnd(t, te, sid1, platform.ProcID{}) // no writer: two looks
	done, cancel := startHolder(t, hq, func(ctx context.Context) (*Report, error) {
		return te.run().drainCommand(ctx, Options{Reason: "session-end"})
	})
	defer cancel()
	te.writeSession(sid2, "", nil)
	u2 := te.scanSession(sid2)
	enqueueEnd(t, te, sid2, gonePID)
	if !until(reapedWait, func() bool { return !exists(transcriptOf(u2)) }) {
		t.Fatal("the reaped-writer request waited for the queue worker's own quiet window")
	}
	close(hq.release)
	rep := <-done
	for _, sid := range []string{sid1, sid2} {
		if n, res := countUnit(rep, te.sessionKey(sid)); n != 1 || res.Outcome != OutSealed {
			t.Fatalf("%s reported %d times (%+v)", sid, n, res)
		}
	}
	if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 0 {
		t.Fatalf("queue left %+v", reqs)
	}
}

// Runs that do not hold the sweep lock (an explicit seal) and dry runs
// never drain the queue during their wait.
func TestD131OnlyALockHolderDrains(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(te *testEnv, ctx context.Context) (*Report, error)
	}{
		{"seal", func(te *testEnv, ctx context.Context) (*Report, error) {
			return te.run().sealCommand(ctx, []harness.Unit{te.scanSession(sid1)}, Options{})
		}},
		{"dry-run sweep", func(te *testEnv, ctx context.Context) (*Report, error) {
			return te.run().sweep(ctx, Options{DryRun: true})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te, _, hq := reapedEnv(t)
			te.writeSession(sid1, "", nil)
			done, cancel := startHolder(t, hq, func(ctx context.Context) (*Report, error) { return tc.run(te, ctx) })
			defer cancel()
			te.writeSession(sid2, "", nil)
			u2 := te.scanSession(sid2)
			enqueueEnd(t, te, sid2, gonePID)
			time.Sleep(200 * time.Millisecond)
			if _, woken := hq.counts(); woken != 0 || !exists(transcriptOf(u2)) {
				t.Fatalf("woken %d, transcript sealed: %v", woken, !exists(transcriptOf(u2)))
			}
			close(hq.release)
			<-done
			if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 1 {
				t.Fatalf("queue %+v, want the request kept", reqs)
			}
		})
	}
}
