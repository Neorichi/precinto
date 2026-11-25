package sweep

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/live"
)

// UX-03, D109: a capsule whose Claude home config does not register is a
// configuration gap with a code of its own, never the unit-key class that
// stands for a capsule whose unit id does not match its key (exit 5).
func TestUnregisteredHomeHasItsOwnFailureCode(t *testing.T) {
	for _, err := range []error{harness.ErrUnregistered, fmt.Errorf("%w: no target base", harness.ErrUnregistered)} {
		if code, _ := failureCode(err); code != codeUnregistered {
			t.Fatalf("failureCode(%v) = %q, want %q", err, code, codeUnregistered)
		}
		res := failed(UnitResult{Kind: "claude-session", Unit: "0123456789abcdef0123456789abcdef"}, err)
		if !strings.HasPrefix(res.Detail, codeUnregistered+": ") || res.Outcome != OutFailed {
			t.Fatalf("result %+v", res)
		}
		rerr := (&Report{Units: []UnitResult{res}}).Err()
		if !errors.Is(rerr, harness.ErrUnregistered) || errors.Is(rerr, harness.ErrUnitKey) {
			t.Fatalf("Report.Err = %v, want ErrUnregistered and not ErrUnitKey", rerr)
		}
	}
	if code, _ := failureCode(harness.ErrUnitKey); code != codeUnitKey {
		t.Fatalf("ErrUnitKey code %q", code)
	}
}

// UX-17, D113: Options.OnQuietWait is called once, with the quiet window,
// just before a run's single wait, and never by a run that does not wait.
func TestOnQuietWaitAnnouncesTheWait(t *testing.T) {
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	k := te.sessionKey(sid1)
	// A first observation only: the run waits once and decides again.
	te.live.set(k, live.Verdict{Live: true, Evidence: []live.Evidence{{Reason: live.ReasonUnobserved, Weak: true}}})
	var mu sync.Mutex
	var got []time.Duration
	notify := func(d time.Duration) {
		mu.Lock()
		got = append(got, d)
		te.sleptMu.Lock()
		slept := len(te.slept)
		te.sleptMu.Unlock()
		if slept != 0 {
			t.Error("notified after the wait began")
		}
		mu.Unlock()
	}
	u := te.scanSession(sid1)
	if _, err := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{OnQuietWait: notify}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(got) != 1 || got[0] != 10*time.Second {
		t.Fatalf("notified %v, want once with the 10 s window", got)
	}
	got = nil
	mu.Unlock()
	// A sweep that waits announces it too; one with nothing to wait for
	// never does.
	te2 := newTestEnv(t)
	if _, err := te2.run().sweep(tctx(t), Options{OnQuietWait: notify}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("a run that did not wait announced %v", got)
	}
}
