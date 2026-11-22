//go:build crossgroup

package sweep_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/queue"
)

func plaintextOf(paths []string) int {
	n := 0
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil {
			n++
		}
	}
	return n
}

// L-1 / D131 acceptance (E2E-2): a lock sweep (`sweep --lock --root R`)
// that met a session first sits in its D63 quiet wait holding the sweep
// lock. A session of the folder ends — its writer has exited — and its
// SessionEnd hook queues it (wait_for = the writer, R20) and starts
// `seal --queue`, which finds the lock held and only touches
// sweep.requested. The queued session is sealed within seconds, while the
// lock sweep still waits, not after its quiet window. Real stack: Claude
// adapter, live engine, fsx, capsule, vault.
func TestL1QueuedSessionIsSealedDuringALockSweepsQuietWait(t *testing.T) {
	for _, tc := range []struct {
		name string
		same bool // the queued session is the one the lock sweep waits on
	}{{"same session", true}, {"other session", false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStack(t)
			const quiet = 120 * time.Second
			s.e.Live.Quiet = quiet
			s.e.Cfg.Policy.QuietWindow = config.Duration(quiet)
			s.e.Harness.Cfg.Policy.QuietWindow = config.Duration(quiet)

			waited := filterSID(s.session(t, xSID, ""), xSID)
			inWait, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			var mu sync.Mutex
			quietWaits := 0
			s.e.Sleep = func(ctx context.Context, d time.Duration) error {
				if d >= quiet/2 {
					mu.Lock()
					quietWaits++
					mu.Unlock()
					once.Do(func() { close(inWait) })
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				s.clock.Advance(d)
				return ctx.Err()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			type out struct {
				rep *sweep.Report
				err error
			}
			done := make(chan out, 1)
			go func() {
				rep, err := sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true, Quiet: true,
					Scope: harness.Scope{RootIDs: []string{xRoot}}})
				done <- out{rep, err}
			}()
			select {
			case <-inWait:
			case <-time.After(20 * time.Second):
				t.Fatal("the lock sweep never reached its quiet wait")
			}

			sid, queued := xSID, waited
			if !tc.same {
				sid, queued = xSID2, filterSID(s.session(t, xSID2, ""), xSID2)
			}
			if _, err := queue.Enqueue(s.h.Layout.QueueDir, queue.Request{Harness: string(harness.ClaudeCode), SID: sid,
				Reason: "other", WaitFor: platform.ProcID{PID: 4242, StartUS: 1}, ConfigDir: s.h.ClaudeConfig,
				Cwd: s.h.Root, At: s.clock.Now()}); err != nil {
				t.Fatal(err)
			}
			// The hook's `seal --queue` worker: turned away by the lock.
			if _, err := sweep.DrainQueue(ctx, s.e, sweep.Options{Reason: "session-end", Quiet: true}); err != sweep.ErrBusy {
				t.Fatalf("seal --queue beside the lock sweep: %v, want ErrBusy", err)
			}
			t0 := time.Now()
			for time.Since(t0) < 5*time.Second && plaintextOf(queued) > 0 {
				time.Sleep(20 * time.Millisecond)
			}
			if n := plaintextOf(queued); n > 0 {
				t.Fatalf("%d/%d files of the ended session stayed plaintext while the lock sweep waited", n, len(queued))
			}
			t.Logf("sealed %s after the request, during the lock sweep's quiet wait", time.Since(t0).Round(time.Millisecond))
			select {
			case res := <-done:
				t.Fatalf("the lock sweep ended before its window: %+v %v", res.rep, res.err)
			default:
			}
			close(release)
			res := <-done
			if res.err != nil {
				t.Fatal(res.err)
			}
			if n := plaintextOf(waited); n > 0 {
				t.Fatalf("the session the lock sweep waited on stayed plaintext: %d files", n)
			}
			sealed := map[string]int{}
			all, err := s.e.Log.All()
			if err != nil {
				t.Fatal(err)
			}
			for _, en := range all {
				if en.Kind == string(capsule.KindClaudeSession) {
					sealed[en.Unit]++
				}
			}
			want := 2
			if tc.same {
				want = 1
			}
			if len(sealed) != want {
				t.Fatalf("sealed sessions %v, want %d", sealed, want)
			}
			for k, n := range sealed {
				if n != 1 {
					t.Fatalf("session %s sealed %d times", k, n)
				}
			}
			if reqs, _ := queue.List(s.h.Layout.QueueDir); len(reqs) != 0 {
				t.Fatalf("queue left %+v", reqs)
			}
			mu.Lock()
			defer mu.Unlock()
			if quietWaits < 2 {
				t.Fatalf("quiet waits %d: the wait did not resume after the drain", quietWaits)
			}
		})
	}
}
