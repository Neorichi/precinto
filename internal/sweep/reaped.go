package sweep

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/Neorichi/precinto/internal/sweep/queue"
)

// D131: a run that holds state/locks/sweep.lock is the only process that
// drains the queue (SPEC §10.6); a worker turned away only touches
// sweep.requested. Its D63 quiet wait would keep a queued session whose
// writer has exited — sealed at once under R20 — in plaintext for the
// whole window, so the wait watches the queue: when a request whose
// wait_for process has exited (and that the pass does not handle itself)
// appears, the run seals its units at once, as a queue drain does, then
// sleeps the rest of the window. The units the pass waits on are decided
// again only once the full window has passed on the monotonic clock. The
// drain runs while the pass has no seal in flight, so the run's bound of
// Env.Parallel seals, large units alone, holds (R19, CONC-1).

// reapedPoll is how often a waiting run looks at the queue (a variable so
// tests can shorten it).
var reapedPoll = 500 * time.Millisecond

// midDrain is the queue drain of one pass's quiet wait: the pass's options
// (each queued request carries its own reason and writer) and the
// requests the pass handles itself or this wait already took.
type midDrain struct {
	o    Options
	seen map[string]bool
}

// waitPass is the job list of the sealJobs call whose wait drains the
// queue: a drained request that seals one of its units fills that job's
// result (final), so the unit is not decided again after the wait.
type waitPass struct {
	results []UnitResult
	index   map[string]int // unit key → job index
	final   map[int]bool
}

func newWaitPass(jobs []sealJob, results []UnitResult) *waitPass {
	p := &waitPass{results: results, index: map[string]int{}, final: map[int]bool{}}
	for i, j := range jobs {
		if _, dup := p.index[j.u.Key]; !dup && j.u.Key != "" {
			p.index[j.u.Key] = i
		}
	}
	return p
}

// armDrain makes the quiet wait of the pass about to decide qs's jobs
// drain the queue (D131), for a run that holds the sweep lock and is no
// dry run; the returned function disarms it.
func (r *run) armDrain(o Options, qs []queuedReq) func() {
	if !r.locked || o.DryRun {
		return func() {}
	}
	d := &midDrain{o: o, seen: map[string]bool{}}
	for _, q := range qs {
		d.seen[q.req.ID] = true
	}
	r.drain = d
	return func() { r.drain = nil }
}

// sleepQuiet sleeps the quiet window q (Env.Sleep). With a drain armed it
// wakes whenever a queued request whose writer has exited appears, seals
// it (drainReaped) and sleeps what is left of q, measured on the run's
// monotonic clock, so the units of the pass get their full window.
func (r *run) sleepQuiet(ctx context.Context, q time.Duration) error {
	if r.drain == nil {
		return r.p.sleep(ctx, q)
	}
	start, left := r.clock.Mono(), q
	for {
		wctx, cancel := context.WithCancel(ctx)
		var woke atomic.Bool
		done := make(chan struct{})
		go func() {
			defer close(done)
			if r.watchReaped(wctx) {
				woke.Store(true)
				cancel()
			}
		}()
		err := r.p.sleep(wctx, left)
		cancel()
		<-done
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if !woke.Load() {
			return err
		}
		r.drainReaped(ctx)
		// An uninterrupted wait is one Sleep(q), as without a drain; after
		// a wake only what is left of the window is slept.
		if left = q - (r.clock.Mono() - start); left <= 0 {
			return ctx.Err()
		}
	}
}

// watchReaped polls the queue every reapedPoll until ctx ends; it reports
// whether a request drainReaped would take appeared.
func (r *run) watchReaped(ctx context.Context) bool {
	t := time.NewTicker(reapedPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
		if r.reapedWaiting() {
			return true
		}
	}
}

// reapedWaiting reports a queued request the wait's drain takes: one the
// pass does not handle, not taken yet, whose writer has exited.
func (r *run) reapedWaiting() bool {
	d := r.drain
	reqs, err := queue.List(r.l.QueueDir)
	if err != nil || d == nil {
		return false
	}
	now := r.now()
	for _, q := range reqs {
		if !d.seen[q.ID] && r.reapedReady(q, now) {
			return true
		}
	}
	return false
}

// reapedReady reports a request whose wait condition holds now and whose
// writer (wait_for) has exited: R20 lets its seal skip the stability
// window. Requests without a writer wait for the rescan, which gives them
// their two looks.
func (r *run) reapedReady(q queue.Request, now time.Time) bool {
	if q.WaitFor.IsZero() || r.e.Procs == nil {
		return false
	}
	if !q.NotBefore.IsZero() && now.Before(q.NotBefore) {
		return false
	}
	if !q.Deadline.IsZero() && now.After(q.Deadline) {
		return false // the next drain reports and removes it
	}
	return !r.e.Procs.Alive(q.WaitFor)
}

// drainReaped seals, during the quiet wait, every queued request
// reapedWaiting reports, like a queue drain (queueJobs, finishQueue). A
// result for a unit of the waiting pass goes to that job when it sealed
// the unit, and is otherwise left to the pass's second look; the other
// results are the run's own.
func (r *run) drainReaped(ctx context.Context) {
	d := r.drain
	if d == nil {
		return
	}
	qs, jobs := r.queueJobsIf(ctx, d.o, func(q queue.Request, now time.Time) bool {
		if d.seen[q.ID] || !r.reapedReady(q, now) {
			return false
		}
		d.seen[q.ID] = true
		return true
	})
	if len(jobs) == 0 {
		return
	}
	results := r.sealPass(ctx, jobs, false)
	for k, res := range results {
		key := jobs[k].u.Key
		if p := r.pass; p != nil {
			if i, ok := p.index[key]; ok {
				if sealedOutcome(res.Outcome) {
					p.results[i], p.final[i] = res, true
				}
				continue
			}
		}
		r.decided(key, res)
		r.add(res)
	}
	r.finishQueue(d.o, qs, results)
}

// sealedOutcome reports an outcome that committed the unit's plaintext
// (sealed, unchanged, or committed with files it could not remove).
func sealedOutcome(o Outcome) bool {
	return o == OutSealed || o == OutUnchanged || o == OutRemoveFailed
}
