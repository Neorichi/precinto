package sweep

import (
	"context"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/live"
)

// D63: stability is proven inside each sealing process. Sweeps, seals and
// the queue worker are separate processes (SPEC §13.1), so each starts with
// no observations and the engine reports every unit seen for the first
// time as live.ReasonUnobserved (weak). After its first decision pass a run
// waits once for the quiet window (bounded by its context and
// Options.Deadline; the sweep lock stays held) and decides those units
// again: files that kept their identity across both looks are stable. No
// wait when the only known writer was reaped (R20: --wait-pid, wrapper
// exit), because the engine then skips the stability evidence. A run that
// holds the sweep lock seals, during that wait, the queued requests whose
// writer has exited (D131, reaped.go), then waits out the rest of the
// window.

// defaultQuiet is the quiet window when the engine has none: ≤ 0 means
// 120 s, never immediate (live.Engine.Quiet).
const defaultQuiet = 120 * time.Second

// Details of units that a run leaves live for stability reasons (sweeps
// report them bare; explicit seals prefix the live code, exit 4).
const (
	// reasonUnobserved: live only by a first observation (or other
	// evidence the quiet window resolves) and the run could not wait
	// (deadline or cancellation first).
	reasonUnobserved = "unobserved"
	// reasonHoldCapped: a unit of a locked folder still held live after
	// the quiet wait by weak evidence only (SPEC §9.5); status and doctor
	// show it, PlaintextSummary counts it.
	reasonHoldCapped = "hold-capped"
)

// quietWindow is the engine's stability window.
func (r *run) quietWindow() time.Duration {
	if r.e.Live != nil && r.e.Live.Quiet > 0 {
		return r.e.Live.Quiet
	}
	return defaultQuiet
}

// quietResolves reports evidence that the quiet-window wait resolves: a
// first observation; files changed or restored within the window (the
// observer restarts its window at this look, a restore ages out); an mtime
// a little in the future; a non-current session (D20) that is not stable
// yet. Process, registry, lease, job, open-descriptor and reference
// evidence is never resolved by waiting.
func quietResolves(e live.Evidence) bool {
	switch e.Reason {
	case live.ReasonUnobserved, live.ReasonUnstable, live.ReasonFutureTime, live.ReasonWarm:
		return true
	}
	return false
}

// quietOnly reports evidence made only of pieces the quiet wait resolves.
func quietOnly(ev []live.Evidence) bool {
	if len(ev) == 0 {
		return false
	}
	for _, e := range ev {
		if !quietResolves(e) {
			return false
		}
	}
	return true
}

// weakOnly reports evidence made only of weak pieces (S14: process names,
// file times, first observations, a registry naming a non-harness pid).
func weakOnly(ev []live.Evidence) bool {
	if len(ev) == 0 {
		return false
	}
	for _, e := range ev {
		if !e.Weak {
			return false
		}
	}
	return true
}

// liveOutcome reports results the liveness evidence holds (leases never
// count: a lease is a running launch, never capped).
func liveOutcome(res UnitResult) bool { return res.Outcome == OutLive || res.Outcome == OutWarm }

// waitable reports a first-pass result that is live only by evidence the
// quiet-window wait resolves (D63).
func waitable(res UnitResult) bool { return liveOutcome(res) && quietOnly(res.Evidence) }

// weakLive reports a result held live by weak evidence only.
func weakLive(res UnitResult) bool { return liveOutcome(res) && weakOnly(res.Evidence) }

// wantsWait reports first-look evidence that asks for the quiet wait:
// evidence the wait resolves, or weak evidence only, which the second look
// tells apart from a first observation before it is reported hold-capped.
func wantsWait(ev []live.Evidence) bool { return quietOnly(ev) || weakOnly(ev) }

// withDetail replaces the Detail of a live result, keeping the live code
// of explicit seals (exit 4).
func withDetail(res UnitResult, explicit bool, why string) UnitResult {
	if explicit {
		res.Detail = codeLive + ": " + why
	} else {
		res.Detail = why
	}
	return res
}

// sealJob is one unit to seal with its own options: queued requests carry
// their reason and their writer (WaitFor); sweeps and seals share one.
type sealJob struct {
	u harness.Unit
	o Options
}

func jobsOf(units []harness.Unit, o Options) []sealJob {
	jobs := make([]sealJob, len(units))
	for i, u := range units {
		jobs[i] = sealJob{u: u, o: o}
	}
	return jobs
}

// sealJobs seals jobs in two decision passes around the run's single
// quiet-window wait (D63) and reports every result, in input order. A job
// live only by evidence the wait resolves asks for the wait and is decided
// again after it; so does a job held only by weak evidence, which, still
// live then in a locked folder, is reported hold-capped (SPEC §9.5). When
// the run cannot wait (deadline or cancellation first) the waitable jobs
// are reported live with the Detail "unobserved". primed means other
// subjects of the run (notes, history) were observed for the first time
// and need the wait too. A queued request drained during the wait (D131)
// that seals one of the jobs gives it its result; that job is not decided
// again.
func (r *run) sealJobs(ctx context.Context, jobs []sealJob, deadline time.Time, explicit, primed bool) []UnitResult {
	results := r.sealPass(ctx, jobs, explicit)
	var again []int
	need := primed
	for i, res := range results {
		if waitable(res) || weakLive(res) {
			need = true
			again = append(again, i)
		}
	}
	waited := false
	if need {
		pass := newWaitPass(jobs, results)
		r.pass = pass
		waited = r.waitQuiet(ctx, deadline)
		r.pass = nil
		again = slices.DeleteFunc(again, func(i int) bool { return pass.final[i] })
	}
	if waited && len(again) > 0 {
		sub := make([]sealJob, len(again))
		for k, i := range again {
			sub[k] = jobs[i]
		}
		for k, res := range r.sealPass(ctx, sub, explicit) {
			results[again[k]] = res
		}
	}
	var unlocked map[string]bool
	for _, i := range again {
		res := results[i]
		switch {
		case waited && weakLive(res):
			if unlocked == nil {
				unlocked = r.unlocked(ctx)
			}
			if r.unitLocked(jobs[i].u, unlocked) {
				results[i] = withDetail(res, explicit, reasonHoldCapped)
			}
		case !waited && waitable(res):
			results[i] = withDetail(res, explicit, reasonUnobserved)
		}
	}
	for i, res := range results {
		r.decided(jobs[i].u.Key, res)
		r.add(res)
	}
	return results
}

// waitQuiet waits once per run for the quiet window (D63) and reports
// whether it waited now. It does not wait when the window would end after
// the run's deadline or its context's, or when ctx has ended; a run tries
// at most once, and later passes rely on the observations it took.
func (r *run) waitQuiet(ctx context.Context, deadline time.Time) bool {
	q := r.quietWindow()
	r.quietMu.Lock()
	switch {
	case r.quietTried:
		r.quietMu.Unlock()
		return false
	case !deadline.IsZero() && r.now().Add(q).After(deadline):
		r.quietMu.Unlock()
		return false // the units are reported live ("unobserved")
	case ctx.Err() != nil:
		r.quietMu.Unlock()
		return false
	}
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < q {
		r.quietMu.Unlock()
		return false
	}
	r.quietTried = true
	notify := r.onQuiet
	r.quietMu.Unlock()
	if notify != nil {
		notify(q)
	}
	if err := r.sleepQuiet(ctx, q); err != nil {
		return false
	}
	r.quietMu.Lock()
	r.quietDone = true
	r.quietMu.Unlock()
	return true
}

// resetQuiet starts a new sweep pass: a rescan run for the sweeps a lock
// holder turned away is a sweep of its own and gets its own wait (the
// units of a folder locked meanwhile are seen for the first time then).
func (r *run) resetQuiet() {
	r.quietMu.Lock()
	defer r.quietMu.Unlock()
	r.quietTried, r.quietDone = false, false
}

// holdCapped reports whether the run waited for the quiet window, so a
// unit still held only by weak evidence is capped (SPEC §9.5).
func (r *run) holdCapped(res UnitResult, u harness.Unit, unlocked map[string]bool) bool {
	r.quietMu.Lock()
	done := r.quietDone
	r.quietMu.Unlock()
	return done && weakLive(res) && r.unitLocked(u, unlocked)
}

// decisions records the final result of every unit a run decided, so later
// steps of the run (notes whose writer sessions were sealed) need not look
// at plaintext that is gone.
type decisions struct {
	mu sync.Mutex
	m  map[string]UnitResult
}

func (r *run) decided(key string, res UnitResult) {
	if key == "" {
		return
	}
	r.dec.mu.Lock()
	defer r.dec.mu.Unlock()
	if r.dec.m == nil {
		r.dec.m = map[string]UnitResult{}
	}
	r.dec.m[key] = res
}

// sealedNow reports whether this run sealed the unit (its plaintext was
// committed: sealed, unchanged, or committed with files it could not
// remove).
func (r *run) sealedNow(key string) bool {
	r.dec.mu.Lock()
	defer r.dec.mu.Unlock()
	res, ok := r.dec.m[key]
	return ok && sealedOutcome(res.Outcome)
}

// primeNotes takes the first observation of every note candidate of root
// and of the writer sessions that are not decided with the run's other
// units (skip), so that one quiet-window wait covers them too. It reports
// whether one asks for the wait (wantsWait).
func (r *run) primeNotes(ctx context.Context, root config.Root, cands map[string]*noteCand, skip map[string]bool) bool {
	if root.MD == config.MDOff || len(cands) == 0 {
		return false
	}
	rootDir, err := r.p.fs.OpenBase(root.Path)
	if err != nil {
		return false
	}
	defer rootDir.Close()
	any := false
	primed := map[string]bool{}
	for rel, c := range cands {
		if ctx.Err() != nil {
			return any
		}
		for _, w := range c.writers {
			if skip[w.Key] || primed[w.Key] {
				continue
			}
			primed[w.Key] = true
			if v, isLive := r.checkLive(ctx, adapterFor(r.e, w.Harness), w, nil); isLive && wantsWait(v.Evidence) {
				any = true
			}
		}
		st, err := rootDir.Lstat(rel)
		if err != nil || !st.IsRegular() {
			continue
		}
		u, err := r.noteUnit(root, rel, st)
		if err != nil {
			continue
		}
		if v, err := r.p.live.Decide(ctx, subjectOf(u, nil), nil); err == nil && v.Live && wantsWait(v.Evidence) {
			any = true
		}
	}
	return any
}

// primeHistory takes the first observation of every Claude home's
// history.jsonl (the rotation's liveness subject), reporting whether one
// asks for the quiet wait (wantsWait).
func (r *run) primeHistory(ctx context.Context) bool {
	ad := adapterFor(r.e, harness.ClaudeCode)
	if ad == nil {
		return false
	}
	homes, err := ad.Homes(ctx, r.e.Harness)
	if err != nil {
		return false
	}
	any := false
	for _, h := range homes {
		if ctx.Err() != nil {
			return any
		}
		pseudo, ok := r.historySubject(h)
		if !ok {
			continue
		}
		if v, isLive := r.checkLive(ctx, ad, pseudo, nil); isLive && wantsWait(v.Evidence) {
			any = true
		}
	}
	return any
}

// historySubject is the liveness subject of one home's history rotation.
func (r *run) historySubject(h harness.Home) (harness.Unit, bool) {
	cfgDir := h.Bases[capsule.BaseClaudeConfig]
	if cfgDir == "" {
		return harness.Unit{}, false
	}
	jkey, err := r.historyJournalKey(h)
	if err != nil {
		return harness.Unit{}, false
	}
	return harness.Unit{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeHistory, Key: jkey, Home: h,
		Paths: []string{filepath.Join(cfgDir, historyRel)}}, true
}
