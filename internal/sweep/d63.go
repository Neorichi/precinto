package sweep

import (
	"context"
	"path/filepath"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/live"
)

// D63: stability is proven inside each sealing process. Sweeps, seals and
// the queue worker are separate processes (SPEC §13.1), so each starts with
// no observations and the engine reports every unit seen for the first
// time as live.ReasonUnobserved (weak). After its first decision pass a run
// waits once for the quiet window (bounded by its context and
// Options.Deadline; the sweep lock stays held) and decides those units
// again: files that kept their identity across both looks are stable. No
// wait when the only known writer was reaped (R20: --wait-pid, wrapper
// exit), because the engine then skips the stability evidence.

// defaultQuiet is the quiet window when the engine has none: ≤ 0 means
// 120 s, never immediate (live.Engine.Quiet).
const defaultQuiet = 120 * time.Second

// quietWindow is the engine's stability window.
func (r *run) quietWindow() time.Duration {
	if r.e.Live != nil && r.e.Live.Quiet > 0 {
		return r.e.Live.Quiet
	}
	return defaultQuiet
}

// unobservedOnly reports whether every piece of evidence is a first
// observation: the unit is live only because this process has not looked
// at it across a quiet window yet.
func unobservedOnly(ev []live.Evidence) bool {
	if len(ev) == 0 {
		return false
	}
	for _, e := range ev {
		if e.Reason != live.ReasonUnobserved {
			return false
		}
	}
	return true
}

// unobservedResult reports a unit result that is live only by first
// observation.
func unobservedResult(res UnitResult) bool {
	return res.Outcome == OutLive && unobservedOnly(res.Evidence)
}

// waitQuiet waits once per run for the quiet window (D63) and reports
// whether it did. It does not wait when the window would end after the
// run's deadline or when ctx ends first; a run tries at most once.
func (r *run) waitQuiet(ctx context.Context, deadline time.Time) bool {
	r.quietMu.Lock()
	defer r.quietMu.Unlock()
	if r.quietTried {
		return false
	}
	q := r.quietWindow()
	if !deadline.IsZero() && r.now().Add(q).After(deadline) {
		return false // the units are reported live ("unobserved")
	}
	if ctx.Err() != nil {
		return false
	}
	r.quietTried = true
	return r.p.sleep(ctx, q) == nil
}

// primeNotes takes the first observation of every note candidate of root
// (the note's own subject; its writer sessions are decided with the other
// units) so that one quiet-window wait covers notes too. It reports
// whether a note is live only by first observation.
func (r *run) primeNotes(ctx context.Context, root config.Root, cands map[string]*noteCand) bool {
	if root.MD == config.MDOff || len(cands) == 0 {
		return false
	}
	rootDir, err := r.p.fs.OpenBase(root.Path)
	if err != nil {
		return false
	}
	defer rootDir.Close()
	any := false
	for rel := range cands {
		if ctx.Err() != nil {
			return any
		}
		st, err := rootDir.Lstat(rel)
		if err != nil || !st.IsRegular() {
			continue
		}
		u, err := r.noteUnit(root, rel, st)
		if err != nil {
			continue
		}
		if v, err := r.p.live.Decide(ctx, subjectOf(u, nil), nil); err == nil && v.Live && unobservedOnly(v.Evidence) {
			any = true
		}
	}
	return any
}

// primeHistory takes the first observation of every Claude home's
// history.jsonl (the rotation's liveness subject), reporting whether one is
// live only by first observation.
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
		if v, isLive := r.checkLive(ctx, ad, pseudo, nil); isLive && unobservedOnly(v.Evidence) {
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
