package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/wrapper"
)

// backend implements wrapper.Backend (docs/API.md §4) over the engine
// (harness adapters, sweep, live, ledger, queue) and the daemon. One
// backend serves one `precinto run`: it remembers the working directory of
// the plan and the launch lease, so that restores add the units they place
// to the lease before any plaintext appears (SPEC §9.3).
type backend struct {
	a    *app
	eng  engine
	keys *keySource

	mu    sync.Mutex
	cwd   string
	lease wrapper.Lease
}

var _ wrapper.Backend = (*backend)(nil)

func newBackend(a *app, eng engine) *backend {
	return &backend{a: a, eng: eng, keys: a.keys()}
}

// close destroys every file key the launch obtained.
func (b *backend) close() { b.keys.close() }

// Plan asks the harness adapter for the launch plan; the adapter sees the
// child's environment (SPEC §7.0: homes are resolved in the harness's own
// context).
func (b *backend) Plan(ctx context.Context, h harness.ID, cwd string, argv []string) (harness.LaunchPlan, error) {
	b.mu.Lock()
	b.cwd = cwd
	b.mu.Unlock()
	plan, err := b.eng.PlanLaunch(ctx, h, cwd, argv, b.a.env)
	if err != nil {
		return plan, err
	}
	if plan.Confirm == string(ui.MsgCodexConsent) && len(plan.Roots) > 0 {
		// D72: the wrapper runs Prepare only after a yes to the plan's
		// C10.consent (a no aborts the launch), so that is where the
		// consent is recorded in the folder's harness list.
		rootID, prepare := plan.Roots[0].ID, plan.Prepare
		plan.Prepare = func(ctx context.Context) error {
			if err := b.a.addCodexConsent(rootID); err != nil {
				// The launch goes on as planned; the next one asks again.
				b.a.say("run: %s", oneLineText(err.Error()))
			}
			if prepare != nil {
				return prepare(ctx)
			}
			return nil
		}
	}
	return plan, nil
}

// EnsureUnlocked unlocks the plan's folders in this terminal if needed
// (autostarting the daemon, SPEC §13.1).
func (b *backend) EnsureUnlocked(ctx context.Context, roots []config.Root, relay ipc.UIHandler) error {
	return b.a.ensureUnlocked(ctx, roots, relay)
}

// AcquireLease takes the launch lease before any restore (SPEC §9.3).
func (b *backend) AcquireLease(ctx context.Context, plan harness.LaunchPlan) (wrapper.Lease, error) {
	l := live.Lease{Proc: b.a.sys.self(), At: b.a.now().UTC()}
	if len(plan.Roots) > 0 {
		l.Root = plan.Roots[0].ID
	}
	held, err := b.eng.AcquireLease(plan.Lease, l)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.lease = held
	b.mu.Unlock()
	return held, nil
}

// beforePlace adds a unit to the launch lease before its plaintext is
// placed (RestoreRequest.BeforePlace). Without a lease nothing may be
// placed (fail closed).
func (b *backend) beforePlace(unit string) error {
	b.mu.Lock()
	l := b.lease
	b.mu.Unlock()
	if l == nil {
		return errNoLease
	}
	return l.Add(unit)
}

var errNoLease = errors.New("no launch lease is held")

// RestoreSync restores the plan's targeted units before exec; abort is
// closed on lock (the keys are destroyed with it).
func (b *backend) RestoreSync(ctx context.Context, plan harness.LaunchPlan, abort <-chan struct{}) (wrapper.RestoreSummary, error) {
	if len(plan.Sync) == 0 {
		return wrapper.RestoreSummary{}, nil
	}
	stop := b.destroyOn(abort)
	defer stop()
	mtimeNow := false
	for _, s := range plan.Sync {
		mtimeNow = mtimeNow || s.MtimeNow
	}
	rep, err := b.eng.Restore(ctx, b.keys, sweep.RestoreRequest{
		Select:      plan.Sync,
		BeforePlace: b.beforePlace,
		MtimeNow:    mtimeNow,
		Purpose:     ipc.PurposeRestore,
		StopOnErr:   true,
		Abort:       abort,
	})
	sum := summarize(rep)
	if mtimeNow && sum.Units > 0 {
		sum.Notices = append(sum.Notices, ui.Format(ui.MsgResumeOld, ui.Vars{Days: b.cleanupDays(ctx)}))
	}
	return sum, err
}

// RestoreBackground restores the plan's background units after exec, best
// effort (D38).
func (b *backend) RestoreBackground(ctx context.Context, plan harness.LaunchPlan, abort <-chan struct{}) {
	if len(plan.Background) == 0 {
		return
	}
	stop := b.destroyOn(abort)
	defer stop()
	_, _ = b.eng.Restore(ctx, b.keys, sweep.RestoreRequest{
		Select:      plan.Background,
		BeforePlace: b.beforePlace,
		Purpose:     ipc.PurposeRestore,
		Abort:       abort,
	})
}

// destroyOn destroys the file keys as soon as abort closes (REST-8: within
// 2 s of a lock event).
func (b *backend) destroyOn(abort <-chan struct{}) (stop func()) {
	if abort == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-abort:
			b.keys.destroy()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// Daemon returns a new connection on every call (autostarted, SPEC §13.1;
// CC-41): the wrapper keeps one for the subscription stream and one for
// requests, and dials again after a loss, so nothing is cached here.
func (b *backend) Daemon(ctx context.Context) (wrapper.Daemon, error) {
	c, err := b.a.dial(ctx, true)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// RecordLaunch writes the ledger "launch" events of a launch whose session
// id is known before exec (resume targets), one per lease key, carrying the
// harness home. Liveness evidence only (SPEC §9.1).
func (b *backend) RecordLaunch(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) error {
	sid := knownSID(plan.Resume)
	if sid == "" {
		return nil
	}
	b.mu.Lock()
	cwd := b.cwd
	b.mu.Unlock()
	base := ledger.Event{
		Type:      ledger.TypeLaunch,
		Harness:   string(plan.Harness),
		SID:       sid,
		Proc:      child,
		Wrapper:   true,
		Cwd:       cwd,
		ConfigDir: b.homeOf(plan),
		Roots:     rootIDs(plan.Roots),
	}
	keys := plan.Lease
	if len(keys) == 0 {
		return b.eng.AppendLedger(base)
	}
	events := make([]ledger.Event, 0, len(keys))
	for _, k := range keys {
		ev := base
		ev.LeaseKey = k
		events = append(events, ev)
	}
	return b.eng.AppendLedger(events...)
}

// SealAfterExit seals the session's units once the child was reaped (the
// writer is known to have exited, R20), or queues them (with a detached
// worker) when something still holds them (MsgSealDeferred).
func (b *backend) SealAfterExit(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) (wrapper.SealSummary, error) {
	sum := wrapper.SealSummary{SID: knownSID(plan.Resume)}
	if sum.SID == "" && len(plan.SealScope.SIDs) == 1 {
		sum.SID = plan.SealScope.SIDs[0]
	}
	if len(plan.Roots) == 0 {
		// An unmanaged launch (no folder: passthrough or outside every
		// folder, DC-39) seals nothing; a session it touched later is
		// sealed by its hooks and the sweeps (SEC-18).
		return sum, nil
	}
	// Only what the child owned (CC-21): the plan's scope narrowed to the
	// sessions whose ledger owner is the child, never widened to the plan's
	// folders, so other restored sessions of the same unlocked folder stay
	// in place (R4).
	scope := plan.SealScope
	scope.Procs = append(append([]platform.ProcID(nil), scope.Procs...), child)
	waitFor := child
	rep, err := b.eng.Seal(ctx, []harness.ID{plan.Harness}, scope, sweep.Options{
		Scope:   scope,
		Reason:  "wrapper-exit",
		WaitFor: &waitFor,
	})
	_, sum.Files, sum.Bytes = totals(rep, sweep.OutSealed, sweep.OutUnchanged)
	if countOutcome(rep, liveOutcomes...) > 0 || errors.Is(err, sweep.ErrLive) {
		qerr := b.eng.EnqueueSeal(queue.Request{
			Harness:   string(plan.Harness),
			SID:       sum.SID,
			Reason:    "wrapper-exit",
			WaitFor:   child,
			ConfigDir: b.homeOf(plan),
			Cwd:       b.cwdOf(),
			At:        b.a.now().UTC(),
		})
		if qerr == nil {
			qerr = b.a.spawnWorker("seal", "--queue")
		}
		if qerr != nil {
			sum.Failed = errClass(qerr)
			return sum, nil
		}
		sum.Deferred = true
		return sum, nil
	}
	if err != nil {
		sum.Failed = errClass(err)
	}
	return sum, nil
}

// HooksSeen reports whether a hook event arrived for the child (UX10).
func (b *backend) HooksSeen(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) (bool, error) {
	return b.eng.HooksSeen(plan.Harness, child)
}

// cleanupDays is Claude's cleanupPeriodDays for the C7.old notice.
func (b *backend) cleanupDays(ctx context.Context) int {
	if dir := b.a.env.Get(paths.EnvClaudeConfigDir); filepath.IsAbs(dir) {
		if n, err := b.eng.CleanupPeriodDays(dir); err == nil && n > 0 {
			return n
		}
	}
	if homes, err := b.eng.Homes(ctx, harness.ClaudeCode); err == nil {
		for _, h := range homes {
			if dir := h.Bases[capsule.BaseClaudeConfig]; dir != "" {
				if n, err := b.eng.CleanupPeriodDays(dir); err == nil && n > 0 {
					return n
				}
			}
		}
	}
	return 30
}

func (b *backend) cwdOf() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cwd
}

// homeOf is the harness home of a launch: CODEX_HOME from the plan's
// environment additions (the per-folder home, D31), else the Claude config
// dir of the child's environment.
func (b *backend) homeOf(plan harness.LaunchPlan) string {
	for _, kv := range plan.Env {
		if v, ok := strings.CutPrefix(kv, paths.EnvCodexHome+"="); ok && filepath.IsAbs(v) {
			return filepath.Clean(v)
		}
	}
	if plan.Harness == harness.ClaudeCode {
		dir := b.a.env.Get(paths.EnvClaudeConfigDir)
		if !filepath.IsAbs(dir) {
			if h := b.a.home(); h != "" {
				dir = filepath.Join(h, ".claude")
			}
		}
		if dir != "" {
			if real, err := b.a.sys.realpath(filepath.Clean(dir)); err == nil {
				return real
			}
			return filepath.Clean(dir)
		}
	}
	return ""
}

// knownSID is the session id a launch targets before exec, if any.
func knownSID(r harness.Resume) string {
	switch r.Kind {
	case harness.ResumeSID:
		return r.Value
	case harness.ResumePath:
		return strings.TrimSuffix(filepath.Base(r.Value), ".jsonl")
	}
	return ""
}

func rootIDs(rs []config.Root) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

// errClass is the short, content-free error class of a seal failure
// (MsgSealFailed {cause}): never an OS error string.
func errClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, sweep.ErrNoSpace), errors.Is(err, fsx.ErrNoSpace):
		return "disk full"
	case errors.Is(err, sweep.ErrTripwire):
		return "vault changed outside precinto"
	case errors.Is(err, sweep.ErrInaccessible):
		return "files not readable"
	case errors.Is(err, sweep.ErrLive):
		return "still in use"
	case exitFor(err) == exitVerify:
		return "verification failed"
	}
	return "error"
}

// summarize turns a restore report into the wrapper's summary.
func summarize(r *sweep.Report) wrapper.RestoreSummary {
	var s wrapper.RestoreSummary
	s.Units, s.Files, s.Bytes = totals(r, sweep.OutRestored, sweep.OutMerged)
	s.Conflicts = countOutcome(r, sweep.OutConflict)
	s.Skipped = countOutcome(r, sweep.OutSkipped)
	return s
}
