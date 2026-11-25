package main

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

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
	// placed counts the units restores added to the launch lease (D110).
	placed int
	// recorded holds the session ids the ledger has a launch event of
	// this child for (RecordLaunch, WatchSessions), in order, and current
	// the last one recorded: the session the child runs now (D107).
	recorded []string
	current  string
	// startedOf is the child whose wall-clock start started holds,
	// measured once, right after its spawn (childStarted, D157).
	startedOf platform.ProcID
	started   time.Time
}

// watchEvery is how often WatchSessions reads the child's registry entry.
var watchEvery = time.Second

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
	if held == nil {
		return nil, nil
	}
	ll := &launchLease{Lease: held, b: b, plan: plan}
	b.mu.Lock()
	b.lease = ll
	b.mu.Unlock()
	return ll, nil
}

// refusedSweepWait bounds how long the release of a refused launch's lease
// asks the daemon which folders are locked before it spawns their sweep.
const refusedSweepWait = 5 * time.Second

// launchLease is the lease of one launch (D147). A launch the wrapper
// refuses after its pre-exec restore placed units — a lock or the loss of
// the daemon during or right after RestoreSync, a command that cannot
// start — releases its lease without ever having started a child, so
// SealAfterExit never runs: its Release spawns the D110 sweep of every
// folder of the plan that is locked by then, since the lock's own sweep
// met those units leased and left them. A launch whose child started
// leaves that to SealAfterExit.
type launchLease struct {
	wrapper.Lease
	b    *backend
	plan harness.LaunchPlan

	mu      sync.Mutex
	started bool
	swept   bool
}

// SetChild records that the launch started its child.
func (l *launchLease) SetChild(child platform.ProcID) error {
	l.mu.Lock()
	l.started = true
	l.mu.Unlock()
	return l.Lease.SetChild(child)
}

// Release releases the lease; for a launch that never started its child it
// then sweeps the locked folders it restored into (once).
func (l *launchLease) Release() error {
	err := l.Lease.Release()
	l.mu.Lock()
	sweep := !l.started && !l.swept
	l.swept = l.swept || sweep
	l.mu.Unlock()
	if sweep {
		ctx, cancel := context.WithTimeout(context.Background(), refusedSweepWait)
		defer cancel()
		l.b.sweepLockedRoots(ctx, l.plan)
	}
	return err
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
	if err := l.Add(unit); err != nil {
		return err
	}
	b.mu.Lock()
	b.placed++
	b.mu.Unlock()
	return nil
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
// id is known before exec — a resume target, or the id PlanLaunch chose for
// a fresh Claude launch (D107, LaunchPlan.SessionID) — one per lease key,
// carrying the harness home and the plan's folders, so the session is the
// child's and managed even when no hook ever runs (the seal after exit
// finds it by Scope.Procs). Liveness evidence only (SPEC §9.1).
func (b *backend) RecordLaunch(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) error {
	b.childStarted(child)
	sid := launchSID(plan)
	if sid == "" {
		return nil
	}
	return b.recordSession(plan, child, sid, plan.Lease)
}

// recordSession appends the launch events of sid for child (one per lease
// key, or one without a key) and remembers that it did.
func (b *backend) recordSession(plan harness.LaunchPlan, child platform.ProcID, sid string, keys []string) error {
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
	events := []ledger.Event{base}
	if len(keys) > 0 {
		events = make([]ledger.Event, 0, len(keys))
		for _, k := range keys {
			ev := base
			ev.LeaseKey = k
			events = append(events, ev)
		}
	}
	err := b.eng.AppendLedger(events...)
	if err == nil {
		b.mu.Lock()
		if !slices.Contains(b.recorded, sid) {
			b.recorded = append(b.recorded, sid)
		}
		b.current = sid
		b.mu.Unlock()
	}
	return err
}

// WatchSessions implements wrapper.Backend (D107): until ctx ends it reads,
// every watchEvery, the child's own entry of Claude's live-session registry
// in the launch home (the engine checks that the entry is the child's:
// same pid, written after it started) and records the session it names
// whenever that is not the session last recorded — one the user switched
// to with /clear or /resume (or back), a fork, the session -c or the picker
// opened — so that it is managed, the child's newest (D20), and sealed
// after exit without hooks. Unmanaged launches are never watched (they
// leave no ledger, §14.3).
func (b *backend) WatchSessions(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) {
	if len(plan.Roots) == 0 || child.IsZero() {
		return
	}
	home := b.homeOf(plan)
	started := b.childStarted(child)
	t := time.NewTicker(watchEvery)
	defer t.Stop()
	for {
		if sids, err := b.eng.ChildSessions(ctx, plan.Harness, home, child, started); err == nil {
			for _, sid := range sids {
				b.mu.Lock()
				now := b.current == sid
				b.mu.Unlock()
				if !now {
					_ = b.recordSession(plan, child, sid, nil)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// childStarted returns the wall-clock start of child, measured the first
// time it is asked for, which RecordLaunch does right after the spawn
// (D157): btime cannot have moved between the spawn and then, so the start
// is exact for the whole run, even after a WSL 2 host sleep moved btime
// forward (the current btime would then make the start later than the
// real one), and a child started after such a sleep gets no earlier start
// either (the earliest btime of the boot would): WatchSessions compares
// registry entries with it, and what it records stays in the ledger.
func (b *backend) childStarted(child platform.ProcID) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.startedOf != child || b.started.IsZero() {
		b.startedOf, b.started = child, platform.StartTime(child)
	}
	return b.started
}

// SealAfterExit seals the session's units once the child was reaped (the
// writer is known to have exited, R20), or queues them (with a detached
// worker) when something still holds them (MsgSealDeferred). When a folder
// of the launch is locked by now and restores placed units under its lease
// (sessions restored in the background, the project unit), a keyless
// sweep of that folder seals what the lease kept from the lock's sweep
// (D110).
func (b *backend) SealAfterExit(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) (wrapper.SealSummary, error) {
	if len(plan.Roots) == 0 {
		// An unmanaged launch (no folder: passthrough or outside every
		// folder, DC-39) seals nothing; a session it touched later is
		// sealed by its hooks and the sweeps (SEC-18).
		return wrapper.SealSummary{SID: targetSID(plan)}, nil
	}
	defer b.sweepLockedRoots(ctx, plan)
	// The ledger's newest sessions of the child are read before the seal:
	// sealing a session moves its ledger into the capsule (S13).
	var latest []string
	if plan.Harness == harness.ClaudeCode {
		latest, _ = b.eng.LatestSessions(plan.Harness, child)
	}
	// Only what the child owned (CC-21): the plan's scope narrowed to the
	// sessions whose ledger owner is the child, never widened to the plan's
	// folders, so other restored sessions of the same unlocked folder stay
	// in place (R4). A scope naming sessions (a resume's target) also takes
	// those the child was seen running (WatchSessions) and the ledger's
	// newest of the child (D107); a fresh launch's names none, so it takes
	// every session the child owns.
	scope := plan.SealScope
	b.mu.Lock()
	recorded := append([]string(nil), b.recorded...)
	b.mu.Unlock()
	if len(scope.SIDs) > 0 {
		sids := append([]string(nil), scope.SIDs...)
		for _, sid := range append(recorded, latest...) {
			if !slices.Contains(sids, sid) {
				sids = append(sids, sid)
			}
		}
		scope.SIDs = sids
	}
	scope.Procs = append(append([]platform.ProcID(nil), scope.Procs...), child)
	waitFor := child
	rep, err := b.eng.Seal(ctx, []harness.ID{plan.Harness}, scope, sweep.Options{
		Scope:   scope,
		Reason:  "wrapper-exit",
		WaitFor: &waitFor,
	})
	sum := wrapper.SealSummary{SID: b.summarySID(ctx, plan, latest, rep, err != nil)}
	_, sum.Files, sum.Bytes = totals(rep, sweep.OutSealed, sweep.OutUnchanged)
	if countOutcome(rep, liveOutcomes...) > 0 || errors.Is(err, sweep.ErrLive) {
		if qerr := b.enqueueHeld(plan, child, scope, rep); qerr != nil {
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

// summarySID is the session the exit lines name and C5's resume hint
// resumes (D107): of the child's sessions, newest first — latest, the ones
// the ledger said it started last before the seal (hooks or launch events,
// D20), then those this run recorded (RecordLaunch, WatchSessions) from
// the last back — the first the seal found a unit of, so after a /clear it
// is the session the child ran last, not the one it started with; else the
// launch's own target (a resume, or a continue its adapter resolved);
// else, when the seal failed, the session the child ran last, which
// C6.failed names; "" when none is known, so C5 suggests `claude
// --continue` rather than a session that never wrote a transcript (claude
// --resume could not find it).
func (b *backend) summarySID(ctx context.Context, plan harness.LaunchPlan, latest []string, rep *sweep.Report, failed bool) string {
	b.mu.Lock()
	recorded := append([]string(nil), b.recorded...)
	current := b.current
	b.mu.Unlock()
	var order []string
	add := func(sid string) {
		if sid != "" && !slices.Contains(order, sid) {
			order = append(order, sid)
		}
	}
	if plan.Harness == harness.ClaudeCode {
		for _, sid := range latest {
			add(sid)
		}
		add(current)
		for i := len(recorded) - 1; i >= 0; i-- {
			add(recorded[i])
		}
	}
	if sid := b.firstWithUnit(ctx, order, rep); sid != "" {
		return sid
	}
	if sid := targetSID(plan); sid != "" {
		return sid
	}
	if failed && len(order) > 0 {
		return order[0]
	}
	return ""
}

// firstWithUnit returns the first of the Claude sessions sids whose
// session unit, in any registered home, is in rep, whatever its outcome:
// its transcript exists, so `claude --resume` finds it once restored.
func (b *backend) firstWithUnit(ctx context.Context, sids []string, rep *sweep.Report) string {
	if len(sids) == 0 || rep == nil {
		return ""
	}
	units := map[string]bool{}
	for _, u := range rep.Units {
		if u.Kind == capsule.KindClaudeSession {
			units[u.Unit] = true
		}
	}
	if len(units) == 0 {
		return ""
	}
	homes, err := b.eng.Homes(ctx, harness.ClaudeCode)
	if err != nil {
		return ""
	}
	for _, sid := range sids {
		for _, h := range homes {
			if k, err := b.eng.UnitKey(capsule.KindClaudeSession, harness.ClaudeCode, h.ID, "", sid); err == nil && units[k] {
				return sid
			}
		}
	}
	return ""
}

// enqueueHeld queues the units the seal after exit found still held, with
// a detached `seal --queue` worker (SPEC §10.6). Each request names its
// unit by key, so the worker finds it whatever session ids the child ran
// (a request with neither a key nor a sid matched nothing); the sid is
// carried only when the scope names exactly one, which narrows the
// worker's scan to it.
func (b *backend) enqueueHeld(plan harness.LaunchPlan, child platform.ProcID, scope harness.Scope, rep *sweep.Report) error {
	base := queue.Request{
		Harness:   string(plan.Harness),
		Reason:    "wrapper-exit",
		WaitFor:   child,
		ConfigDir: b.homeOf(plan),
		Cwd:       b.cwdOf(),
		At:        b.a.now().UTC(),
	}
	if len(scope.SIDs) == 1 {
		base.SID = scope.SIDs[0]
	}
	var reqs []queue.Request
	if rep != nil {
		for _, u := range rep.Units {
			if slices.Contains(liveOutcomes, u.Outcome) && unitKeyRE.MatchString(u.Unit) {
				r := base
				r.UnitKey = u.Unit
				reqs = append(reqs, r)
			}
		}
	}
	if len(reqs) == 0 {
		reqs = []queue.Request{base}
	}
	for _, r := range reqs {
		if err := b.eng.EnqueueSeal(r); err != nil {
			return err
		}
	}
	return b.a.spawnWorker("seal", "--queue")
}

// sweepLockedRoots spawns a keyless `precinto sweep --root DIR --quiet`
// for every folder of the plan that is locked now (a daemon that does not
// answer means locked, R4) when restores placed units under the launch
// lease: the lock's own sweep left them alone while the lease was held,
// and nothing else would seal them before the next lock or sweep (D110).
// The lease is released before the seal after exit, so the sweep sees
// them free.
func (b *backend) sweepLockedRoots(ctx context.Context, plan harness.LaunchPlan) {
	b.mu.Lock()
	placed := b.placed
	b.mu.Unlock()
	if placed == 0 {
		return
	}
	unlocked, err := b.a.grants()(ctx)
	if err != nil {
		unlocked = nil
	}
	seen := map[string]bool{}
	for _, r := range plan.Roots {
		if r.ID == "" || seen[r.ID] || unlocked[r.ID] || !filepath.IsAbs(r.Path) {
			continue
		}
		seen[r.ID] = true
		if err := b.a.spawnWorker("sweep", "--root", r.Path, "--quiet"); err != nil {
			b.a.say(textWorkerFailed, oneLineText(err.Error()))
		}
	}
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

// launchSID is the session id a launch writes as far as it is known before
// exec: its resume target, or the id PlanLaunch chose for a fresh launch
// (LaunchPlan.SessionID, D107). A job's session (attach, respawn) is
// written by its background worker, not by the child, so it is none of
// these, even when the seal scope names it.
func launchSID(plan harness.LaunchPlan) string {
	if sid := knownSID(plan.Resume); sid != "" {
		return sid
	}
	return plan.SessionID
}

// targetSID is the session a launch's plan targets: its resume target, or
// the single session its seal scope names (a continue or a job the
// adapter resolved).
func targetSID(plan harness.LaunchPlan) string {
	if sid := knownSID(plan.Resume); sid != "" {
		return sid
	}
	if len(plan.SealScope.SIDs) == 1 {
		return plan.SealScope.SIDs[0]
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
