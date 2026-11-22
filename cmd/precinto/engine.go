package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/harness/generic"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/vault"
	"github.com/precinto/precinto/internal/wrapper"
	"github.com/precinto/precinto/inventories"
)

// engine is everything the CLI does through internal/sweep and the packages
// a sweep.Env bundles (harness adapters, liveness, ledger, queue, codex
// homes). The production implementation (sweepEngine) builds one sweep.Env
// per invocation; unit tests use a fake. Every operation that returns a
// report also folds Report.Err into its error, so callers map one error to
// an exit code.
type engine interface {
	Sweep(ctx context.Context, o sweep.Options) (*sweep.Report, error)
	// Seal scans the units of the given harnesses (all when empty) in scope
	// and seals them (sweep.Seal); it never needs a key.
	Seal(ctx context.Context, harnesses []harness.ID, scope harness.Scope, o sweep.Options) (*sweep.Report, error)
	DrainQueue(ctx context.Context, o sweep.Options) (*sweep.Report, error)
	Restore(ctx context.Context, keys sweep.KeySource, r sweep.RestoreRequest) (*sweep.Report, error)
	RestoreMarkdown(ctx context.Context, keys sweep.KeySource, root config.Root) (*sweep.Report, error)
	MergeHistory(ctx context.Context, keys sweep.KeySource, rootID string) (*sweep.Report, error)
	List(ctx context.Context, o sweep.ListOptions) ([]sweep.UnitInfo, error)
	PlaintextSummary(ctx context.Context) ([]sweep.Plaintext, error)
	OpenNotes(ctx context.Context, keys sweep.KeySource, markers []string) (*sweep.Report, error)
	CatNote(ctx context.Context, keys sweep.KeySource, marker string, w io.Writer) error
	ParseMarker(path string) (string, error)
	Resolve(ctx context.Context, keys sweep.KeySource, path, keep string) (*sweep.Report, error)
	Forget(ctx context.Context, unit string) (*sweep.Report, error)
	Prune(ctx context.Context, o sweep.PruneOptions) (*sweep.Report, error)
	Generations(unit string) ([]sweep.Generation, error)
	ReconcileCodex(ctx context.Context, keys sweep.KeySource, rootID string, prefer sweep.CodexPrefer) (*sweep.Report, error)
	// LatestCapsuleHeader returns the age header of the most recently
	// sealed logged capsule (ok=false when none is logged).
	LatestCapsuleHeader() (header []byte, ok bool, err error)

	// Harness facts.
	Homes(ctx context.Context, h harness.ID) ([]harness.Home, error)
	UnitKey(k capsule.Kind, h harness.ID, homeID, rootID, unitID string) (string, error)
	CleanupPeriodDays(configDir string) (int, error)
	PlanLaunch(ctx context.Context, h harness.ID, cwd string, argv []string, host paths.Env) (harness.LaunchPlan, error)
	// HarnessFor maps an executable name to the harness it runs (built-in
	// adapters, then enabled experimental inventories).
	HarnessFor(exe string) (harness.ID, bool)
	// Inventory returns the embedded inventory of a harness.
	Inventory(id harness.ID) (harness.Inventory, bool)
	ClaudeSettingsJSON(p config.Policy) string

	// Leases, ledger and queue.
	AcquireLease(keys []string, l live.Lease) (wrapper.Lease, error)
	AppendLedger(events ...ledger.Event) error
	HooksSeen(h harness.ID, child platform.ProcID) (bool, error)
	// LatestSessions returns the sessions the ledger says child started,
	// or was launched into, most recently (ledger.ByProc, D20): the session
	// it ran last, whoever recorded it (the wrapper's launch events, the
	// hooks' start events).
	LatestSessions(h harness.ID, child platform.ProcID) ([]string, error)
	// ChildSessions returns the session ids the harness's live-session
	// registry in configDir names for the running process child (Claude:
	// sessions/<pid>.json written by that process, D107); nil for harnesses
	// without one.
	ChildSessions(ctx context.Context, h harness.ID, configDir string, child platform.ProcID) ([]string, error)
	EnqueueSeal(r queue.Request) error

	// Codex per-folder homes (D31).
	PrepareCodexHome(ctx context.Context, rootID string, forceConfig bool) error
	// WrongHomeRollouts counts, per folder id, the Codex rollouts of
	// protected folders saved in the user's own Codex home
	// (codex.WrongHomeRollouts, CC-18; C9.codexoutside).
	WrongHomeRollouts(ctx context.Context) (map[string]int, error)
}

// registerBuiltins registers the built-in adapters in the harness registry
// once per process (docs/API.md §4: called from cmd/precinto wiring).
var registerBuiltins = sync.OnceValue(func() []harness.Adapter {
	ads := []harness.Adapter{claude.New(), codex.New()}
	for _, a := range ads {
		harness.Register(a)
	}
	return ads
})

// sweepEngine is the production engine.
type sweepEngine struct {
	layout   paths.Layout
	ledger   *ledger.Ledger
	adapters []harness.Adapter
	invs     []harness.Inventory
	// register saves homes in config.toml (D109; app.registerHomes).
	register func(add []config.Home) (config.Config, error)

	// mu guards the configuration and the environments built from it: a
	// seal or sweep registers the homes it meets (D109) while other
	// goroutines of the same `precinto run` restore or record.
	mu   sync.Mutex
	cfg  config.Config
	henv harness.Env
	senv sweep.Env
}

// envs returns the current configuration and environments.
func (e *sweepEngine) envs() (config.Config, harness.Env, sweep.Env) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg, e.henv, e.senv
}

// sweepEnv is the current sweep.Env.
func (e *sweepEngine) sweepEnv() sweep.Env {
	_, _, s := e.envs()
	return s
}

// harnessEnv is the current harness.Env.
func (e *sweepEngine) harnessEnv() harness.Env {
	_, h, _ := e.envs()
	return h
}

// newSweepEngine builds the production engine: precinto's directories,
// the name salt, the liveness engine, the ledger, the registered adapters
// (plus experimental inventories that are enabled, or all of them with
// experimental), the vault store, the capsule log, the journal and the
// daemon-backed grants.
func newSweepEngine(ctx context.Context, a *app, experimental bool) (engine, error) {
	l, err := a.layout()
	if err != nil {
		return nil, err
	}
	cfg, err := a.config()
	if err != nil {
		return nil, err
	}
	// D142: the engine seals, lists and scans the folders the agent
	// enforces, not only config.toml's (a removal waiting for its
	// confirmation keeps its folder protected).
	cfg = a.enforcedConfig(cfg, l)
	if err := l.EnsureDirs(); err != nil {
		return nil, err
	}
	salt, err := capsule.LoadSalt(l.NameSalt)
	if err != nil {
		return nil, err
	}
	procs := a.sys.procs()
	clock := a.sys.clock()
	le := &live.Engine{
		Procs:     procs,
		Clock:     clock,
		LeasesDir: l.LeasesDir,
		Observer:  live.NewObserver(clock),
		Quiet:     cfg.Policy.QuietWindow.D(),
		HoldCap:   cfg.Policy.HoldCap.D(),
	}
	led := ledger.Open(l.SessionsDir)
	henv := harness.Env{
		Cfg:    cfg,
		Layout: l,
		Ledger: led,
		Index:  func(h string) *ledger.Index { return ledger.OpenIndex(l.ProjectsDir, h) },
		Live:   le,
		Procs:  procs,
		Clock:  clock,
		Salt:   salt,
		Host:   a.env,
	}
	adapters := append([]harness.Adapter(nil), registerBuiltins()...)
	gens, err := generic.Adapters(inventories.FS, true)
	if err != nil {
		return nil, err
	}
	for _, g := range gens {
		h := cfg.Harness[string(g.ID())]
		if experimental || (h.Enabled && h.Experimental) {
			adapters = append(adapters, g)
		}
	}
	invs, err := harness.LoadInventories(inventories.FS)
	if err != nil {
		return nil, err
	}
	e := &sweepEngine{
		layout:   l,
		cfg:      cfg,
		henv:     henv,
		ledger:   led,
		adapters: adapters,
		invs:     invs,
		register: func(add []config.Home) (config.Config, error) {
			next, err := a.registerHomes(add)
			if err != nil {
				return config.Config{}, err
			}
			return a.enforcedConfig(next, l), nil
		},
	}
	e.senv = sweep.Env{
		Cfg:      cfg,
		Harness:  henv,
		Adapters: adapters,
		Vaults:   vault.OpenStore(l.VaultsDir, l.VerifiedDir, l.FactorsDir),
		Log:      capslog.Open(l.CapsuleLog),
		Journal:  journal.Open(l.JournalDir),
		Live:     le,
		Procs:    procs,
		Clock:    clock,
		Grants:   a.grants(),
		Floor:    floorPolicy(cfg, l).Floor(),
		Sealer:   "precinto " + buildVersion(),
		Parallel: 2,
		Sleep:    a.sys.sweepSleep, // nil in production: a real timer (D63)
	}
	return e, nil
}

// floorPolicy is the policy whose min_free every seal and restore of this
// process keeps free on its volume (D76): config.toml merged with
// state/policy.pinned by config.Strictest, the policy the daemon enforces
// (D55); without a readable pin — before the first protect (D68) or after
// tampering — the compiled-in defaults take the pin's place, as in the
// daemon. User commands and the daemon's workers (this same binary) build
// their sweep.Env the same way. A process without keys cannot verify the
// pin's MACs: a forged pin can only raise the floor above config.toml's;
// lowering it below the pinned value needs the TTY confirmation (D48).
func floorPolicy(cfg config.Config, l paths.Layout) config.Policy {
	other := config.Default()
	if pinned, ok, err := config.LoadPinned(l.PolicyPinned); err == nil && ok {
		other = pinned.Config
	}
	return config.Strictest(cfg, other).Policy
}

// withErr folds the report's own failure summary into err.
func withErr(r *sweep.Report, err error) (*sweep.Report, error) {
	if r != nil {
		if rerr := r.Err(); rerr != nil {
			err = errors.Join(err, rerr)
		}
	}
	return r, err
}

func (e *sweepEngine) Sweep(ctx context.Context, o sweep.Options) (*sweep.Report, error) {
	if !o.DryRun {
		e.registerSeenHomes(ctx)
	}
	return withErr(sweep.Sweep(ctx, e.sweepEnv(), o))
}

func (e *sweepEngine) Seal(ctx context.Context, hs []harness.ID, scope harness.Scope, o sweep.Options) (*sweep.Report, error) {
	// D106: `seal --adopt` asks the adapters for the sessions they find
	// only by their transcripts' cwd (S6), as sweep.scanAll does for
	// sweeps; the scope a caller passes may not carry the flag.
	if o.Adopt || o.Scope.Adopt {
		scope.Adopt = true
	}
	if !o.DryRun {
		e.registerSeenHomes(ctx)
	}
	henv := e.harnessEnv()
	var units []harness.Unit
	var scanErr error
	for _, ad := range e.adapters {
		if len(hs) > 0 && !slices.Contains(hs, ad.ID()) {
			continue
		}
		us, err := ad.Scan(ctx, henv, scope)
		if err != nil {
			// A harness whose scan failed keeps its plaintext; the others
			// are still sealed (fail closed per harness).
			scanErr = errors.Join(scanErr, fmt.Errorf("scan %s: %w", ad.ID(), err))
			continue
		}
		units = append(units, us...)
	}
	if len(units) == 0 {
		return &sweep.Report{}, scanErr
	}
	r, err := withErr(sweep.Seal(ctx, e.sweepEnv(), units, o))
	return r, errors.Join(scanErr, err)
}

func (e *sweepEngine) DrainQueue(ctx context.Context, o sweep.Options) (*sweep.Report, error) {
	if !o.DryRun {
		e.registerSeenHomes(ctx)
	}
	return withErr(sweep.DrainQueue(ctx, e.sweepEnv(), o))
}

// registerSeenHomes implements SPEC §7.0 for the processes that seal
// (D109): every Claude home a seal, sweep or queue worker visits that
// config.toml does not register — a config dir the ledger saw (hooks run in
// Claude's own environment), the default home of this environment — and
// that exists is registered before anything is sealed from it, realpath'd
// as the adapter resolved it, with its tmp and cache bases. Only
// registered homes are restore targets, so a session sealed from a home
// registered nowhere could never be restored. Adding a home is a
// strengthening edit that applies at once (D48); config.toml is read again
// right before the write, so edits made since this process loaded it are
// kept. A failure leaves config.toml as it was: the seal goes on, and the
// next one tries again.
func (e *sweepEngine) registerSeenHomes(ctx context.Context) {
	if e.register == nil {
		return
	}
	ad, err := e.adapter(harness.ClaudeCode)
	if err != nil {
		return
	}
	cfg, henv, _ := e.envs()
	homes, err := ad.Homes(ctx, henv)
	if err != nil {
		return
	}
	known := map[string]bool{}
	for _, h := range cfg.Harness[string(harness.ClaudeCode)].Homes {
		known[filepath.Clean(h.Dir)] = true
	}
	var add []config.Home
	for _, h := range homes {
		dir := h.Bases[capsule.BaseClaudeConfig]
		if !filepath.IsAbs(dir) || known[filepath.Clean(dir)] {
			continue
		}
		if st, err := fsx.Lstat(dir); err != nil || !st.IsDir() {
			continue // never seen on disk: nothing is sealed from it
		}
		known[filepath.Clean(dir)] = true
		add = append(add, config.Home{Dir: filepath.Clean(dir), Tmp: h.Bases[capsule.BaseClaudeTmp],
			Cache: h.Bases[capsule.BaseClaudeCache], SeenAt: e.sweepEnv().Clock.Now().UTC(), Default: h.Default})
	}
	if len(add) == 0 {
		return
	}
	next, err := e.register(add)
	if err != nil {
		return
	}
	// The folders this engine seals stay (D142: those of the confirmed
	// settings, and those a running agent reported, which config.toml
	// may not hold).
	next = config.WithRoots(next, cfg.Roots...)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = next
	e.henv.Cfg = next
	e.senv.Cfg = next
	e.senv.Harness.Cfg = next
}

func (e *sweepEngine) Restore(ctx context.Context, keys sweep.KeySource, r sweep.RestoreRequest) (*sweep.Report, error) {
	return withErr(sweep.Restore(ctx, e.sweepEnv(), keys, r))
}

func (e *sweepEngine) RestoreMarkdown(ctx context.Context, keys sweep.KeySource, root config.Root) (*sweep.Report, error) {
	return withErr(sweep.RestoreMarkdown(ctx, e.sweepEnv(), keys, root))
}

func (e *sweepEngine) MergeHistory(ctx context.Context, keys sweep.KeySource, rootID string) (*sweep.Report, error) {
	return withErr(sweep.MergeHistory(ctx, e.sweepEnv(), keys, rootID))
}

func (e *sweepEngine) List(ctx context.Context, o sweep.ListOptions) ([]sweep.UnitInfo, error) {
	return sweep.List(ctx, e.sweepEnv(), o)
}

func (e *sweepEngine) PlaintextSummary(ctx context.Context) ([]sweep.Plaintext, error) {
	return sweep.PlaintextSummary(ctx, e.sweepEnv())
}

func (e *sweepEngine) OpenNotes(ctx context.Context, keys sweep.KeySource, markers []string) (*sweep.Report, error) {
	return withErr(sweep.OpenNotes(ctx, e.sweepEnv(), keys, markers))
}

func (e *sweepEngine) CatNote(ctx context.Context, keys sweep.KeySource, marker string, w io.Writer) error {
	return sweep.CatNote(ctx, e.sweepEnv(), keys, marker, w)
}

func (e *sweepEngine) ParseMarker(path string) (string, error) { return sweep.ParseMarker(path) }

func (e *sweepEngine) Resolve(ctx context.Context, keys sweep.KeySource, path, keep string) (*sweep.Report, error) {
	return withErr(sweep.Resolve(ctx, e.sweepEnv(), keys, path, keep))
}

func (e *sweepEngine) Forget(ctx context.Context, unit string) (*sweep.Report, error) {
	return withErr(sweep.Forget(ctx, e.sweepEnv(), unit))
}

func (e *sweepEngine) Prune(ctx context.Context, o sweep.PruneOptions) (*sweep.Report, error) {
	return withErr(sweep.Prune(ctx, e.sweepEnv(), o))
}

func (e *sweepEngine) Generations(unit string) ([]sweep.Generation, error) {
	return sweep.Generations(e.sweepEnv(), unit)
}

func (e *sweepEngine) ReconcileCodex(ctx context.Context, keys sweep.KeySource, rootID string, prefer sweep.CodexPrefer) (*sweep.Report, error) {
	return withErr(sweep.ReconcileCodex(ctx, e.sweepEnv(), keys, rootID, prefer))
}

func (e *sweepEngine) LatestCapsuleHeader() ([]byte, bool, error) {
	entries, err := e.sweepEnv().Log.All()
	if err != nil {
		return nil, false, err
	}
	var newest *capslog.Entry
	for i := range entries {
		if newest == nil || entries[i].SealedAt.After(newest.SealedAt) {
			newest = &entries[i]
		}
	}
	if newest == nil {
		return nil, false, nil
	}
	base, err := fsx.OpenBase(e.layout.CapsulesDir)
	if err != nil {
		return nil, false, err
	}
	defer base.Close()
	dir, err := base.OpenDir(filepath.Dir(filepath.FromSlash(newest.Path)), false)
	if err != nil {
		return nil, false, err
	}
	defer dir.Close()
	h, _, err := capsule.ReadHeader(dir, filepath.Base(newest.Path))
	if err != nil {
		return nil, false, err
	}
	return h, true, nil
}

func (e *sweepEngine) adapter(h harness.ID) (harness.Adapter, error) {
	for _, ad := range e.adapters {
		if ad.ID() == h {
			return ad, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", harness.ErrUnknownHarness, h)
}

func (e *sweepEngine) Homes(ctx context.Context, h harness.ID) ([]harness.Home, error) {
	ad, err := e.adapter(h)
	if err != nil {
		return nil, err
	}
	return ad.Homes(ctx, e.harnessEnv())
}

func (e *sweepEngine) UnitKey(k capsule.Kind, h harness.ID, homeID, rootID, unitID string) (string, error) {
	return harness.UnitKeyFor(e.harnessEnv().Salt, k, h, homeID, rootID, unitID)
}

func (e *sweepEngine) CleanupPeriodDays(configDir string) (int, error) {
	return claude.CleanupPeriodDays(configDir)
}

func (e *sweepEngine) PlanLaunch(ctx context.Context, h harness.ID, cwd string, argv []string, host paths.Env) (harness.LaunchPlan, error) {
	ad, err := e.adapter(h)
	if err != nil {
		return harness.LaunchPlan{}, err
	}
	henv := e.harnessEnv()
	henv.Host = host
	return ad.PlanLaunch(ctx, henv, cwd, argv)
}

func (e *sweepEngine) HarnessFor(exe string) (harness.ID, bool) {
	base := filepath.Base(exe)
	switch base {
	case "claude":
		return harness.ClaudeCode, true
	case "codex":
		return harness.Codex, true
	}
	for _, inv := range e.invs {
		id := harness.ID(inv.ID)
		if id == harness.ClaudeCode || id == harness.Codex {
			continue
		}
		if _, err := e.adapter(id); err != nil {
			continue // not enabled (experimental inventories need opt-in, D33)
		}
		if slices.Contains(inv.Process.ExeBasenames, base) {
			return id, true
		}
	}
	return "", false
}

func (e *sweepEngine) Inventory(id harness.ID) (harness.Inventory, bool) {
	for _, inv := range e.invs {
		if harness.ID(inv.ID) == id {
			return inv, true
		}
	}
	return harness.Inventory{}, false
}

func (e *sweepEngine) ClaudeSettingsJSON(p config.Policy) string { return claude.SettingsJSON(p) }

func (e *sweepEngine) AcquireLease(keys []string, l live.Lease) (wrapper.Lease, error) {
	h, err := live.Acquire(e.layout.LeasesDir, keys, l)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (e *sweepEngine) AppendLedger(events ...ledger.Event) error {
	var errs []error
	for _, ev := range events {
		errs = append(errs, e.ledger.Append(ev))
	}
	return errors.Join(errs...)
}

func (e *sweepEngine) HooksSeen(h harness.ID, child platform.ProcID) (bool, error) {
	ss, err := e.ledger.ByProc(string(h), child)
	if err != nil {
		if errors.Is(err, ledger.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	for _, s := range ss {
		if s.HooksSeen {
			return true, nil
		}
	}
	return false, nil
}

func (e *sweepEngine) LatestSessions(h harness.ID, child platform.ProcID) ([]string, error) {
	ss, err := e.ledger.ByProc(string(h), child)
	if err != nil {
		if errors.Is(err, ledger.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.SID)
	}
	return out, nil
}

// registryStartSlack is how much later than a registry entry's startedAt
// the process may have started and still be its writer (the Claude
// adapter's D18 rule).
const registryStartSlack = 2 * time.Second

// sidRE matches a session id as ChildSessions returns it (a lowercase UUID).
var sidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (e *sweepEngine) ChildSessions(ctx context.Context, h harness.ID, configDir string, child platform.ProcID) ([]string, error) {
	if h != harness.ClaudeCode || !filepath.IsAbs(configDir) || child.IsZero() {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := claude.ReadRegistry(configDir)
	if err != nil {
		return nil, err
	}
	start := platform.StartTime(child)
	var out []string
	for _, r := range entries {
		if r.PID != child.PID || !r.Valid {
			continue
		}
		// Written by this process, not left behind by an earlier one with
		// the same pid: its startedAt is at most registryStartSlack before
		// the child's start, else its mtime is not before it (an unknown
		// start time trusts the pid, which the child holds while it runs).
		switch {
		case start.IsZero():
		case !r.StartedAt.IsZero():
			if start.After(r.StartedAt.Add(registryStartSlack)) {
				continue
			}
		case !r.Mtime.IsZero() && r.Mtime.Before(start):
			continue
		}
		if sid := strings.ToLower(r.SessionID); sidRE.MatchString(sid) && !slices.Contains(out, sid) {
			out = append(out, sid)
		}
	}
	return out, nil
}

func (e *sweepEngine) EnqueueSeal(r queue.Request) error {
	_, err := queue.Enqueue(e.layout.QueueDir, r)
	return err
}

func (e *sweepEngine) WrongHomeRollouts(ctx context.Context) (map[string]int, error) {
	user, err := codex.UserHome(e.harnessEnv().Host)
	if err != nil {
		return nil, err
	}
	cfg, _, _ := e.envs()
	return codex.WrongHomeRollouts(ctx, user, cfg)
}

func (e *sweepEngine) PrepareCodexHome(ctx context.Context, rootID string, forceConfig bool) error {
	user, err := codex.UserHome(e.harnessEnv().Host)
	if err != nil {
		return err
	}
	return codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: e.layout.CodexHome(rootID), ForceConfig: forceConfig})
}

// registerHomes adds homes to [harness.claude-code].homes of config.toml
// as the file is on disk under the config lock (not this process's cached
// copy, D114) and returns the configuration it saved (D109; addHome
// deduplicates by directory).
func (a *app) registerHomes(add []config.Home) (config.Config, error) {
	next, err := a.editConfig(func(disk config.Config) (config.Config, error) {
		next := disk
		next.Harness = cloneHarness(disk.Harness)
		for _, h := range add {
			addHome(next.Harness, string(harness.ClaudeCode), h)
		}
		return next, nil
	})
	if err != nil {
		return config.Config{}, err
	}
	return next, nil
}
