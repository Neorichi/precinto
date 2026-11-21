package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/agent"
	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/shellinit"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
	"github.com/precinto/precinto/internal/wrapper"
)

// env is one CLI invocation environment for unit tests: a testkit fake
// HOME, and fakes for every seam of the app (no other group's code runs).
type env struct {
	t   *testing.T
	h   *testkit.Home
	sys *system

	in       *bytes.Buffer
	out, err bytes.Buffer

	cwd         string
	interactive bool // stdin and stdout are terminals
	stdoutTTY   bool
	tty         *fakeTTY // nil: no controlling terminal
	agentCtx    bool
	goos        string
	uictx       platform.UIContext

	daemon  *fakeDaemon
	dialErr error
	dials   []ipc.DialOptions

	eng    *fakeEngine
	engErr error
	engExp []bool

	vaults *fakeVaults
	shell  *fakeShell

	hardened  int
	hardenErr error
	execs     []execSpec
	execOut   map[string][]byte // first argv element after the binary → output
	execErr   map[string]error
	launchctl [][]string
	spawned   [][]string
	wrapped   []wrapper.Options
	wrapCode  int
	wrapErr   error
	hooked    [][]string
	agentOpts []agent.Options
	agentErr  error
	doctorOut []doctor.Finding
}

func newEnv(t *testing.T) *env {
	t.Helper()
	h := testkit.NewHome(t)
	e := &env{
		t:           t,
		h:           h,
		in:          &bytes.Buffer{},
		cwd:         h.Root,
		interactive: true,
		stdoutTTY:   true,
		goos:        "darwin",
		daemon:      newFakeDaemon(),
		eng:         newFakeEngine(),
		vaults:      newFakeVaults(),
		shell:       &fakeShell{},
		execOut:     map[string][]byte{},
		execErr:     map[string]error{},
	}
	e.tty = &fakeTTY{}
	return e
}

// app builds the app over the fakes (fresh per call, like one process).
func (e *env) app() *app {
	e.sys = &system{
		goos:        e.goos,
		newLayout:   func(paths.Env) (paths.Layout, error) { return e.h.Layout, nil },
		harden:      func() error { e.hardened++; return e.hardenErr },
		executable:  func() (string, error) { return "/opt/precinto/bin/precinto", nil },
		procs:       func() platform.ProcTable { return e.h.Procs },
		clock:       func() platform.Clock { return e.h.Clock },
		self:        func() platform.ProcID { return platform.ProcID{PID: 4242, StartUS: 7} },
		parseProcID: fakeParseProcID,
		getwd:       func() (string, error) { return e.cwd, nil },
		uid:         func() int { return 501 },
		loc:         time.UTC,
		openTTY: func() (terminal, error) {
			if e.tty == nil {
				return nil, errors.New("no controlling terminal")
			}
			return e.tty, nil
		},
		interactive:  func() bool { return e.interactive },
		stdoutTTY:    func() bool { return e.stdoutTTY },
		agentContext: func(paths.Env, platform.ProcTable) (bool, string) { return e.agentCtx, "test evidence" },
		uiContext:    func(paths.Env) platform.UIContext { return e.uictx },
		cloudSynced:  func(p string) bool { return strings.Contains(p, "CloudStorage") },
		realpath:     filepath.EvalSymlinks,
		exec: func(ctx context.Context, c execSpec) ([]byte, error) {
			e.execs = append(e.execs, c)
			key := ""
			if len(c.Argv) > 1 {
				key = c.Argv[1]
			}
			return e.execOut[key], e.execErr[key]
		},
		launchctl: func(ctx context.Context, args []string) error {
			e.launchctl = append(e.launchctl, args)
			return nil
		},
		spawn: func(argv []string, o platform.SpawnOptions) (platform.ProcID, error) {
			e.spawned = append(e.spawned, argv)
			return platform.ProcID{PID: 9999, StartUS: 1}, nil
		},
		sleep: func(time.Duration) {},
		dial: func(ctx context.Context, o ipc.DialOptions) (daemonClient, error) {
			e.dials = append(e.dials, o)
			if e.dialErr != nil {
				return nil, e.dialErr
			}
			return e.daemon, nil
		},
		vaults: func(paths.Layout) vaultStore { return e.vaults },
		engine: func(ctx context.Context, a *app, experimental bool) (engine, error) {
			e.engExp = append(e.engExp, experimental)
			if e.engErr != nil {
				return nil, e.engErr
			}
			return e.eng, nil
		},
		wrapperRun: func(ctx context.Context, o wrapper.Options) (int, error) {
			e.wrapped = append(e.wrapped, o)
			return e.wrapCode, e.wrapErr
		},
		hookMain: func(args []string, stdin io.Reader, stdout, stderr io.Writer, env paths.Env) int {
			e.hooked = append(e.hooked, args)
			return 10
		},
		agentRun: func(ctx context.Context, o agent.Options) error {
			e.agentOpts = append(e.agentOpts, o)
			return e.agentErr
		},
		doctorRun: func(ctx context.Context, o doctor.Options) ([]doctor.Finding, error) {
			return e.doctorOut, nil
		},
		shell:            e.shell,
		registerAdapters: func() {},
	}
	return newApp(stdio{in: e.in, out: &e.out, err: &e.err}, e.h.Env, e.sys)
}

// run runs one command line and returns its exit code.
func (e *env) run(args ...string) int {
	e.t.Helper()
	return e.app().run(args)
}

// stderr and stdout return what the commands printed so far.
func (e *env) stderr() string { return e.err.String() }
func (e *env) stdout() string { return e.out.String() }

// saveConfig rewrites config.toml and roots.list of the fake home.
func (e *env) saveConfig(c config.Config) {
	e.t.Helper()
	if err := config.Save(e.h.Layout.ConfigFile, c); err != nil {
		e.t.Fatal(err)
	}
	if err := config.WriteRootsList(e.h.Layout.RootsList, c); err != nil {
		e.t.Fatal(err)
	}
	e.h.Cfg = c
}

// loadConfig reads config.toml of the fake home.
func (e *env) loadConfig() config.Config {
	e.t.Helper()
	c, err := config.Load(e.h.Layout.ConfigFile)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func fakeParseProcID(s string) (platform.ProcID, error) {
	pid, start, ok := strings.Cut(s, ":")
	if !ok {
		return platform.ProcID{}, errors.New("bad proc id")
	}
	p, err1 := strconv.Atoi(pid)
	st, err2 := strconv.ParseInt(start, 10, 64)
	if err1 != nil || err2 != nil || p <= 0 {
		return platform.ProcID{}, errors.New("bad proc id")
	}
	return platform.ProcID{PID: p, StartUS: st}, nil
}

// fakeTTY is a scripted terminal.
type fakeTTY struct {
	mu       sync.Mutex
	lines    []string // ReadLine answers, in order ("" when exhausted)
	lineErr  error
	secrets  []string // Secret answers
	yesno    []bool   // YesNo answers (default answer when exhausted)
	confirms []bool   // Confirm answers
	prompts  []string // every prompt shown
	shown    []string // ShowSecretScreen secrets (test only)
	display  []string
	closed   int
}

func (f *fakeTTY) record(p string) {
	f.mu.Lock()
	f.prompts = append(f.prompts, p)
	f.mu.Unlock()
}

func (f *fakeTTY) Display(msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.display = append(f.display, msg)
	return nil
}

func (f *fakeTTY) Secret(prompt string) (*memguard.LockedBuffer, error) {
	f.record(prompt)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.secrets) == 0 {
		return nil, ui.ErrCancelled
	}
	s := f.secrets[0]
	f.secrets = f.secrets[1:]
	return memguard.NewBufferFromBytes([]byte(s)), nil
}

func (f *fakeTTY) Confirm(prompt, yes, no string) (bool, error) {
	f.record(prompt)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.confirms) == 0 {
		return false, nil
	}
	v := f.confirms[0]
	f.confirms = f.confirms[1:]
	return v, nil
}

func (f *fakeTTY) ReadLine(prompt string) (string, error) {
	f.record(prompt)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lineErr != nil {
		return "", f.lineErr
	}
	if len(f.lines) == 0 {
		return "", nil
	}
	l := f.lines[0]
	f.lines = f.lines[1:]
	return l, nil
}

func (f *fakeTTY) YesNo(prompt string, def bool) (bool, error) {
	f.record(prompt)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.yesno) == 0 {
		return def, nil
	}
	v := f.yesno[0]
	f.yesno = f.yesno[1:]
	return v, nil
}

func (f *fakeTTY) Printf(format string, args ...any) { f.record(fmt.Sprintf(format, args...)) }

func (f *fakeTTY) ShowSecretScreen(header []string, secret *memguard.LockedBuffer, confirmLast int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shown = append(f.shown, string(secret.Bytes()))
	return nil
}

func (f *fakeTTY) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

func (f *fakeTTY) allPrompts() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.prompts, "\n")
}

// fakeDaemon records requests and answers from its fields.
type fakeDaemon struct {
	mu sync.Mutex

	status    ipc.StatusResp
	statusErr error

	unlocks   []ipc.UnlockReq
	unlockUI  []ipc.UIHandler
	unlockRes ipc.UnlockResp
	unlockErr error

	locks   []ipc.LockReq
	lockRes ipc.LockResp
	lockErr error

	keys     []ipc.KeysReq
	keysFunc func(ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error)

	creates   []ipc.VaultCreateReq
	createErr error

	factors   []ipc.FactorAddReq
	factorErr error

	repairs   []ipc.VaultRepairReq
	repairRes []ipc.VaultRepairResp
	repairErr error

	policies  []ipc.PolicyReq
	pending   []string
	shutdowns int

	registers []ipc.RegisterReq
	subs      []ipc.SubscribeReq
	events    chan ipc.Event
	closed    int
}

func newFakeDaemon() *fakeDaemon { return &fakeDaemon{} }

func (d *fakeDaemon) Status(ctx context.Context) (ipc.StatusResp, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.status, d.statusErr
}

func (d *fakeDaemon) Unlock(ctx context.Context, r ipc.UnlockReq, u ipc.UIHandler) (ipc.UnlockResp, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.unlocks = append(d.unlocks, r)
	d.unlockUI = append(d.unlockUI, u)
	return d.unlockRes, d.unlockErr
}

func (d *fakeDaemon) Lock(ctx context.Context, r ipc.LockReq) (ipc.LockResp, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.locks = append(d.locks, r)
	return d.lockRes, d.lockErr
}

func (d *fakeDaemon) VaultCreate(ctx context.Context, r ipc.VaultCreateReq, u ipc.UIHandler) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.creates = append(d.creates, r)
	return d.createErr
}

func (d *fakeDaemon) FactorAdd(ctx context.Context, r ipc.FactorAddReq, u ipc.UIHandler) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.factors = append(d.factors, r)
	return d.factorErr
}

func (d *fakeDaemon) VaultRepair(ctx context.Context, r ipc.VaultRepairReq, rec *memguard.LockedBuffer, u ipc.UIHandler) (ipc.VaultRepairResp, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.repairs = append(d.repairs, r)
	var res ipc.VaultRepairResp
	if len(d.repairRes) > 0 {
		res = d.repairRes[0]
		d.repairRes = d.repairRes[1:]
	}
	return res, d.repairErr
}

func (d *fakeDaemon) Policy(ctx context.Context, r ipc.PolicyReq) (ipc.PolicyResp, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.policies = append(d.policies, r)
	return ipc.PolicyResp{Pending: d.pending}, nil
}

func (d *fakeDaemon) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.shutdowns++
	return nil
}

func (d *fakeDaemon) Register(ctx context.Context, r ipc.RegisterReq) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.registers = append(d.registers, r)
	return nil
}

func (d *fakeDaemon) Unregister(ctx context.Context, r ipc.UnregisterReq) error { return nil }

func (d *fakeDaemon) Subscribe(ctx context.Context, r ipc.SubscribeReq) (<-chan ipc.Event, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subs = append(d.subs, r)
	if d.events == nil {
		d.events = make(chan ipc.Event)
	}
	return d.events, nil
}

func (d *fakeDaemon) Activity(ctx context.Context, r ipc.ActivityReq) error { return nil }

func (d *fakeDaemon) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed++
	return nil
}

func (d *fakeDaemon) releaseKeys(ctx context.Context, r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
	d.mu.Lock()
	d.keys = append(d.keys, r)
	fn := d.keysFunc
	d.mu.Unlock()
	if fn == nil {
		return nil, ipc.KeysResp{}, &ipc.Error{Code: ipc.CodeLocked, Msg: "locked"}
	}
	return fn(r)
}

// fakeKeys is a released key set.
type fakeKeys struct {
	mu        sync.Mutex
	paths     []string
	destroyed bool
}

func (k *fakeKeys) Key(p string) (*memguard.LockedBuffer, bool) { return nil, false }

func (k *fakeKeys) Destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.destroyed = true
}

func (k *fakeKeys) isDestroyed() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.destroyed
}

// fakeEngine records every call and answers from its fields.
type fakeEngine struct {
	mu    sync.Mutex
	calls []string

	sweepOpts []sweep.Options
	sweepRep  *sweep.Report
	sweepErr  error

	sealHarness [][]harness.ID
	sealScope   []harness.Scope
	sealOpts    []sweep.Options
	sealRep     *sweep.Report
	sealErr     error

	drainOpts []sweep.Options

	restores   []sweep.RestoreRequest
	restoreRep *sweep.Report
	restoreErr error
	restoreFn  func(keys sweep.KeySource, r sweep.RestoreRequest)
	mdRoots    []string
	histRoots  []string

	listOpts []sweep.ListOptions
	units    []sweep.UnitInfo
	listErr  error
	plain    []sweep.Plaintext

	opened  [][]string
	catBody string
	catKeys []sweep.KeySource
	markers map[string]string // marker path → unit key ("" = ErrNotMarker)

	resolved []string
	forgot   []string
	pruneOps []sweep.PruneOptions
	pruneRep *sweep.Report
	gens     map[string][]sweep.Generation

	reconciled []string
	homes      []harness.Home
	plans      []harness.LaunchPlan
	planHost   []paths.Env
	planErr    error
	plan       harness.LaunchPlan
	harnessFor map[string]harness.ID
	invs       map[harness.ID]harness.Inventory
	settings   string

	leaseKeys [][]string
	lease     *fakeLease
	ledgerEvs []ledger.Event
	hooksSeen bool
	enqueued  []queue.Request
	prepared  []string
	header    []byte
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{
		markers:    map[string]string{},
		gens:       map[string][]sweep.Generation{},
		harnessFor: map[string]harness.ID{"claude": harness.ClaudeCode, "codex": harness.Codex},
		invs:       map[harness.ID]harness.Inventory{},
		settings:   `{"idleCompaction":false,"awaySummaryEnabled":false,"precomputeCompactionEnabled":false}`,
		lease:      &fakeLease{},
	}
}

func (f *fakeEngine) call(name string) {
	f.mu.Lock()
	f.calls = append(f.calls, name)
	f.mu.Unlock()
}

func (f *fakeEngine) called(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == name {
			return true
		}
	}
	return false
}

func orEmpty(r *sweep.Report) *sweep.Report {
	if r == nil {
		return &sweep.Report{}
	}
	return r
}

func (f *fakeEngine) Sweep(ctx context.Context, o sweep.Options) (*sweep.Report, error) {
	f.call("Sweep")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepOpts = append(f.sweepOpts, o)
	return orEmpty(f.sweepRep), f.sweepErr
}

func (f *fakeEngine) Seal(ctx context.Context, hs []harness.ID, scope harness.Scope, o sweep.Options) (*sweep.Report, error) {
	f.call("Seal")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sealHarness = append(f.sealHarness, hs)
	f.sealScope = append(f.sealScope, scope)
	f.sealOpts = append(f.sealOpts, o)
	return orEmpty(f.sealRep), f.sealErr
}

func (f *fakeEngine) DrainQueue(ctx context.Context, o sweep.Options) (*sweep.Report, error) {
	f.call("DrainQueue")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.drainOpts = append(f.drainOpts, o)
	return &sweep.Report{}, nil
}

func (f *fakeEngine) Restore(ctx context.Context, keys sweep.KeySource, r sweep.RestoreRequest) (*sweep.Report, error) {
	f.call("Restore")
	f.mu.Lock()
	f.restores = append(f.restores, r)
	fn := f.restoreFn
	rep, err := orEmpty(f.restoreRep), f.restoreErr
	f.mu.Unlock()
	if fn != nil {
		fn(keys, r)
	}
	return rep, err
}

func (f *fakeEngine) RestoreMarkdown(ctx context.Context, keys sweep.KeySource, root config.Root) (*sweep.Report, error) {
	f.call("RestoreMarkdown")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mdRoots = append(f.mdRoots, root.ID)
	return &sweep.Report{}, nil
}

func (f *fakeEngine) MergeHistory(ctx context.Context, keys sweep.KeySource, rootID string) (*sweep.Report, error) {
	f.call("MergeHistory")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.histRoots = append(f.histRoots, rootID)
	return &sweep.Report{}, nil
}

func (f *fakeEngine) List(ctx context.Context, o sweep.ListOptions) ([]sweep.UnitInfo, error) {
	f.call("List")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listOpts = append(f.listOpts, o)
	return f.units, f.listErr
}

func (f *fakeEngine) PlaintextSummary(ctx context.Context) ([]sweep.Plaintext, error) {
	f.call("PlaintextSummary")
	return f.plain, nil
}

func (f *fakeEngine) OpenNotes(ctx context.Context, keys sweep.KeySource, markers []string) (*sweep.Report, error) {
	f.call("OpenNotes")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opened = append(f.opened, markers)
	rep := &sweep.Report{}
	for range markers {
		rep.Units = append(rep.Units, sweep.UnitResult{Outcome: sweep.OutRestored})
	}
	return rep, nil
}

func (f *fakeEngine) CatNote(ctx context.Context, keys sweep.KeySource, marker string, w io.Writer) error {
	f.call("CatNote")
	f.mu.Lock()
	f.catKeys = append(f.catKeys, keys)
	body := f.catBody
	f.mu.Unlock()
	// Written in two pieces to exercise the streaming sanitizer.
	half := len(body) / 2
	if _, err := w.Write([]byte(body[:half])); err != nil {
		return err
	}
	_, err := w.Write([]byte(body[half:]))
	return err
}

func (f *fakeEngine) ParseMarker(path string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if k, ok := f.markers[path]; ok && k != "" {
		return k, nil
	}
	return "", sweep.ErrNotMarker
}

func (f *fakeEngine) Resolve(ctx context.Context, keys sweep.KeySource, path, keep string) (*sweep.Report, error) {
	f.call("Resolve")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, path+"="+keep)
	return &sweep.Report{}, nil
}

func (f *fakeEngine) Forget(ctx context.Context, unit string) (*sweep.Report, error) {
	f.call("Forget")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forgot = append(f.forgot, unit)
	return &sweep.Report{Units: []sweep.UnitResult{{Unit: unit}}}, nil
}

func (f *fakeEngine) Prune(ctx context.Context, o sweep.PruneOptions) (*sweep.Report, error) {
	f.call("Prune")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneOps = append(f.pruneOps, o)
	return orEmpty(f.pruneRep), nil
}

func (f *fakeEngine) Generations(unit string) ([]sweep.Generation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gens[unit], nil
}

func (f *fakeEngine) ReconcileCodex(ctx context.Context, keys sweep.KeySource, rootID string, prefer sweep.CodexPrefer) (*sweep.Report, error) {
	f.call("ReconcileCodex")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconciled = append(f.reconciled, rootID+"="+string(prefer))
	return &sweep.Report{}, nil
}

func (f *fakeEngine) LatestCapsuleHeader() ([]byte, bool, error) {
	return f.header, f.header != nil, nil
}

func (f *fakeEngine) Homes(ctx context.Context, h harness.ID) ([]harness.Home, error) {
	return f.homes, nil
}

func (f *fakeEngine) UnitKey(k capsule.Kind, h harness.ID, homeID, rootID, unitID string) (string, error) {
	return capsule.UnitKey([]byte("test-salt"), string(k), string(h), homeID, rootID, unitID), nil
}

func (f *fakeEngine) CleanupPeriodDays(configDir string) (int, error) { return 30, nil }

func (f *fakeEngine) PlanLaunch(ctx context.Context, h harness.ID, cwd string, argv []string, host paths.Env) (harness.LaunchPlan, error) {
	f.call("PlanLaunch")
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.plan
	p.Harness = h
	f.plans = append(f.plans, p)
	f.planHost = append(f.planHost, host)
	return p, f.planErr
}

func (f *fakeEngine) HarnessFor(exe string) (harness.ID, bool) {
	id, ok := f.harnessFor[filepath.Base(exe)]
	return id, ok
}

func (f *fakeEngine) Inventory(id harness.ID) (harness.Inventory, bool) {
	inv, ok := f.invs[id]
	return inv, ok
}

func (f *fakeEngine) ClaudeSettingsJSON(p config.Policy) string { return f.settings }

func (f *fakeEngine) AcquireLease(keys []string, l live.Lease) (wrapper.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leaseKeys = append(f.leaseKeys, keys)
	f.lease.keys = append(f.lease.keys, keys...)
	return f.lease, nil
}

func (f *fakeEngine) AppendLedger(events ...ledger.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ledgerEvs = append(f.ledgerEvs, events...)
	return nil
}

func (f *fakeEngine) HooksSeen(h harness.ID, child platform.ProcID) (bool, error) {
	return f.hooksSeen, nil
}

func (f *fakeEngine) EnqueueSeal(r queue.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enqueued = append(f.enqueued, r)
	return nil
}

func (f *fakeEngine) PrepareCodexHome(ctx context.Context, rootID string, forceConfig bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prepared = append(f.prepared, fmt.Sprintf("%s:%v", rootID, forceConfig))
	return nil
}

// fakeLease is a launch lease.
type fakeLease struct {
	mu   sync.Mutex
	keys []string
}

func (l *fakeLease) Add(keys ...string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, keys...)
	return nil
}
func (l *fakeLease) SetChild(platform.ProcID) error { return nil }
func (l *fakeLease) Inheritable() []*os.File        { return nil }
func (l *fakeLease) Release() error                 { return nil }

// fakeVaults is the vault store.
type fakeVaults struct {
	initialized bool
	initOpts    []vault.InitOptions
	recovery    string
	initErr     error
	metas       map[string]vault.Meta
	removed     []string
	removeErr   error
}

func newFakeVaults() *fakeVaults {
	return &fakeVaults{initialized: true, metas: map[string]vault.Meta{
		vault.GlobalID: {ID: vault.GlobalID, Factors: []vault.Factor{
			{Name: "se", Kind: vault.FactorSE, GUI: true},
			{Name: "recovery", Kind: vault.FactorRecovery},
		}},
		"root-acme": {ID: "root-acme"},
	}}
}

func (v *fakeVaults) Initialized() (bool, error) { return v.initialized, nil }

func (v *fakeVaults) Init(ctx context.Context, o vault.InitOptions) (*memguard.LockedBuffer, error) {
	v.initOpts = append(v.initOpts, o)
	if v.initErr != nil {
		return nil, v.initErr
	}
	v.initialized = true
	rec := v.recovery
	if rec == "" {
		rec = "TEST-RECOVERY-PLACEHOLDER"
	}
	return memguard.NewBufferFromBytes([]byte(rec)), nil
}

func (v *fakeVaults) List() ([]string, error) {
	var ids []string
	for id := range v.metas {
		ids = append(ids, id)
	}
	return sortedStrings(ids), nil
}

func (v *fakeVaults) Meta(id string) (vault.Meta, error) {
	m, ok := v.metas[id]
	if !ok {
		return vault.Meta{}, vault.ErrNotFound
	}
	return m, nil
}

func (v *fakeVaults) RemoveFactor(id, name string) error {
	v.removed = append(v.removed, id+":"+name)
	return v.removeErr
}

// fakeShell is internal/shellinit.
type fakeShell struct {
	scripts   []shellinit.Options
	installed []string
	enter     shellinit.EnterResult
	enterErr  error
	requests  []shellinit.EnterRequest
}

func (s *fakeShell) Script(o shellinit.Options) (string, error) {
	s.scripts = append(s.scripts, o)
	return "# precinto " + o.Shell + " integration\n", nil
}

func (s *fakeShell) InstallLine(shell string) string {
	return `eval "$(precinto shell-init ` + shell + `)"`
}

func (s *fakeShell) RCFile(shell, home string) string {
	return filepath.Join(home, "."+shell+"rc")
}

func (s *fakeShell) Install(shell, home string) error {
	s.installed = append(s.installed, shell)
	return nil
}

func (s *fakeShell) OnEnter(ctx context.Context, c config.Config, l paths.Layout, r shellinit.EnterRequest) (shellinit.EnterResult, error) {
	s.requests = append(s.requests, r)
	return s.enter, s.enterErr
}
