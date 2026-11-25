package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/agent"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/shellinit"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/vault"
	"github.com/precinto/precinto/internal/wrapper"
)

// app is one invocation of the binary: the environment snapshot, the
// standard streams and the seams to every other package. Commands never
// call another group's package directly: they go through sys, whose
// production implementation (wire.go) wires the real packages and whose
// test implementation uses fakes, so CLI tests need no other group's code.
type app struct {
	stdio
	env paths.Env
	sys *system

	mu      sync.Mutex
	lay     paths.Layout
	layErr  error
	layDone bool
	cfg     config.Config
	cfgErr  error
	cfgDone bool
	eng     engine
	engErr  error
	engDone bool
	engExp  bool
}

func newApp(s stdio, env paths.Env, sys *system) *app {
	return &app{stdio: s, env: env, sys: sys}
}

// system holds every seam of the CLI. Function fields are replaced by tests;
// nil is never valid in production (productionSystem sets them all).
type system struct {
	goos string // runtime.GOOS; tests set "linux" to exercise linux paths

	newLayout   func(paths.Env) (paths.Layout, error)
	harden      func() error
	executable  func() (string, error)
	procs       func() platform.ProcTable
	clock       func() platform.Clock
	self        func() platform.ProcID
	parseProcID func(string) (platform.ProcID, error)
	getwd       func() (string, error)
	uid         func() int
	loc         *time.Location // time zone of displayed times

	openTTY      func() (terminal, error)
	interactive  func() bool // stdin and stdout are terminals
	stdoutTTY    func() bool
	stdinFile    *os.File // wrapper.Run needs files (PTY proxy)
	stdoutFile   *os.File
	agentContext func(paths.Env, platform.ProcTable) (bool, string)
	uiContext    func(paths.Env) platform.UIContext
	cloudSynced  func(string) bool
	realpath     func(string) (string, error)
	// WSL (D155, D156): the facts of this system (paths.DetectWSL), the
	// refusal of a location on a Windows drive (paths.CheckDrive) and of a
	// harness executable that would run as a Windows program
	// (harness.CheckProgram). Tests fake all three.
	wsl          func() paths.WSL
	checkDrive   func(p string) error
	checkProgram func(e paths.Env, h harness.ID, exe string) error

	exec      func(ctx context.Context, c execSpec) ([]byte, error)
	launchctl func(ctx context.Context, args []string) error // never runs in testing builds
	spawn     func(argv []string, o platform.SpawnOptions) (platform.ProcID, error)
	sleep     func(time.Duration)
	// sweepSleep is sweep.Env.Sleep, the one D63 quiet-window wait of a
	// sealing run: nil in production (a real timer, CC-29); tests over a
	// fake clock pass one that advances it.
	sweepSleep func(ctx context.Context, d time.Duration) error

	dial       func(ctx context.Context, o ipc.DialOptions) (daemonClient, error)
	vaults     func(paths.Layout) vaultStore
	engine     func(ctx context.Context, a *app, experimental bool) (engine, error)
	wrapperRun func(ctx context.Context, o wrapper.Options) (int, error)
	hookMain   func(args []string, stdin io.Reader, stdout, stderr io.Writer, env paths.Env) int
	agentRun   func(ctx context.Context, o agent.Options) error
	doctorRun  func(ctx context.Context, o doctor.Options) ([]doctor.Finding, error)
	shell      shellOps
	// registerAdapters registers the built-in harness adapters (once).
	registerAdapters func()
}

// terminal is the controlling terminal (*ui.TTY implements it, asserted in
// seams.go). It is also the ipc.UIHandler that relays daemon prompts.
type terminal interface {
	ipc.UIHandler
	ReadLine(prompt string) (string, error)
	YesNo(prompt string, def bool) (bool, error)
	Printf(format string, args ...any)
	ShowSecretScreen(header []string, secret *memguard.LockedBuffer, confirmLast int) error
	Close() error
}

// daemonClient is the part of *ipc.Client the CLI uses. Keys is reached
// through releaseKeys, which returns the key set as sweep.FileKeys (the
// production adapter ipcClient converts *ipc.KeySet), so tests can hand out
// fake keys. It includes wrapper.Daemon (asserted in seams.go).
type daemonClient interface {
	Status(ctx context.Context) (ipc.StatusResp, error)
	Unlock(ctx context.Context, r ipc.UnlockReq, ui ipc.UIHandler) (ipc.UnlockResp, error)
	Lock(ctx context.Context, r ipc.LockReq) (ipc.LockResp, error)
	VaultCreate(ctx context.Context, r ipc.VaultCreateReq, ui ipc.UIHandler) error
	FactorAdd(ctx context.Context, r ipc.FactorAddReq, ui ipc.UIHandler) error
	VaultRepair(ctx context.Context, r ipc.VaultRepairReq, recovery *memguard.LockedBuffer, ui ipc.UIHandler) (ipc.VaultRepairResp, error)
	Policy(ctx context.Context, r ipc.PolicyReq) (ipc.PolicyResp, error)
	Shutdown(ctx context.Context) error
	Register(ctx context.Context, r ipc.RegisterReq) error
	Unregister(ctx context.Context, r ipc.UnregisterReq) error
	Subscribe(ctx context.Context, r ipc.SubscribeReq) (<-chan ipc.Event, error)
	Activity(ctx context.Context, r ipc.ActivityReq) error
	Close() error
	releaseKeys(ctx context.Context, r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error)
}

// vaultStore is the part of vault.Store the CLI uses directly (init and
// factor removal run in the CLI; every unwrap runs in the daemon, D4).
type vaultStore interface {
	Initialized() (bool, error)
	Init(ctx context.Context, o vault.InitOptions) (*memguard.LockedBuffer, error)
	List() ([]string, error)
	Meta(id string) (vault.Meta, error)
	RemoveFactor(id, name string) error
	// MarkRecoveryVerified records a successful recover --verify in every
	// vault (vault.Store.MarkRecoveryVerified, SPEC §4.7).
	MarkRecoveryVerified(at time.Time) error
	// RepinPlugin re-pins a plugin factor in every vault (D75).
	RepinPlugin(name string) (oldSHA, newSHA string, err error)
}

// shellOps is internal/shellinit.
type shellOps interface {
	Script(o shellinit.Options) (string, error)
	InstallLine(shell string) string
	RCFile(shell, home string) string
	Install(shell, home string) error
	OnEnter(ctx context.Context, c config.Config, l paths.Layout, r shellinit.EnterRequest) (shellinit.EnterResult, error)
}

// execSpec is one external command (launchctl, a harness CLI, an age
// plugin). Env is always explicit: nothing inherits the process
// environment.
type execSpec struct {
	Argv    []string
	Env     []string
	Dir     string
	Stdout  io.Writer // nil: captured (bounded) and returned
	Stderr  io.Writer // nil: discarded
	Timeout time.Duration
}

// layout returns the precinto layout for this invocation.
func (a *app) layout() (paths.Layout, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.layDone {
		a.lay, a.layErr = a.sys.newLayout(a.env)
		a.layDone = true
	}
	return a.lay, a.layErr
}

// reportLayout is layout for status and doctor, which report a location
// on a Windows drive (D156) instead of stopping on it: paths.NewLayout
// returns the layout complete with its *paths.DriveError, which comes back
// as onDrive, and from then on this invocation's layout and config accept
// the layout, since these commands only read (status then builds no
// engine, which would create directories there). Any other error stops
// them as before.
func (a *app) reportLayout() (l paths.Layout, onDrive *paths.DriveError, err error) {
	l, err = a.layout()
	if errors.As(err, &onDrive) && l.Base != "" {
		a.mu.Lock()
		a.layErr = nil
		a.mu.Unlock()
		return l, onDrive, nil
	}
	return l, nil, err
}

// config loads config.toml once (a missing file yields the defaults).
func (a *app) config() (config.Config, error) {
	l, err := a.layout()
	if err != nil {
		return config.Config{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.cfgDone {
		a.cfg, a.cfgErr = config.Load(l.ConfigFile)
		a.cfgDone = true
	}
	return a.cfg, a.cfgErr
}

// setConfig replaces the cached configuration after the command saved it.
func (a *app) setConfig(c config.Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg, a.cfgErr, a.cfgDone = c, nil, true
	// An engine built from the old configuration must not be reused.
	a.eng, a.engErr, a.engDone = nil, nil, false
}

// configLockWait bounds how long a config.toml edit waits for another
// process's edit to end (each holds the lock for a read and two small
// atomic writes).
var configLockWait = 10 * time.Second

// errNoEdit is returned by an editConfig edit that finds config.toml
// already as it wants it: nothing is written.
var errNoEdit = errors.New("config.toml needs no change")

// editConfig changes config.toml as it is on disk (D114, D144): it holds
// state/locks/config.lock — an exclusive flock that every edit of
// config.toml and roots.list takes — while edit computes, from config.toml
// read again under the lock (never this process's cached copy), the
// configuration to save, and saves it with roots.list. So an edit made by
// another process between this command's start and its save (a protect,
// an unprotect, an integrate, a background seal registering a home) is
// never undone: each command applies its own change, as a delta, to what
// is on disk. An edit that returns errNoEdit saves nothing; editConfig then
// returns the configuration on disk and errNoEdit. roots.list lists the
// folders the agent enforces (D143): config.toml's and those of the
// confirmed settings, so a removal waiting for its confirmation keeps its
// folder in the shim's list.
func (a *app) editConfig(edit func(disk config.Config) (config.Config, error)) (config.Config, error) {
	l, err := a.layout()
	if err != nil {
		return config.Config{}, err
	}
	if err := l.EnsureDirs(); err != nil {
		return config.Config{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), configLockWait)
	defer cancel()
	lk, err := fsx.WaitLock(ctx, l.LockFile("config"), false)
	if errors.Is(err, context.DeadlineExceeded) {
		return config.Config{}, errors.New("config.toml stayed locked by another precinto process; try again")
	}
	if err != nil {
		return config.Config{}, err
	}
	defer lk.Unlock()
	disk, err := config.Load(l.ConfigFile)
	if err != nil {
		return config.Config{}, err
	}
	c, err := edit(disk)
	if errors.Is(err, errNoEdit) {
		a.setConfig(disk)
		return disk, errNoEdit
	}
	if err != nil {
		return config.Config{}, err
	}
	if err := config.Save(l.ConfigFile, c); err != nil {
		return config.Config{}, err
	}
	if err := config.WriteRootsList(l.RootsList, a.enforcedConfig(c, l)); err != nil {
		// Never fail an edit over what the confirmed settings hold:
		// config.toml's own folders at least.
		if err := config.WriteRootsList(l.RootsList, c); err != nil {
			return config.Config{}, err
		}
	}
	a.setConfig(c)
	return c, nil
}

// engine returns the orchestration facade (built once per invocation).
func (a *app) engine(ctx context.Context, experimental bool) (engine, error) {
	a.mu.Lock()
	if a.engDone && (a.engExp || !experimental) {
		e, err := a.eng, a.engErr
		a.mu.Unlock()
		return e, err
	}
	a.mu.Unlock()
	e, err := a.sys.engine(ctx, a, experimental)
	a.mu.Lock()
	a.eng, a.engErr, a.engDone, a.engExp = e, err, true, experimental
	a.mu.Unlock()
	return e, err
}

// vaults returns the vault store of the layout.
func (a *app) vaults() (vaultStore, error) {
	l, err := a.layout()
	if err != nil {
		return nil, err
	}
	return a.sys.vaults(l), nil
}

// procs returns the process table.
func (a *app) procs() platform.ProcTable { return a.sys.procs() }

// now is the wall clock.
func (a *app) now() time.Time { return a.sys.clock().Now() }

// wireDeadline is the deadline of an ipc request d from now. It is real
// time, never the injected clock: the daemon checks it with its own clock
// (ipc.UnlockReq.Deadline), so a test clock must not reach it (D77).
func wireDeadline(d time.Duration) time.Time { return time.Now().Add(d) }

// home returns $HOME ("" when unset).
func (a *app) home() string {
	h, err := paths.UserHome(a.env)
	if err != nil {
		return ""
	}
	return h
}

// display shortens p for messages (~/work/acme). A path holding a control
// or Unicode format character, or that is not valid UTF-8, is shown
// Go-quoted (D149, as factor repin's values): a folder name — one a forged
// pin or vault.toml supplies included — never repaints the terminal.
func (a *app) display(p string) string { return shownValue(paths.Tilde(a.home(), p)) }

// absPath makes p absolute against the working directory and cleans it.
func (a *app) absPath(p string) (string, error) {
	if p == "" {
		return "", usageErrorf("missing path")
	}
	if !filepath.IsAbs(p) {
		wd, err := a.sys.getwd()
		if err != nil {
			return "", err
		}
		p = filepath.Join(wd, p)
	}
	return filepath.Clean(p), nil
}

// resolveDir returns the realpath of an existing directory.
func (a *app) resolveDir(p string) (string, error) {
	abs, err := a.absPath(p)
	if err != nil {
		return "", err
	}
	real, err := a.sys.realpath(abs)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%s: %w", a.display(abs), errNotDir)
	}
	return real, nil
}

var errNotDir = errors.New("not a directory")

// rootFor returns the deepest protected folder containing p, comparing the
// path as given and its realpath (a folder is recorded realpath'd).
func (a *app) rootFor(cfg config.Config, p string) (config.Root, bool) {
	abs, err := a.absPath(p)
	if err != nil {
		return config.Root{}, false
	}
	if r, ok := cfg.RootFor(abs); ok {
		return r, true
	}
	if real, err := a.sys.realpath(abs); err == nil {
		return cfg.RootFor(real)
	}
	// The path may not exist (yet): resolve its deepest existing parent.
	for dir := filepath.Dir(abs); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if real, err := a.sys.realpath(dir); err == nil {
			rest, _ := filepath.Rel(dir, abs)
			return cfg.RootFor(filepath.Join(real, rest))
		}
	}
	return config.Root{}, false
}

// rootArg resolves a --root DIR argument: DIR is a path (relative to the
// working directory) inside a protected folder, never a folder id (the
// daemon's workers get the folder's absolute path too, CC-43).
func (a *app) rootArg(cfg config.Config, dir string) (config.Root, error) {
	if r, ok := a.rootFor(cfg, dir); ok {
		return r, nil
	}
	return config.Root{}, notProtectedError{dir: a.display(mustAbs(a, dir))}
}

// cwdRoot returns the protected folder containing the working directory.
func (a *app) cwdRoot(cfg config.Config) (config.Root, bool) {
	wd, err := a.sys.getwd()
	if err != nil {
		return config.Root{}, false
	}
	return a.rootFor(cfg, wd)
}

func mustAbs(a *app, p string) string {
	abs, err := a.absPath(p)
	if err != nil {
		return p
	}
	return abs
}

// say prints one line on stderr with the "precinto: " prefix.
func (a *app) say(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	if !strings.HasPrefix(s, "precinto") {
		s = "precinto: " + s
	}
	fmt.Fprintln(a.err, s)
}

// sayOut prints one line on stdout with the "precinto: " prefix.
func (a *app) sayOut(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	if !strings.HasPrefix(s, "precinto") {
		s = "precinto: " + s
	}
	fmt.Fprintln(a.out, s)
}

// fileExists reports whether p exists (without following a final symlink).
func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}
