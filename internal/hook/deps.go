package hook

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep/queue"
)

// hookLayout is precinto's layout as hook mode sees it: paths.HookLayout,
// which never honours PRECINTO_HOME, PRECINTO_RUNTIME_DIR or PRECINTO_DEV,
// not even in builds with -tags testing (hooks always run in an agent
// context, and Claude's settings env reaches them; SPEC §6.1, D6, D56). ok
// is false when HOME is unusable; when only the socket path is too long the
// files stay usable and the daemon is unreachable (Socket is empty).
func hookLayout(env paths.Env) (paths.Layout, bool) {
	l, err := paths.HookLayout(env)
	if err == nil {
		return l, true
	}
	if !errors.Is(err, paths.ErrSocketPath) {
		return paths.Layout{}, false
	}
	base, err := paths.DefaultBase(env) // ignores overrides as well
	if err != nil {
		return paths.Layout{}, false
	}
	l, err = paths.LayoutAt(base, "/")
	if err != nil {
		return paths.Layout{}, false
	}
	l.RunDir = filepath.Join(base, "run")
	l.Socket, l.AgentLock = "", ""
	return l, true
}

// effectiveConfig is the policy and root set the hook enforces: the
// stricter of config.toml and the pinned policy the daemon enforces
// (config.Strictest, D48, D55), plus every folder of roots.list (hooks use
// the stricter of config.toml and roots.list, SPEC §12.8). An unreadable or
// invalid config.toml contributes no root and the default policy.
func effectiveConfig(l paths.Layout) config.Config {
	if l.ConfigFile == "" {
		return config.Default()
	}
	cfg, err := config.Load(l.ConfigFile)
	if err != nil {
		cfg = config.Default()
	}
	if pinned, ok, err := config.LoadPinned(l.PolicyPinned); err == nil && ok {
		cfg = config.Strictest(cfg, pinned.Config)
	}
	listed, _ := config.ReadRootsList(l.RootsList)
	cfg.Roots = withListedRoots(cfg.Roots, listed)
	return cfg
}

// withListedRoots adds the roots.list folders that no root of the
// configuration has. They have no id (no vault, no ledger taint): they only
// make sessions there managed, so their gates fail closed.
func withListedRoots(roots []config.Root, listed []string) []config.Root {
	out := slices.Clone(roots)
	for _, p := range listed {
		known := false
		for _, r := range out {
			if r.Path == p {
				known = true
				break
			}
		}
		if !known {
			out = append(out, config.Root{Path: p, MD: config.MDLedger})
		}
	}
	return out
}

// productionDeps builds the real dependencies of hook mode.
func productionDeps(env paths.Env) Deps {
	l, ok := hookLayout(env)
	d := Deps{
		Cfg:    effectiveConfig(l),
		Layout: l,
		Env:    env,
		Now:    time.Now,
	}
	if !ok {
		// Without a base nothing is known to be protected; the shim's
		// roots.list rule is the only gate left.
		return d
	}
	d.Procs = platform.System()
	d.Identify = platform.Identify
	d.Ledger = &lazyLedger{layout: l}
	d.Dial = func(ctx context.Context) (Daemon, error) { return dialIPC(ctx, l, env, false) }
	d.DialUnlock = func(ctx context.Context) (Daemon, error) { return dialIPC(ctx, l, env, true) }
	d.Enqueue = func(r queue.Request) (string, error) {
		if err := l.EnsureDirs(); err != nil {
			return "", err
		}
		return queue.Enqueue(l.QueueDir, r)
	}
	d.Spawn = func(args []string) error { return spawnWorker(args, env) }
	return d
}

// lazyLedger opens the ledger at first use and makes sure the state
// directories exist before the first write.
type lazyLedger struct {
	layout paths.Layout
	once   sync.Once
	l      *ledger.Ledger
	dirs   sync.Once
	dirErr error
}

func (x *lazyLedger) open() *ledger.Ledger {
	x.once.Do(func() { x.l = ledger.Open(x.layout.SessionsDir) })
	return x.l
}

// Get folds a session's ledger.
func (x *lazyLedger) Get(harness, sid string) (ledger.Session, error) {
	return x.open().Get(harness, sid)
}

// Append writes one event.
func (x *lazyLedger) Append(e ledger.Event) error {
	x.dirs.Do(func() { x.dirErr = x.layout.EnsureDirs() })
	if x.dirErr != nil {
		return x.dirErr
	}
	return x.open().Append(e)
}

// dialIPC connects to the daemon: without autostart within the gate budget
// (the fast path), or with autostart for the hook unlock path only (IM7).
func dialIPC(ctx context.Context, l paths.Layout, env paths.Env, autostart bool) (Daemon, error) {
	if l.Socket == "" {
		return nil, ipc.ErrNoDaemon
	}
	o := ipc.DialOptions{Layout: l, Client: "hook", Timeout: ipc.GateBudget}
	if autostart {
		exe, _, _, err := platform.Executable()
		if err != nil {
			return nil, err
		}
		o.Autostart, o.Exe, o.Env = true, exe, workerEnv(env)
		if dl, ok := ctx.Deadline(); ok {
			o.Timeout = time.Until(dl)
		}
	}
	c, err := ipc.Dial(ctx, o)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// spawnWorker starts `precinto <args…>` detached (Setsid, stdio /dev/null,
// cwd /), with an allowlisted environment.
func spawnWorker(args []string, env paths.Env) error {
	exe, _, _, err := platform.Executable()
	if err != nil {
		return err
	}
	_, err = platform.Spawn(append([]string{exe}, args...), platform.SpawnOptions{Dir: "/", Env: workerEnv(env)})
	return err
}

// workerEnvKeys are the variables a worker or an autostarted daemon gets
// from the hook's environment (SPEC §4.6: autostart passes an allowlisted
// environment). No PRECINTO_* override, no agent marker, no loader
// variable and nothing the harness put there for itself.
var workerEnvKeys = []string{
	"HOME", "USER", "LOGNAME", "PATH", "SHELL", "TMPDIR", "TZ",
	"LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
	"XDG_DATA_HOME", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
	"DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS",
}

// workerEnv returns the allowlisted KEY=VALUE pairs of env.
func workerEnv(env paths.Env) []string {
	var out []string
	for _, k := range workerEnvKeys {
		if v, ok := env.Lookup(k); ok && !strings.ContainsRune(v, 0) {
			out = append(out, k+"="+v)
		}
	}
	return out
}
