package main

import (
	"context"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/term"

	"github.com/precinto/precinto/internal/agent"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/shellinit"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
	"github.com/precinto/precinto/internal/wrapper"
)

// productionSystem wires the real packages. Nothing here runs until a
// command calls it, so the hook fast path pays for none of it.
func productionSystem() *system {
	return &system{
		goos:        runtime.GOOS,
		newLayout:   paths.NewLayout,
		harden:      platform.Harden,
		executable:  executablePath,
		procs:       platform.System,
		clock:       platform.SystemClock,
		self:        platform.Self,
		parseProcID: platform.ParseProcID,
		getwd:       os.Getwd,
		uid:         os.Getuid,
		loc:         time.Local,

		openTTY: func() (terminal, error) {
			t, err := ui.OpenTTY()
			if err != nil {
				return nil, err
			}
			return t, nil
		},
		interactive:  func() bool { return ui.Interactive(os.Stdin, os.Stdout) },
		stdoutTTY:    func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
		stdinFile:    os.Stdin,
		stdoutFile:   os.Stdout,
		agentContext: ui.AgentContext,
		uiContext: func(e paths.Env) platform.UIContext {
			return platform.DetectUIContext(e, os.Stdin, os.Stdout)
		},
		cloudSynced: platform.CloudSynced,
		realpath:    fsx.Realpath,

		exec:      runExternal,
		launchctl: runLaunchctl,
		spawn:     platform.Spawn,
		sleep:     time.Sleep,

		dial: func(ctx context.Context, o ipc.DialOptions) (daemonClient, error) {
			c, err := ipc.Dial(ctx, o)
			if err != nil {
				return nil, err
			}
			return ipcClient{c}, nil
		},
		vaults: func(l paths.Layout) vaultStore {
			return storeAdapter{vault.OpenStore(l.VaultsDir, l.VerifiedDir, l.FactorsDir)}
		},
		engine:     newSweepEngine,
		wrapperRun: wrapper.Run,
		hookMain:   hook.Main,
		agentRun:   agent.Run,
		doctorRun:  doctor.Run,
		shell:      shellinitOps{},

		registerAdapters: func() { registerBuiltins() },
	}
}

// executablePath is the absolute path of the running binary.
func executablePath() (string, error) {
	p, _, _, err := platform.Executable()
	return p, err
}

// ipcClient adapts *ipc.Client to daemonClient: Keys hands out the key set
// as sweep.FileKeys (a nil *ipc.KeySet never becomes a non-nil interface).
type ipcClient struct{ *ipc.Client }

func (c ipcClient) releaseKeys(ctx context.Context, r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
	ks, resp, err := c.Client.Keys(ctx, r)
	if ks == nil {
		return nil, resp, err
	}
	return ks, resp, err
}

// storeAdapter adapts *vault.Store to vaultStore.
type storeAdapter struct{ s *vault.Store }

func (v storeAdapter) Initialized() (bool, error) { return v.s.Initialized() }

func (v storeAdapter) Init(ctx context.Context, o vault.InitOptions) (*memguard.LockedBuffer, error) {
	return v.s.Init(ctx, o)
}

func (v storeAdapter) List() ([]string, error) { return v.s.List() }

func (v storeAdapter) MarkRecoveryVerified(at time.Time) error { return v.s.MarkRecoveryVerified(at) }

func (v storeAdapter) RepinPlugin(name string) (string, string, error) { return v.s.RepinPlugin(name) }

func (v storeAdapter) Meta(id string) (vault.Meta, error) {
	vv, err := v.s.Open(id)
	if err != nil {
		return vault.Meta{}, err
	}
	return vv.Meta, nil
}

func (v storeAdapter) RemoveFactor(id, name string) error {
	vv, err := v.s.Open(id)
	if err != nil {
		return err
	}
	return vv.RemoveFactor(name)
}

// shellinitOps is internal/shellinit.
type shellinitOps struct{}

func (shellinitOps) Script(o shellinit.Options) (string, error) { return shellinit.Script(o) }
func (shellinitOps) InstallLine(shell string) string            { return shellinit.InstallLine(shell) }
func (shellinitOps) RCFile(shell, home string) string           { return shellinit.RCFile(shell, home) }
func (shellinitOps) Install(shell, home string) error           { return shellinit.Install(shell, home) }
func (shellinitOps) OnEnter(ctx context.Context, c config.Config, l paths.Layout, r shellinit.EnterRequest) (shellinit.EnterResult, error) {
	return shellinit.OnEnter(ctx, c, l, r)
}

// Dial budgets: a running daemon answers hello at once; an autostarted one
// needs a moment to take its lock and bind the socket.
const (
	dialTimeout      = 2 * time.Second
	autostartTimeout = 15 * time.Second
)

// dial connects to the daemon, autostarting it (detached, allowlisted
// environment) only for the commands SPEC §13.1 names: unlock, run, resume,
// protect (and the repair/recovery flows that need an unwrap).
func (a *app) dial(ctx context.Context, autostart bool) (daemonClient, error) {
	l, err := a.layout()
	if err != nil {
		return nil, err
	}
	o := ipc.DialOptions{Layout: l, Client: "cli", Timeout: dialTimeout}
	if autostart {
		exe, err := a.sys.executable()
		if err == nil {
			o.Autostart, o.Exe, o.Env, o.Timeout = true, exe, daemonEnv(a.env), autostartTimeout
		}
	}
	c, err := a.sys.dial(ctx, o)
	if err != nil {
		return nil, err
	}
	if m := paths.AgentMarkers(a.env); len(m) > 0 {
		return markedClient{daemonClient: c, markers: m}, nil
	}
	return c, nil
}

// markedClient fills UnlockReq.AgentMarkers and KeysReq.AgentMarkers with
// this process's own paths.AgentMarkers when the request names none
// (CC-11): a self-restricting claim the daemon unions with the ancestry
// and controlling-terminal facts it measures itself. It can only narrow
// what the daemon grants, never widen it.
type markedClient struct {
	daemonClient
	markers []string
}

func (c markedClient) Unlock(ctx context.Context, r ipc.UnlockReq, relay ipc.UIHandler) (ipc.UnlockResp, error) {
	if len(r.AgentMarkers) == 0 {
		r.AgentMarkers = append([]string(nil), c.markers...)
	}
	return c.daemonClient.Unlock(ctx, r, relay)
}

func (c markedClient) releaseKeys(ctx context.Context, r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
	if len(r.AgentMarkers) == 0 {
		r.AgentMarkers = append([]string(nil), c.markers...)
	}
	return c.daemonClient.releaseKeys(ctx, r)
}

// daemonEnvKeys are the variables an autostarted daemon or a spawned worker
// receives (SPEC §4.6: an allowlisted environment). Agent markers, loader
// variables (DYLD_*, LD_*) and harness variables never pass: the daemon
// never derives harness homes from its own environment (SPEC §7.0).
var daemonEnvKeys = []string{
	"HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
	"XDG_DATA_HOME", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
	"DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS",
}

// daemonEnv returns the allowlisted environment for a daemon or worker.
// PRECINTO_HOME/PRECINTO_RUNTIME_DIR (and PRECINTO_DEV) are passed only
// when this process honours them itself (D6), so a child never resolves a
// different layout than its parent.
func daemonEnv(e paths.Env) []string {
	var out []string
	for _, k := range daemonEnvKeys {
		if v, ok := e.Lookup(k); ok {
			out = append(out, k+"="+v)
		}
	}
	if paths.OverridesAllowed(e) {
		for _, k := range []string{paths.EnvHome, paths.EnvRuntimeDir, paths.EnvDev} {
			if v, ok := e.Lookup(k); ok && v != "" {
				out = append(out, k+"="+v)
			}
		}
	}
	// D64: only a -tags testing build reads (and so passes on) the test
	// ancestry stop; TestAncestryStop is ("", false) in every other build.
	if v, ok := paths.TestAncestryStop(e); ok {
		out = append(out, paths.EnvTestAncestryStop+"="+v)
	}
	return out
}

// harnessEnv is the environment for a harness CLI precinto runs itself
// (integrate): the user's environment without precinto's own variables and
// without loader variables.
func harnessEnv(e paths.Env) []string {
	var drop []string
	for _, kv := range e.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "PRECINTO_") || strings.HasPrefix(k, "DYLD_") || strings.HasPrefix(k, "LD_") {
			drop = append(drop, k)
		}
	}
	return e.Without(drop...).Environ()
}

// spawnWorker starts `<exe> args…` detached (Setsid, stdio /dev/null) with
// the allowlisted environment (the seal-queue worker after a wrapper exit).
func (a *app) spawnWorker(args ...string) error {
	exe, err := a.sys.executable()
	if err != nil {
		return err
	}
	// The worker never keeps a protected folder as its working directory.
	_, err = a.sys.spawn(append([]string{exe}, args...), platform.SpawnOptions{Dir: "/", Env: daemonEnv(a.env)})
	return err
}

// readBounded reads at most limit bytes of r.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}
