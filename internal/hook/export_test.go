package hook

// Test-only access to unexported seams (compiled into the test binary only;
// the external tests in package hook_test use these).

import (
	"io"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/ui"
)

// TestSystem replaces what Main takes from the process.
type TestSystem struct {
	Deps Deps
	// Harden replaces platform.Harden (nil: hardening succeeds).
	Harden func() error
	// Getwd replaces os.Getwd (nil: no working directory is known).
	Getwd func() (string, error)
	// Deadline, when non-zero, replaces every hook deadline (the harness
	// timeouts of Timings are unchanged).
	Deadline time.Duration
}

// RunWith is Main with injected dependencies.
func RunWith(args []string, stdin io.Reader, stdout, stderr io.Writer, env paths.Env, ts TestSystem) int {
	sys := system{
		harden: func() error { return nil },
		deps:   func(paths.Env) Deps { return ts.Deps },
		getwd:  ts.Getwd,
		timing: timings,
	}
	if ts.Harden != nil {
		sys.harden = ts.Harden
	}
	if ts.Deadline > 0 {
		sys.timing = func(h Host, e Event) Timing {
			t := timings(h, e)
			t.Deadline = ts.Deadline
			return t
		}
	}
	return run(args, stdin, stdout, stderr, env, sys)
}

// RunWithDepsPanic is Main whose dependency construction panics (a stub or
// a bug before the configuration is known).
func RunWithDepsPanic(args []string, stdin io.Reader, stdout, stderr io.Writer, env paths.Env) int {
	sys := system{
		harden: func() error { return nil },
		deps:   func(paths.Env) Deps { panic("deps") },
		timing: timings,
	}
	return run(args, stdin, stdout, stderr, env, sys)
}

// SetApplyPatchPaths replaces the apply_patch header extractor and returns
// a function restoring the real one.
func SetApplyPatchPaths(f func(patch []byte, cwd string) []string) (restore func()) {
	old := applyPatchPaths
	applyPatchPaths = f
	return func() { applyPatchPaths = old }
}

// SetSelfPID roots the harness ancestry walk at pid, with ppid as the
// parent-pid fallback, and returns a function restoring the real ones.
func SetSelfPID(pid, ppid int) (restore func()) {
	oldSelf, oldParent := selfPID, parentPID
	selfPID = func() int { return pid }
	parentPID = func() int { return ppid }
	return func() { selfPID, parentPID = oldSelf, oldParent }
}

// ProductionLayout is the layout of the production dependencies:
// paths.HookLayout, without a socket when only the socket path is too
// long; ok is false when there is no usable base at all.
func ProductionLayout(env paths.Env) (l paths.Layout, ok bool) {
	l = productionDeps(env).Layout
	return l, l.Base != ""
}

// SpawnCall is one process start the production Spawn asked for.
type SpawnCall struct {
	Argv []string
	Opts platform.SpawnOptions
}

// SetSpawnProcess makes the production Spawn and autostart see exe as the
// running executable and record process starts in calls instead of
// starting anything; it returns a function restoring the real primitives.
func SetSpawnProcess(exe string, calls *[]SpawnCall) (restore func()) {
	oldExe, oldSpawn := executable, spawnDetached
	executable = func() (string, uint64, uint64, error) { return exe, 0, 0, nil }
	spawnDetached = func(argv []string, o platform.SpawnOptions) (platform.ProcID, error) {
		*calls = append(*calls, SpawnCall{Argv: append([]string(nil), argv...), Opts: o})
		return platform.ProcID{}, nil
	}
	return func() { executable, spawnDetached = oldExe, oldSpawn }
}

// EffectiveConfig is the configuration hook mode enforces.
func EffectiveConfig(l paths.Layout) config.Config { return effectiveConfig(l) }

// WorkerEnv is the allowlisted environment of spawned workers.
func WorkerEnv(env paths.Env) []string { return workerEnv(env) }

// ProductionDeps are the real dependencies (crossgroup tests only: they
// call other groups' implementations).
func ProductionDeps(env paths.Env) Deps { return productionDeps(env) }

// LockedLine is the PreToolUse stopReason text.
func LockedLine(folder string) string { return ui.Format(ui.MsgToolStop, ui.Vars{Folder: folder}) }

// HeadlessUI is the hook's relayed-prompt handler.
type HeadlessUI = headlessUI

// ParseEvent maps an argv event name onto Event.
func ParseEvent(name string) Event { return parseEvent(name) }
