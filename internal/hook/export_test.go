package hook

// Test-only access to unexported seams (compiled into the test binary only;
// the external tests in package hook_test use these).

import (
	"github.com/precinto/precinto/internal/ui"
	"io"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/paths"
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

// HookLayout is the hook-mode layout (no PRECINTO_* overrides).
func HookLayout(env paths.Env) (paths.Layout, bool) { return hookLayout(env) }

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
