package main

import (
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/ui"
)

// SEC-28 (D59): prune, forget and unprotect are refused in agent contexts
// (environment marker, harness ancestor, or no controlling terminal: all
// three are what ui.AgentContext reports) and without a terminal for the
// typed confirmation; a wrong typed word deletes nothing.
func TestSEC28DestructiveCommandsRefused(t *testing.T) {
	const unit = "0123456789abcdef0123456789abcdef"
	cmds := map[string][]string{
		"prune":     {"prune", "--diverged"},
		"forget":    {"forget", unit},
		"unprotect": {"unprotect"},
	}
	for name, args := range cmds {
		t.Run(name+"/agent", func(t *testing.T) {
			e := destructiveEnv(t, unit)
			e.agentCtx = true
			code := e.run(withRoot(e, args)...)
			if code != exitLocked {
				t.Fatalf("exit %d, want 3 (stderr %q)", code, e.stderr())
			}
			if !strings.Contains(e.stderr(), "precinto: refusing to ") {
				t.Fatalf("stderr %q lacks C12.agent", e.stderr())
			}
			assertNothingDeleted(t, e)
		})
		t.Run(name+"/no-terminal", func(t *testing.T) {
			e := destructiveEnv(t, unit)
			e.tty = nil
			if code := e.run(withRoot(e, args)...); code != exitLocked {
				t.Fatalf("exit %d, want 3", code)
			}
			assertNothingDeleted(t, e)
		})
		t.Run(name+"/wrong-word", func(t *testing.T) {
			e := destructiveEnv(t, unit)
			e.tty.lines = []string{"yes"}
			if code := e.run(withRoot(e, args)...); code != exitLocked {
				t.Fatalf("exit %d, want 3", code)
			}
			if !strings.Contains(e.tty.allPrompts(), "Type \"") {
				t.Fatalf("no typed confirmation asked: %q", e.tty.allPrompts())
			}
			assertNothingDeleted(t, e)
		})
	}
}

func withRoot(e *env, args []string) []string {
	if args[0] == "unprotect" {
		return []string{"unprotect", e.h.Root}
	}
	return args
}

// destructiveEnv has one unit with generations and a prune plan.
func destructiveEnv(t *testing.T, unit string) *env {
	e := newEnv(t)
	e.eng.gens[unit] = []sweep.Generation{{Gen: 1, Size: 10}, {Gen: 2, Size: 12}}
	e.eng.pruneRep = &sweep.Report{Units: []sweep.UnitResult{{Unit: unit, Outcome: sweep.OutPruned, Files: 1}}}
	e.eng.units = []sweep.UnitInfo{{Unit: unit, RootIDs: []string{"root-acme"}}}
	return e
}

func assertNothingDeleted(t *testing.T, e *env) {
	t.Helper()
	if len(e.eng.forgot) != 0 {
		t.Errorf("Forget called: %v", e.eng.forgot)
	}
	for _, o := range e.eng.pruneOps {
		if !o.DryRun {
			t.Errorf("Prune ran for real: %+v", o)
		}
	}
	if e.eng.called("Restore") {
		t.Error("unprotect restored before confirmation")
	}
	if c := e.loadConfig(); len(c.Roots) != 1 {
		t.Errorf("config roots %d, want 1 (protection kept)", len(c.Roots))
	}
}

// The typed word confirms: forget and prune run, unprotect restores first.
func TestDestructiveCommandsWithTypedWord(t *testing.T) {
	const unit = "0123456789abcdef0123456789abcdef"
	e := destructiveEnv(t, unit)
	e.tty.lines = []string{wordForget}
	if code := e.run("forget", unit); code != exitOK {
		t.Fatalf("forget exit %d (%s)", code, e.stderr())
	}
	if len(e.eng.forgot) != 1 || e.eng.forgot[0] != unit {
		t.Fatalf("forgot %v", e.eng.forgot)
	}

	e = destructiveEnv(t, unit)
	e.tty.lines = []string{wordPrune}
	if code := e.run("prune", "--diverged"); code != exitOK {
		t.Fatalf("prune exit %d (%s)", code, e.stderr())
	}
	if n := len(e.eng.pruneOps); n != 2 || !e.eng.pruneOps[0].DryRun || e.eng.pruneOps[1].DryRun || !e.eng.pruneOps[1].Diverged {
		t.Fatalf("prune ops %+v", e.eng.pruneOps)
	}
}

// prune --dry-run deletes nothing and needs neither a human nor a
// terminal (D59 exempts it).
func TestPruneDryRunAllowedEverywhere(t *testing.T) {
	const unit = "0123456789abcdef0123456789abcdef"
	e := destructiveEnv(t, unit)
	e.agentCtx, e.tty = true, nil
	if code := e.run("prune", "--dry-run"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if len(e.eng.pruneOps) != 1 || !e.eng.pruneOps[0].DryRun || e.eng.pruneOps[0].KeepLast != 3 {
		t.Fatalf("ops %+v", e.eng.pruneOps)
	}
	if !strings.Contains(e.stdout(), "would delete 1 old generation(s) of 1 unit(s)") {
		t.Fatalf("stdout %q", e.stdout())
	}
}

// SEC-21 (D7): init refuses in an agent context (B.refuse) and without a
// terminal; nothing is created.
func TestSEC21InitRefusals(t *testing.T) {
	e := newEnv(t)
	e.vaults.initialized = false
	e.agentCtx = true
	if code := e.run("init"); code != exitLocked {
		t.Fatalf("agent: exit %d", code)
	}
	if !strings.Contains(e.stderr(), ui.Format(ui.MsgInitRefuseAgent, ui.Vars{})) {
		t.Fatalf("agent: stderr %q lacks B.refuse", e.stderr())
	}
	if len(e.vaults.initOpts) != 0 {
		t.Fatal("agent: Init ran")
	}

	e = newEnv(t)
	e.vaults.initialized = false
	e.interactive = false
	if code := e.run("init"); code != exitLocked {
		t.Fatalf("non-tty: exit %d", code)
	}
	if len(e.vaults.initOpts) != 0 {
		t.Fatal("non-tty: Init ran")
	}
}

// SEC-21: recover --key-file needs --insecure-key-file (before anything
// else), and recover is refused in agent contexts.
func TestSEC21RecoverRefusals(t *testing.T) {
	e := newEnv(t)
	if code := e.run("recover", "--key-file", "/nonexistent/key"); code != exitUsage {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(e.stderr(), "--insecure-key-file") {
		t.Fatalf("stderr %q", e.stderr())
	}
	if e.hardened != 0 {
		t.Fatal("hardened before refusing")
	}

	e = newEnv(t)
	e.agentCtx = true
	if code := e.run("recover", "--verify"); code != exitLocked {
		t.Fatalf("agent: exit %d", code)
	}
	if !strings.Contains(e.stderr(), "refusing to use the recovery key") {
		t.Fatalf("stderr %q", e.stderr())
	}
}

// SEC-26 (D53): vault repair is refused with an agent marker and without
// a terminal; the daemon is never asked.
func TestSEC26VaultRepairRefusals(t *testing.T) {
	e := newEnv(t)
	e.agentCtx = true
	if code := e.run("vault", "repair", "--root", e.h.Root); code != exitLocked {
		t.Fatalf("agent: exit %d", code)
	}
	if len(e.daemon.repairs) != 0 {
		t.Fatal("agent: repair requested")
	}
	e = newEnv(t)
	e.tty = nil
	if code := e.run("vault", "repair", "--global"); code != exitLocked {
		t.Fatalf("no tty: exit %d", code)
	}
	if len(e.daemon.repairs) != 0 {
		t.Fatal("no tty: repair requested")
	}
}

// factor is refused in agent contexts (SPEC §16.1).
func TestFactorRefusedInAgentContext(t *testing.T) {
	e := newEnv(t)
	e.agentCtx = true
	if code := e.run("factor", "list"); code != exitLocked {
		t.Fatalf("exit %d", code)
	}
}

// ui.AgentContext is called only by the commands SPEC §16.1 lists: never
// by targeted restores, seals, sweeps, the wrapper, unlock or status
// (D62).
func TestAgentContextNotConsultedByWorkers(t *testing.T) {
	for _, args := range [][]string{
		{"restore", "--background", "--recent", "5", "--md", "--history"},
		{"sweep", "--lock", "--quiet"},
		{"seal", "--queue"},
		{"status"},
		{"lock"},
		{"run", "--", "claude"},
	} {
		e := newEnv(t)
		consulted := 0
		a := e.app()
		a.sys.agentContext = func(_ paths.Env, _ platform.ProcTable) (bool, string) { consulted++; return true, "x" }
		a.run(args)
		if consulted != 0 {
			t.Errorf("%v consulted ui.AgentContext", args)
		}
	}
}
