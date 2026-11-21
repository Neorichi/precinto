package main

import (
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/shellinit"
	"github.com/precinto/precinto/internal/ui"
)

func TestShellInitScript(t *testing.T) {
	e := newEnv(t)
	if code := e.run("shell-init", "zsh"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	o := e.shell.scripts[0]
	if o.Shell != "zsh" || strings.Join(o.Harnesses, ",") != "claude,codex" || o.Exe != "/opt/precinto/bin/precinto" {
		t.Fatalf("options %+v", o)
	}
	if e.stdout() != "# precinto zsh integration\n" {
		t.Fatalf("stdout %q", e.stdout())
	}
	if len(e.engExp) != 0 {
		t.Fatal("shell-init built the engine (it runs on every shell start)")
	}
	e = newEnv(t)
	if code := e.run("shell-init", "tcsh"); code != exitUsage {
		t.Fatalf("tcsh: exit %d", code)
	}
}

// --install appends the eval line only after consent (SPEC §15.5).
func TestShellInitInstall(t *testing.T) {
	e := newEnv(t)
	e.tty.yesno = []bool{false}
	if code := e.run("shell-init", "bash", "--install"); code != exitLocked || len(e.shell.installed) != 0 {
		t.Fatalf("declined: exit %d installed %v", code, e.shell.installed)
	}
	e = newEnv(t)
	if code := e.run("shell-init", "bash", "--install"); code != exitOK || len(e.shell.installed) != 1 {
		t.Fatalf("exit %d installed %v", code, e.shell.installed)
	}
	e = newEnv(t)
	e.tty = nil
	if code := e.run("shell-init", "fish", "--install"); code != exitLocked {
		t.Fatalf("no tty: exit %d", code)
	}
}

// shell-hook: OnEnter decides; notify prints C1.notify and sets the skip
// key; prompt asks C1.prompt and unlocks on Enter only.
func TestShellHook(t *testing.T) {
	e := newEnv(t)
	e.shell.enter = shellinit.EnterResult{Action: shellinit.EnterNotify, RootID: "root-acme", Epoch: 7}
	if code := e.run("shell-hook", "--shell", "zsh", "--pwd", e.h.Root, "--prev", e.h.HomeDir, "--skip", "x:1", "--first"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if r := e.shell.requests[0]; r.PWD != e.h.Root || r.PrevPWD != e.h.HomeDir || r.SkipKey != "x:1" || !r.FirstRun || r.Shell != "zsh" {
		t.Fatalf("request %+v", r)
	}
	if e.stdout() != "_PRECINTO_SKIP='root-acme:7'\n" {
		t.Fatalf("stdout %q", e.stdout())
	}
	if !strings.Contains(e.stderr(), ui.Format(ui.MsgEnterNotify, ui.Vars{Folder: "~/work/acme"})) {
		t.Fatalf("stderr %q", e.stderr())
	}

	e = newEnv(t)
	e.shell.enter = shellinit.EnterResult{Action: shellinit.EnterPrompt, RootID: "root-acme", Epoch: 3}
	e.tty.lines = []string{""} // Enter
	if code := e.run("shell-hook", "--shell", "fish", "--pwd", e.h.Root); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if len(e.daemon.unlocks) != 1 || e.daemon.unlocks[0].RootIDs[0] != "root-acme" || !e.daemon.unlocks[0].TTY {
		t.Fatalf("unlocks %+v", e.daemon.unlocks)
	}
	if e.stdout() != "set -g _PRECINTO_SKIP 'root-acme:3'\n" {
		t.Fatalf("stdout %q", e.stdout())
	}

	e = newEnv(t)
	e.shell.enter = shellinit.EnterResult{Action: shellinit.EnterPrompt, RootID: "root-acme", Epoch: 3}
	e.tty.lines = []string{"n"} // any other key skips
	e.run("shell-hook", "--shell", "bash", "--pwd", e.h.Root)
	if len(e.daemon.unlocks) != 0 {
		t.Fatal("unlocked on a skip")
	}
	if e.stdout() != "_PRECINTO_SKIP='root-acme:3'\n" {
		t.Fatalf("stdout %q", e.stdout())
	}

	// Nothing to do, or any failure: silent.
	e = newEnv(t)
	e.shell.enterErr = errBoom
	if code := e.run("shell-hook", "--shell", "zsh", "--pwd", e.h.Root); code != exitOK || e.stdout() != "" || e.stderr() != "" {
		t.Fatalf("failure not silent: %d %q %q", code, e.stdout(), e.stderr())
	}
}

var errBoom = boomError("boom")

type boomError string

func (b boomError) Error() string { return string(b) }

func TestShellAssignQuoting(t *testing.T) {
	if got := shellAssign("zsh", "V", "a'b"); got != `V='a'\''b'` {
		t.Fatalf("%s", got)
	}
	if got := shellAssign("fish", "V", `a'b\c`); got != `set -g V 'a\'b\\c'` {
		t.Fatalf("%s", got)
	}
}
