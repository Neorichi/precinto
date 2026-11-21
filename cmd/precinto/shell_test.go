package main

import (
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/shellinit"
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

// shell-hook prints shellinit.EnterResult.Lines and nothing else (D69): no
// prompt, no unlock, no shell assignment; the scripts parse the lines.
func TestShellHook(t *testing.T) {
	e := newEnv(t)
	e.shell.enter = shellinit.EnterResult{Action: shellinit.EnterNotify, RootID: "root-acme", Path: e.h.Root, Folder: "~/work/acme", Epoch: 7, Message: "precinto: ~/work/acme is locked."}
	if code := e.run("shell-hook", "--shell", "zsh", "--pwd", e.h.Root, "--prev", e.h.HomeDir, "--skip", "x:1", "--first"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	r := e.shell.requests[0]
	if r.PWD != e.h.Root || r.PrevPWD != e.h.HomeDir || r.SkipKey != "x:1" || !r.FirstRun || r.Shell != "zsh" || r.Home != e.h.HomeDir {
		t.Fatalf("request %+v", r)
	}
	if e.stdout() != e.shell.enter.Lines() || e.stderr() != "" {
		t.Fatalf("stdout %q stderr %q, want exactly the result lines", e.stdout(), e.stderr())
	}

	// A prompt is printed as data too: precinto never reads the terminal
	// or unlocks from shell-hook.
	e = newEnv(t)
	e.shell.enter = shellinit.EnterResult{Action: shellinit.EnterPrompt, RootID: "root-acme", Path: e.h.Root, Epoch: 3, Message: "m"}
	e.tty.lines = []string{""} // an Enter that must not be read
	if code := e.run("shell-hook", "--shell", "fish", "--pwd", e.h.Root); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if len(e.daemon.unlocks) != 0 {
		t.Fatalf("shell-hook unlocked: %+v", e.daemon.unlocks)
	}
	if e.stdout() != e.shell.enter.Lines() {
		t.Fatalf("stdout %q", e.stdout())
	}

	// Nothing to do, or any failure: silent.
	e = newEnv(t)
	e.shell.enterErr = errBoom
	if code := e.run("shell-hook", "--shell", "zsh", "--pwd", e.h.Root); code != exitOK || e.stdout() != "" || e.stderr() != "" {
		t.Fatalf("failure not silent: %d %q %q", code, e.stdout(), e.stderr())
	}
	e = newEnv(t)
	if code := e.run("shell-hook", "--shell", "zsh", "--pwd", e.h.Root); code != exitOK || e.stdout() != "" {
		t.Fatalf("nothing to do: %d %q", code, e.stdout())
	}
}

var errBoom = boomError("boom")

type boomError string

func (b boomError) Error() string { return string(b) }
