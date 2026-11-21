package main

import (
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
)

// D50: `precinto lock` with no flag locks every folder; --root narrows it;
// --hard is an alias of --end. lock never autostarts the daemon.
func TestLockDefaultScopeAll(t *testing.T) {
	e := newEnv(t)
	e.daemon.lockRes = ipc.LockResp{Locked: []string{"root-acme"}}
	if code := e.run("lock"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if len(e.daemon.locks) != 1 || !e.daemon.locks[0].All || len(e.daemon.locks[0].RootIDs) != 0 {
		t.Fatalf("lock request %+v", e.daemon.locks)
	}
	if e.dials[0].Autostart {
		t.Fatal("lock autostarted the daemon")
	}
	if !strings.Contains(e.stdout(), "locked ~/work/acme.") {
		t.Fatalf("stdout %q", e.stdout())
	}

	e = newEnv(t)
	if code := e.run("lock", "--root", e.h.Root, "--hard", "--force", "--let-finish"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	r := e.daemon.locks[0]
	if r.All || len(r.RootIDs) != 1 || r.RootIDs[0] != "root-acme" || !r.End || !r.Force || !r.LetFinish {
		t.Fatalf("lock request %+v", r)
	}
}

func TestLockWithoutDaemonIsLocked(t *testing.T) {
	e := newEnv(t)
	e.dialErr = ipc.ErrNoDaemon
	if code := e.run("lock"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(e.stdout(), "every folder is locked") {
		t.Fatalf("stdout %q", e.stdout())
	}
}

func TestLockOutsideFolderIsUsage(t *testing.T) {
	e := newEnv(t)
	if code := e.run("lock", "--root", e.h.HomeDir); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if len(e.daemon.locks) != 0 {
		t.Fatal("locked anyway")
	}
}

// unlock of the working directory's folder: TTY relay, autostart, C2.ok.
func TestUnlockCwdFolder(t *testing.T) {
	e := newEnv(t)
	e.daemon.unlockRes = ipc.UnlockResp{Unlocked: []string{"root-acme"}, Until: testkit.Epoch.Add(8 * time.Hour)}
	if code := e.run("unlock", "--for", "2h", "--factor", "passphrase"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if e.hardened != 1 {
		t.Fatal("unlock did not harden first (SPEC §4.6)")
	}
	if !e.dials[0].Autostart {
		t.Fatal("unlock must autostart the daemon (SPEC §13.1)")
	}
	r := e.daemon.unlocks[0]
	if len(r.RootIDs) != 1 || r.RootIDs[0] != "root-acme" || r.All || !r.TTY || r.TTL != 2*time.Hour || r.Factor != "passphrase" {
		t.Fatalf("unlock request %+v", r)
	}
	if r.Deadline.IsZero() {
		t.Fatal("no deadline")
	}
	if _, ok := e.daemon.unlockUI[0].(*fakeTTY); !ok {
		t.Fatalf("relay is %T, want the terminal", e.daemon.unlockUI[0])
	}
	want := ui.Format(ui.MsgUnlockOK, ui.Vars{Folder: "~/work/acme", N: 5, Idle: 15 * time.Minute, Until: testkit.Epoch.Add(8 * time.Hour)})
	if !strings.Contains(e.stderr(), want) {
		t.Fatalf("stderr %q lacks %q", e.stderr(), want)
	}
}

// unlock --all needs typed confirmation on a terminal (D40); without a
// terminal it is refused before the daemon is asked.
func TestUnlockAllTypedConfirmation(t *testing.T) {
	e := newEnv(t)
	e.tty.lines = []string{"unlock"}
	if code := e.run("unlock", "--all"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	r := e.daemon.unlocks[0]
	if !r.All || !r.Confirmed {
		t.Fatalf("request %+v", r)
	}
	if !strings.Contains(e.tty.allPrompts(), `Type "unlock" to confirm`) {
		t.Fatalf("prompts %q", e.tty.allPrompts())
	}

	e = newEnv(t)
	e.tty.lines = []string{"yes"}
	if code := e.run("unlock", "--all"); code != exitLocked {
		t.Fatalf("wrong word: exit %d", code)
	}
	if len(e.daemon.unlocks) != 0 {
		t.Fatal("unlocked without the typed word")
	}

	e = newEnv(t)
	e.tty, e.interactive = nil, false
	if code := e.run("unlock", "--all"); code != exitLocked {
		t.Fatalf("no tty: exit %d", code)
	}
	if len(e.daemon.unlocks) != 0 {
		t.Fatal("unlocked without a terminal")
	}
}

// Without a terminal, unlock relays nothing (the daemon falls back to GUI
// factors or pinentry, D27).
func TestUnlockHeadless(t *testing.T) {
	e := newEnv(t)
	e.tty, e.interactive = nil, false
	if code := e.run("unlock"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if e.daemon.unlocks[0].TTY {
		t.Fatal("TTY claimed without a terminal")
	}
	if _, ok := e.daemon.unlockUI[0].(headlessUI); !ok {
		t.Fatalf("relay %T", e.daemon.unlockUI[0])
	}
}

func TestUnlockOutsideFolder(t *testing.T) {
	e := newEnv(t)
	e.cwd = e.h.HomeDir
	if code := e.run("unlock"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(e.stderr(), "precinto unlock --root DIR") {
		t.Fatalf("stderr %q", e.stderr())
	}
}

// per_root_auth = false: unlock outside a folder unlocks every folder
// (D40), confirmed by the policy itself.
func TestUnlockPerRootAuthOff(t *testing.T) {
	e := newEnv(t)
	c := e.loadConfig()
	c.Policy.PerRootAuth = false
	e.saveConfig(c)
	e.cwd = e.h.HomeDir
	if code := e.run("unlock"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if r := e.daemon.unlocks[0]; !r.All || !r.Confirmed {
		t.Fatalf("request %+v", r)
	}
}

// A cancelled prompt prints C2.cancelled and exits 3; a refusal from the
// daemon (agent context, SEC-24) prints the daemon's catalog text.
func TestUnlockCancelAndRefusal(t *testing.T) {
	e := newEnv(t)
	e.daemon.unlockErr = &ipc.Error{Code: ipc.CodeCancelled, Msg: "cancelled"}
	if code := e.run("unlock"); code != exitLocked {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(e.stderr(), ui.Format(ui.MsgUnlockCancelled, ui.Vars{Folder: "~/work/acme"})) {
		t.Fatalf("stderr %q", e.stderr())
	}

	e = newEnv(t)
	msg := ui.Format(ui.MsgRefuseAgent, ui.Vars{Action: "unlock", Folder: "~/work/other", Command: "unlock --root ~/work/other"})
	e.daemon.unlockErr = &ipc.Error{Code: ipc.CodeAgentContext, Msg: msg}
	if code := e.run("unlock", "--root", e.h.Root); code != exitLocked {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(e.stderr(), msg) {
		t.Fatalf("stderr %q", e.stderr())
	}
}

// D48: pending weakening changes are listed after a terminal unlock and
// confirmed only on an explicit yes.
func TestUnlockPendingPolicy(t *testing.T) {
	e := newEnv(t)
	e.daemon.unlockRes = ipc.UnlockResp{Unlocked: []string{"root-acme"}, Pending: []string{"policy.idle_soft: 15m -> 2h"}}
	e.tty.yesno = []bool{false}
	if code := e.run("unlock"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if len(e.daemon.policies) != 0 {
		t.Fatalf("confirmed without a yes: %+v", e.daemon.policies)
	}
	if !strings.Contains(e.stderr(), "policy.idle_soft") {
		t.Fatalf("stderr %q", e.stderr())
	}
	e = newEnv(t)
	e.daemon.unlockRes = ipc.UnlockResp{Unlocked: []string{"root-acme"}, Pending: []string{"x"}}
	e.tty.yesno = []bool{true}
	e.run("unlock")
	if len(e.daemon.policies) != 1 || !e.daemon.policies[0].Confirm {
		t.Fatalf("policies %+v", e.daemon.policies)
	}
}

func TestUnlockExclusiveScopes(t *testing.T) {
	e := newEnv(t)
	if code := e.run("unlock", "--all", "--global"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
}

func TestUnlockAlreadyUnlocked(t *testing.T) {
	e := newEnv(t)
	if code := e.run("unlock"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(e.stderr(), "~/work/acme is already unlocked.") {
		t.Fatalf("stderr %q", e.stderr())
	}
}
