package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/platform/fakeplatform"
	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/internal/ui"
	"github.com/Neorichi/precinto/internal/vault"
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

// Outside every folder without a terminal, the cwd rule stands: nothing is
// unlocked and the folder must be named (SPEC §12.8).
func TestUnlockOutsideFolder(t *testing.T) {
	e := newEnv(t)
	e.cwd = e.h.HomeDir
	e.tty, e.interactive = nil, false
	if code := e.run("unlock"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(e.stderr(), "precinto unlock --root DIR") || len(e.daemon.unlocks) != 0 {
		t.Fatalf("stderr %q unlocks %+v", e.stderr(), e.daemon.unlocks)
	}
}

// DC-35: outside every folder on a terminal, the one locked folder is
// unlocked; several are listed and picked by number, or all of them after
// the typed "unlock" (C2.confirmall).
func TestUnlockOutsideFolderPicks(t *testing.T) {
	two := func(t *testing.T) *env {
		e := newEnv(t)
		e.h.Protect(t, "work/beta")
		e.cwd = e.h.HomeDir
		return e
	}
	// One locked folder (the other is unlocked): unlocked without asking.
	e := two(t)
	e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}}
	if code := e.run("unlock"); code != exitOK {
		t.Fatalf("one locked: exit %d (%s)", code, e.stderr())
	}
	if r := e.daemon.unlocks[0]; len(r.RootIDs) != 1 || r.RootIDs[0] != "root-beta" || r.All || !r.TTY {
		t.Fatalf("one locked: request %+v", r)
	}
	// Several: the number picks one.
	e = two(t)
	e.tty.lines = []string{"2"}
	if code := e.run("unlock"); code != exitOK {
		t.Fatalf("pick: exit %d (%s)", code, e.stderr())
	}
	if r := e.daemon.unlocks[0]; len(r.RootIDs) != 1 || r.RootIDs[0] != "root-beta" || r.Confirmed {
		t.Fatalf("pick: request %+v", r)
	}
	if !strings.Contains(e.stderr(), "1) ~/work/acme") || !strings.Contains(e.stderr(), "2) ~/work/beta") {
		t.Fatalf("list %q", e.stderr())
	}
	// all, confirmed with the typed word.
	e = two(t)
	e.tty.lines = []string{"all", wordUnlock}
	if code := e.run("unlock"); code != exitOK {
		t.Fatalf("all: exit %d (%s)", code, e.stderr())
	}
	if r := e.daemon.unlocks[0]; len(r.RootIDs) != 2 || !r.Confirmed || !r.TTY {
		t.Fatalf("all: request %+v", r)
	}
	if !strings.Contains(e.tty.allPrompts(), ui.Format(ui.MsgUnlockConfirmAll, ui.Vars{N: 2, Folder: "~/work/acme"})) {
		t.Fatalf("prompts %q", e.tty.allPrompts())
	}
	// all without the word, or a bad answer: nothing unlocked.
	for _, lines := range [][]string{{"all", "no"}, {"3"}, {"x"}} {
		e = two(t)
		e.tty.lines = lines
		if code := e.run("unlock"); code != exitLocked || len(e.daemon.unlocks) != 0 {
			t.Fatalf("%v: exit %d unlocks %+v", lines, code, e.daemon.unlocks)
		}
	}
	// Every folder unlocked already: nothing to do.
	e = two(t)
	e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}, {VaultID: "root-beta", State: "unlocked"}}}
	if code := e.run("unlock"); code != exitOK || len(e.daemon.unlocks) != 0 {
		t.Fatalf("all open: exit %d unlocks %+v", code, e.daemon.unlocks)
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

// CC-08: a wrong passphrase or recovery key prints C2.badsecret (the
// catalog text, whatever the daemon sent) and exits 3, from the daemon's
// bad_secret code or a local vault.ErrBadSecret.
func TestUnlockBadSecret(t *testing.T) {
	want := ui.Format(ui.MsgUnlockBadSecret, ui.Vars{Folder: "~/work/acme"})
	for _, err := range []error{
		&ipc.Error{Code: ipc.CodeBadSecret},
		&ipc.Error{Code: ipc.CodeBadSecret, Msg: "precinto: some other wording"},
		fmt.Errorf("unwrap: %w", vault.ErrBadSecret),
	} {
		e := newEnv(t)
		e.daemon.unlockErr = err
		if code := e.run("unlock"); code != exitLocked {
			t.Fatalf("%v: exit %d", err, code)
		}
		if got := e.stderr(); !strings.Contains(got, want) || strings.Contains(got, "other wording") || strings.Contains(got, "unwrap") {
			t.Fatalf("%v: stderr %q, want only %q", err, got, want)
		}
	}
	// Elsewhere the same class still prints C2.badsecret, never the chain.
	e := newEnv(t)
	if code := e.app().fail("x", fmt.Errorf("wrapped: %w", vault.ErrBadSecret)); code != exitLocked {
		t.Fatalf("fail: exit %d", code)
	}
	if !strings.Contains(e.stderr(), "that passphrase or recovery key is not right") || strings.Contains(e.stderr(), "wrapped") {
		t.Fatalf("fail stderr %q", e.stderr())
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

// TestUnlockDeadlineIsRealTime (D77): the deadline an unlock sends is real
// time (wireDeadline), because the daemon checks it with its own clock;
// the CLI's injected clock — here frozen decades or a year away from the
// system clock — never reaches the wire.
func TestUnlockDeadlineIsRealTime(t *testing.T) {
	const year = 365 * 24 * time.Hour
	for name, start := range map[string]time.Time{
		"epoch":                      testkit.Epoch,
		"30 years before epoch":      testkit.Epoch.Add(-30 * year),
		"70 years after epoch":       testkit.Epoch.Add(70 * year),
		"a year behind the system":   time.Now().Add(-year).Round(0),
		"a year ahead of the system": time.Now().Add(year).Round(0),
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.h.Clock = fakeplatform.NewClock(start)
			e.daemon.unlockRes = ipc.UnlockResp{Unlocked: []string{"root-acme"}, Until: start.Add(8 * time.Hour)}
			before := time.Now()
			if code := e.run("unlock"); code != exitOK {
				t.Fatalf("exit %d (%s)", code, e.stderr())
			}
			after := time.Now()
			if len(e.daemon.unlocks) != 1 {
				t.Fatalf("%d unlock requests", len(e.daemon.unlocks))
			}
			if dl := e.daemon.unlocks[0].Deadline; dl.Before(before.Add(unlockDeadline)) || dl.After(after.Add(unlockDeadline)) {
				t.Fatalf("deadline %v, want real time %v after [%v, %v] (CLI clock %v)", dl, unlockDeadline, before, after, start)
			}
		})
	}
}

// writeBrokenConfig replaces config.toml with one that does not load: a
// decimal size, an easy mistake (the README asks for binary units).
func writeBrokenConfig(t *testing.T, e *env) {
	t.Helper()
	body := "version = 1\n[policy]\nmin_free = \"2GB\"\n[[roots]]\nid = \"root-acme\"\npath = \"" + e.h.Root + "\"\n"
	if err := os.WriteFile(e.h.Layout.ConfigFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// UX-09: a config.toml that does not load never stops `precinto lock`:
// locking every folder needs no configuration, so the request goes out
// and the folders are named from the agent's status; the config error is
// still reported, with the key, the line and the hint. With --root the
// folder cannot be found: lock says so, names precinto lock, and locks
// nothing.
func TestLockWithBrokenConfig(t *testing.T) {
	e := newEnv(t)
	writeBrokenConfig(t, e)
	e.daemon.lockRes = ipc.LockResp{Locked: []string{"root-acme"}}
	e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", RootPath: e.h.Root, State: "locked"}}}
	if code := e.run("lock", "--end"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if len(e.daemon.locks) != 1 || !e.daemon.locks[0].All || !e.daemon.locks[0].End {
		t.Fatalf("lock request %+v", e.daemon.locks)
	}
	if !strings.Contains(e.stdout(), "locked ~/work/acme.") {
		t.Errorf("stdout %q", e.stdout())
	}
	for _, w := range []string{"policy.min_free", "line 3", `"2GiB"`} {
		if !strings.Contains(e.stderr(), w) {
			t.Errorf("stderr %q does not say %q", e.stderr(), w)
		}
	}

	e = newEnv(t)
	writeBrokenConfig(t, e)
	if code := e.run("lock", "--root", e.h.Root); code != exitError {
		t.Fatalf("--root: exit %d (%s)", code, e.stderr())
	}
	if len(e.daemon.locks) != 0 {
		t.Fatalf("--root with a broken config locked %+v", e.daemon.locks)
	}
	if !strings.Contains(e.stderr(), "policy.min_free") || !strings.Contains(e.stderr(), "precinto lock") {
		t.Errorf("--root: stderr %q", e.stderr())
	}
}

// UX-08: after a cancelled or mistyped unlock the CLI also says when it
// can be tried again (D27's back-off, policy.prompt_backoff, 30 s by
// default), so the agent's refusal of an immediate retry is no surprise.
func TestUnlockSaysWhenToRetry(t *testing.T) {
	for _, err := range []error{&ipc.Error{Code: ipc.CodeCancelled}, &ipc.Error{Code: ipc.CodeBadSecret}} {
		e := newEnv(t)
		e.daemon.unlockErr = err
		if code := e.run("unlock"); code != exitLocked {
			t.Fatalf("%v: exit %d", err, code)
		}
		if want := ui.Format(ui.MsgUnlockRetry, ui.Vars{Wait: 30 * time.Second}); !strings.Contains(e.stderr(), want) {
			t.Errorf("%v: stderr %q lacks %q", err, e.stderr(), want)
		}
	}
}

// pinPolicy writes state/policy.pinned with the settings the user
// confirmed last (the agent enforces Strictest(config.toml, pin), D55).
func pinPolicy(t *testing.T, e *env, c config.Config) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(e.h.Layout.PolicyPinned), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePinned(e.h.Layout.PolicyPinned, config.Pinned{Config: c, ConfirmedAt: testkit.Epoch}); err != nil {
		t.Fatal(err)
	}
}

// UX-14: C2.ok quotes the policy in force, not config.toml's unconfirmed
// edit: with idle_soft raised to 30 min in config.toml but 15 min
// confirmed, the folder locks after 15 min until the edit is confirmed.
// The terminal review of pending edits uses its own wording (C13.review),
// never C13.policy's "review them at your next unlock", and C2.ok comes
// after the decision, with the values that decision put in force. The
// count of sessions is an upper bound ("up to").
func TestUnlockQuotesThePolicyInForce(t *testing.T) {
	for _, confirm := range []bool{false, true} {
		e := newEnv(t)
		pinPolicy(t, e, e.loadConfig())
		c := e.loadConfig()
		c.Policy.IdleSoft = config.Duration(30 * time.Minute)
		e.saveConfig(c)
		e.daemon.unlockRes = ipc.UnlockResp{Unlocked: []string{"root-acme"}, Until: testkit.Epoch.Add(8 * time.Hour),
			Pending: []string{"policy.idle_soft: 15m → 30m"}}
		e.tty.yesno = []bool{confirm}
		if code := e.run("unlock"); code != exitOK {
			t.Fatalf("confirm=%v: exit %d (%s)", confirm, code, e.stderr())
		}
		idle := 15 * time.Minute
		if confirm {
			idle = 30 * time.Minute
		}
		ok := ui.Format(ui.MsgUnlockOK, ui.Vars{Folder: "~/work/acme", N: 5, Idle: idle, Until: testkit.Epoch.Add(8 * time.Hour)})
		review := ui.Format(ui.MsgPolicyReview, ui.Vars{N: 1})
		out := e.stderr()
		if !strings.Contains(out, ok) {
			t.Errorf("confirm=%v: stderr %q lacks %q", confirm, out, ok)
		}
		if !strings.Contains(out, review) || strings.Contains(out, "at your next unlock") {
			t.Errorf("confirm=%v: stderr %q: want the review wording %q", confirm, out, review)
		}
		if i, j := strings.Index(out, review), strings.Index(out, ok); i < 0 || j < i {
			t.Errorf("confirm=%v: C2.ok comes before the review: %q", confirm, out)
		}
		if !strings.Contains(out, "Restoring up to 5 recent sessions") {
			t.Errorf("confirm=%v: C2.ok promises an exact count: %q", confirm, out)
		}
	}
	// A confirmation the agent refuses still says the folder is unlocked
	// (with the policy that stays in force), then reports the failure.
	e := newEnv(t)
	pinPolicy(t, e, e.loadConfig())
	c := e.loadConfig()
	c.Policy.IdleSoft = config.Duration(30 * time.Minute)
	e.saveConfig(c)
	e.daemon.unlockRes = ipc.UnlockResp{Unlocked: []string{"root-acme"}, Until: testkit.Epoch.Add(8 * time.Hour),
		Pending: []string{"policy.idle_soft: 15m → 30m"}}
	e.daemon.policyErr = &ipc.Error{Code: ipc.CodeInternal, Msg: "precinto: could not save the confirmed settings"}
	e.tty.yesno = []bool{true}
	if code := e.run("unlock"); code == exitOK {
		t.Fatalf("a failed confirmation exits 0 (%s)", e.stderr())
	}
	ok := ui.Format(ui.MsgUnlockOK, ui.Vars{Folder: "~/work/acme", N: 5, Idle: 15 * time.Minute, Until: testkit.Epoch.Add(8 * time.Hour)})
	if out := e.stderr(); !strings.Contains(out, ok) || !strings.Contains(out, "could not save the confirmed settings") || strings.Index(out, ok) > strings.Index(out, "could not save") {
		t.Errorf("failed confirmation: stderr %q, want %q first, then the error", out, ok)
	}
}

// D150 (UX-14, U6-6): nothing is restored after a global unlock, so its
// line promises no background restore and names restore --global, which
// restores what belongs to no folder; a folder's line stays C2.ok.
func TestUnlockGlobalNamesRestoreGlobal(t *testing.T) {
	e := newEnv(t)
	until := testkit.Epoch.Add(8 * time.Hour)
	e.daemon.unlockRes = ipc.UnlockResp{Unlocked: []string{vault.GlobalID}, Until: until}
	if code := e.run("unlock", "--global"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	out := e.stderr()
	if !strings.Contains(out, "precinto restore --global") || strings.Contains(out, "Restoring up to") || !strings.Contains(out, "the global vault unlocked.") {
		t.Fatalf("stderr %q, want the global vault's own line (C2.okglobal)", out)
	}
}

// D146 (U6-1): a folder whose removal from config.toml waits for its
// confirmation is still protected by the agent (the confirmed settings
// hold it), so unlock can name it — by --root or as the working directory
// — and the review of that removal is reachable from the folder itself.
func TestUnlockNamesAFolderWhoseRemovalWaits(t *testing.T) {
	for _, args := range [][]string{{"unlock", "--root", ""}, {"unlock"}} {
		e := newEnv(t)
		pinPolicy(t, e, e.loadConfig()) // the confirmed settings hold the folder
		c := e.loadConfig()
		c.Roots = nil
		e.saveConfig(c) // removed from config.toml: a weakening edit, pending
		e.daemon.unlockRes = ipc.UnlockResp{Unlocked: []string{"root-acme"}, Until: testkit.Epoch.Add(8 * time.Hour)}
		if args[len(args)-1] == "" {
			args[len(args)-1] = e.h.Root
		}
		if code := e.run(args...); code != exitOK {
			t.Fatalf("%v: exit %d (%s)", args, code, e.stderr())
		}
		if len(e.daemon.unlocks) != 1 || len(e.daemon.unlocks[0].RootIDs) != 1 || e.daemon.unlocks[0].RootIDs[0] != "root-acme" {
			t.Fatalf("%v: unlock requests %+v", args, e.daemon.unlocks)
		}
	}
}

// D145 (S6-1): while the confirmed settings name no folder (signed by the
// global vault alone, which a folder unlock never checks), the review of
// a terminal unlock of a folder also names the folders whose vault is kept
// but that config.toml does not protect: confirming adopts config.toml, so
// a yes never drops one unseen, even when the agent lists nothing. unlock
// --global checks the settings itself and shows no such line.
func TestUnlockReviewNamesTheFoldersTheSettingsDrop(t *testing.T) {
	setup := func(t *testing.T) *env {
		e := newEnv(t)
		if err := os.MkdirAll(e.h.Layout.VaultsDir, 0o700); err != nil {
			t.Fatal(err)
		}
		e.vaults.metas["root-acme"] = vault.Meta{ID: "root-acme", RootPath: e.h.Root}
		e.vaults.metas["root-beta"] = vault.Meta{ID: "root-beta", RootPath: filepath.Join(e.h.HomeDir, "work", "beta")}
		c := e.loadConfig()
		c.Roots = nil
		if err := os.MkdirAll(filepath.Dir(e.h.Layout.PolicyPinned), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := config.SavePinned(e.h.Layout.PolicyPinned, config.Pinned{Config: c, MACs: map[string]string{vault.GlobalID: strings.Repeat("ab", 32)}}); err != nil {
			t.Fatal(err)
		}
		e.daemon.unlockRes = ipc.UnlockResp{Unlocked: []string{"root-acme"}}
		return e
	}
	for _, yes := range []bool{false, true} {
		e := setup(t)
		e.tty.yesno = []bool{yes}
		if code := e.run("unlock"); code != exitOK {
			t.Fatalf("yes=%v: exit %d (%s)", yes, code, e.stderr())
		}
		out := e.stderr()
		if !strings.Contains(out, ui.Format(ui.MsgPolicyReview, ui.Vars{N: 1})) || !strings.Contains(out, "~/work/beta: no longer protected") ||
			strings.Contains(out, "~/work/acme: no longer protected") || strings.Contains(out, "roots[") {
			t.Fatalf("yes=%v: review %q", yes, out)
		}
		confirmed := len(e.daemon.policies) == 1 && e.daemon.policies[0].Confirm
		if confirmed != yes {
			t.Fatalf("yes=%v: policy calls %+v", yes, e.daemon.policies)
		}
	}
	e := setup(t)
	e.daemon.unlockRes = ipc.UnlockResp{Unlocked: []string{vault.GlobalID}}
	if code := e.run("unlock", "--global"); code != exitOK {
		t.Fatalf("unlock --global: exit %d (%s)", code, e.stderr())
	}
	if strings.Contains(e.stderr(), "no longer protected") || len(e.tty.prompts) != 0 {
		t.Fatalf("unlock --global reviews the dropped folders: %q (prompts %q)", e.stderr(), e.tty.prompts)
	}
}
