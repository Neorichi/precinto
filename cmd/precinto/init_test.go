package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

func TestParseFactorArgs(t *testing.T) {
	got, err := parseFactorArgs(nil, "darwin")
	if err != nil || len(got) != 1 || got[0].kind != vault.FactorSE {
		t.Fatalf("darwin default %+v %v", got, err)
	}
	got, err = parseFactorArgs(nil, "linux")
	if err != nil || len(got) != 1 || got[0].kind != vault.FactorPassphrase {
		t.Fatalf("linux default %+v %v", got, err)
	}
	if _, err := parseFactorArgs([]string{"se"}, "linux"); err == nil {
		t.Fatal("se accepted on linux")
	}
	got, err = parseFactorArgs([]string{"passphrase", "plugin:age1yubikey1qwerty"}, "darwin")
	if err != nil || len(got) != 2 || got[1].plugin != "yubikey" || got[1].recipient != "age1yubikey1qwerty" {
		t.Fatalf("%+v %v", got, err)
	}
	for _, bad := range []string{"plugin:age1qqq", "plugin:x", "plugin:AGE1YUBIKEY1Q", "tpm"} {
		if _, err := parseFactorArgs([]string{bad}, "darwin"); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, err := parseFactorArgs([]string{"passphrase", "passphrase"}, "darwin"); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestParseSEKeygen(t *testing.T) {
	out := "# created: 2026-11-21T09:00:00Z\n# access control: any biometry or passcode\n# public key: age1se1qexample\n# recipient (tag): age1tag1qexample\nAGE-PLUGIN-SE-1QEXAMPLE\n"
	r, stub := parseSEKeygen([]byte(out))
	if r != "age1tag1qexample" || stub != "AGE-PLUGIN-SE-1QEXAMPLE" {
		t.Fatalf("recipient %q stub %q", r, stub)
	}
	r, _ = parseSEKeygen([]byte("# public key: age1se1qonly\nAGE-PLUGIN-SE-1Q\n"))
	if r != "age1se1qonly" {
		t.Fatalf("recipient %q", r)
	}
}

// init with the Secure Enclave factor: keygen through the plugin pinned
// with PATH limited to its directory, Init, then the recovery key on the
// alternate screen (D7) and the service offer.
func TestInitSecureEnclave(t *testing.T) {
	e := newEnv(t)
	e.vaults.initialized = false
	bin := fakePluginDir(t, e, "age-plugin-se")
	e.execOut["keygen"] = []byte("# public key: age1se1qexample\nAGE-PLUGIN-SE-1QEXAMPLE\n")
	e.tty.yesno = []bool{false} // no service
	if code := e.run("init"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if e.hardened != 1 {
		t.Fatal("init did not harden")
	}
	x := e.execs[0]
	if x.Argv[0] != filepath.Join(bin, "age-plugin-se") || strings.Join(x.Argv[1:], " ") != "keygen --access-control any-biometry-or-passcode" {
		t.Fatalf("keygen %v", x.Argv)
	}
	if x.Env[0] != "PATH="+bin {
		t.Fatalf("plugin env %v (PATH must be limited to its directory, S2)", x.Env)
	}
	spec := e.vaults.initOpts[0].Factors[0]
	if spec.Kind != vault.FactorSE || spec.Recipient != "age1se1qexample" || spec.IdentityStub != "AGE-PLUGIN-SE-1QEXAMPLE" || spec.SEAccessControl != seAccessControl {
		t.Fatalf("spec %+v", spec)
	}
	if len(e.tty.shown) != 1 || e.tty.shown[0] != "TEST-RECOVERY-PLACEHOLDER" {
		t.Fatalf("recovery key not shown on the secret screen: %v", e.tty.shown)
	}
	if strings.Contains(e.stdout()+e.stderr(), "TEST-RECOVERY-PLACEHOLDER") {
		t.Fatal("recovery key printed outside the secret screen")
	}
	if len(e.launchctl) != 0 {
		t.Fatal("service installed without consent")
	}
}

// B.needse when age-plugin-se is missing; B.remote offers a passphrase in
// tmux/SSH (D60).
func TestInitNeedsSEPlugin(t *testing.T) {
	e := newEnv(t)
	e.vaults.initialized = false
	if code := e.run("init"); code != exitError {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(e.stderr(), ui.Format(ui.MsgInitNeedSE, ui.Vars{})) {
		t.Fatalf("stderr %q", e.stderr())
	}
	if len(e.vaults.initOpts) != 0 {
		t.Fatal("Init ran")
	}
}

func TestInitRemoteOffersPassphrase(t *testing.T) {
	e := newEnv(t)
	e.vaults.initialized = false
	fakePluginDir(t, e, "age-plugin-se")
	e.uictx = platform.UIContext{TTY: true, Tmux: true}
	e.tty.yesno = []bool{false} // decline B.remote; then the service offer defaults
	e.execOut["keygen"] = []byte("# public key: age1se1q\nAGE-PLUGIN-SE-1Q\n")
	e.run("init")
	if !strings.Contains(e.tty.allPrompts(), ui.Format(ui.MsgInitRemote, ui.Vars{})) {
		t.Fatalf("B.remote not offered: %q", e.tty.allPrompts())
	}
}

// --recovery-out writes the key to a new 0600 file and does not show it;
// it is refused inside a protected folder before anything is created.
func TestInitRecoveryOut(t *testing.T) {
	e := newEnv(t)
	e.vaults.initialized = false
	fakePluginDir(t, e, "age-plugin-se")
	e.execOut["keygen"] = []byte("# public key: age1se1q\nAGE-PLUGIN-SE-1Q\n")
	e.tty.yesno = []bool{false}
	out := filepath.Join(e.h.Dir, "recovery.txt")
	if code := e.run("init", "--recovery-out", out); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	b, err := os.ReadFile(out)
	if err != nil || string(b) != "TEST-RECOVERY-PLACEHOLDER\n" {
		t.Fatalf("file %q %v", b, err)
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if len(e.tty.shown) != 0 {
		t.Fatal("shown although written to a file")
	}

	e = newEnv(t)
	e.vaults.initialized = false
	if code := e.run("init", "--recovery-out", filepath.Join(e.h.Root, "key.txt")); code != exitLocked {
		t.Fatalf("inside folder: exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(e.h.Root, "key.txt")); !os.IsNotExist(err) {
		t.Fatal("file created inside a protected folder")
	}
	if code := e.run("init", "--recovery-out", filepath.Join(e.h.ClaudeConfig, "key.txt")); code != exitLocked {
		t.Fatalf("inside a harness home: exit %d", code)
	}
	if len(e.vaults.initOpts) != 0 {
		t.Fatal("Init ran before the output was validated")
	}
}

// A failed Init leaves no recovery file behind.
func TestInitFailureRemovesRecoveryOut(t *testing.T) {
	e := newEnv(t)
	e.vaults.initialized = false
	e.vaults.initErr = vault.ErrPluginPin
	fakePluginDir(t, e, "age-plugin-se")
	e.execOut["keygen"] = []byte("# public key: age1se1q\nAGE-PLUGIN-SE-1Q\n")
	out := filepath.Join(e.h.Dir, "recovery.txt")
	if code := e.run("init", "--recovery-out", out); code != exitVerify {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("recovery file left behind")
	}
}

// UX-07: the recovery key is confirmed before anything exists. Stopping
// at its screen (Ctrl-C, then no to seeing it again) sets nothing up: init
// exits 3 saying so, never with a raw "ui: cancelled" or a lost key, and
// the next init starts over instead of saying "already set up".
func TestInitStoppedBeforeTheKeyIsConfirmed(t *testing.T) {
	e := newEnv(t)
	e.vaults.initialized = false
	fakePluginDir(t, e, "age-plugin-se")
	e.execOut["keygen"] = []byte("# public key: age1se1q\nAGE-PLUGIN-SE-1Q\n")
	e.tty.screens = []error{ui.ErrCancelled}
	e.tty.yesno = []bool{false} // Show it again? no
	if code := e.run("init"); code != exitLocked {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if e.vaults.initialized {
		t.Fatal("init set up the vaults without a confirmed recovery key")
	}
	got := e.stderr()
	if !strings.Contains(got, textInitNotConfirmed) || strings.Contains(got, "ui: cancelled") || strings.Contains(got, ui.Format(ui.MsgRecoveryLost, ui.Vars{})) {
		t.Fatalf("stderr %q", got)
	}
	e.tty.yesno = []bool{false} // no service
	if code := e.run("init"); code != exitOK || !e.vaults.initialized {
		t.Fatalf("init again: exit %d (%s)", code, e.stderr())
	}
	if len(e.tty.shown) != 2 {
		t.Fatalf("the second init showed %d keys in all, want a new one", len(e.tty.shown))
	}

	// With --recovery-out the key is in the file first: a cancelled
	// --show-recovery screen does not stop init.
	e = newEnv(t)
	e.vaults.initialized = false
	fakePluginDir(t, e, "age-plugin-se")
	e.execOut["keygen"] = []byte("# public key: age1se1q\nAGE-PLUGIN-SE-1Q\n")
	e.tty.screens = []error{ui.ErrCancelled}
	e.tty.yesno = []bool{false, false} // not again; no service
	out := filepath.Join(e.h.Dir, "recovery.txt")
	if code := e.run("init", "--recovery-out", out, "--show-recovery"); code != exitOK || !e.vaults.initialized {
		t.Fatalf("--recovery-out: exit %d (%s)", code, e.stderr())
	}
	if b, err := os.ReadFile(out); err != nil || string(b) != "TEST-RECOVERY-PLACEHOLDER\n" {
		t.Fatalf("recovery file %q %v", b, err)
	}
}

func TestInitAlreadyDone(t *testing.T) {
	e := newEnv(t)
	if code := e.run("init"); code != exitError {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(e.stderr(), "already set up") {
		t.Fatalf("stderr %q", e.stderr())
	}
}

// fakePluginDir puts an executable placeholder named name on the fake
// HOME's PATH (it is never run: exec is a fake).
func fakePluginDir(t *testing.T, e *env, name string) string {
	t.Helper()
	dir := mkdir(t, filepath.Join(e.h.Dir, "plugins"))
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	e.h.Env = e.h.Env.With("PATH", dir+":"+e.h.Env.Get("PATH"))
	return dir
}

func TestFactorListAddRemoveTest(t *testing.T) {
	e := newEnv(t)
	if code := e.run("factor", "list"); code != exitOK || !strings.Contains(e.stdout(), "se ") {
		t.Fatalf("list: exit %d %q", code, e.stdout())
	}
	e = newEnv(t)
	if code := e.run("factor", "add", "passphrase"); code != exitOK {
		t.Fatalf("add: exit %d (%s)", code, e.stderr())
	}
	if len(e.daemon.factors) != 1 || e.daemon.factors[0].Kind != "passphrase" || e.dials[0].Autostart {
		t.Fatalf("factor_add %+v dials %+v", e.daemon.factors, e.dials)
	}
	e = newEnv(t)
	e.dialErr = ipc.ErrNoDaemon
	if code := e.run("factor", "add", "passphrase"); code != exitLocked || !strings.Contains(e.stderr(), "unlock every folder first") {
		t.Fatalf("no daemon: exit %d %q", code, e.stderr())
	}
	e = newEnv(t)
	e.tty.yesno = []bool{true}
	if code := e.run("factor", "remove", "se"); code != exitOK || len(e.vaults.removed) != 2 {
		t.Fatalf("remove: exit %d removed %v", code, e.vaults.removed)
	}
	e = newEnv(t)
	e.vaults.removeErr = vault.ErrLastFactor
	e.tty.yesno = []bool{true}
	if code := e.run("factor", "remove", "se"); code != exitError {
		t.Fatalf("last factor: exit %d", code)
	}
	e = newEnv(t)
	if code := e.run("factor", "remove", "recovery"); code == exitOK {
		t.Fatal("recovery removed")
	}
	// factor test is a test unlock (CC-50): unwrap and verify, no grant.
	e = newEnv(t)
	if code := e.run("factor", "test", "se"); code != exitOK {
		t.Fatalf("test: exit %d (%s)", code, e.stderr())
	}
	if r := e.daemon.unlocks[0]; !r.Global || r.Factor != "se" || !r.Test || !r.TTY {
		t.Fatalf("unlock %+v, want a test unlock of the global vault", r)
	}
	if len(e.daemon.locks) != 0 {
		t.Fatal("a test unlock that granted nothing was followed by a lock")
	}
	// A daemon that answered with a grant anyway: locked again (it was
	// locked before), never left open.
	e = newEnv(t)
	e.daemon.unlockRes = ipc.UnlockResp{Unlocked: []string{vault.GlobalID}}
	if code := e.run("factor", "test", "se"); code != exitOK {
		t.Fatalf("test: exit %d (%s)", code, e.stderr())
	}
	if len(e.daemon.locks) != 1 || e.daemon.locks[0].RootIDs[0] != vault.GlobalID {
		t.Fatalf("locks %+v", e.daemon.locks)
	}
	// A wrong passphrase: C2.badsecret, exit 3.
	e = newEnv(t)
	e.daemon.unlockErr = &ipc.Error{Code: ipc.CodeBadSecret}
	if code := e.run("factor", "test", "passphrase"); code != exitLocked || !strings.Contains(e.stderr(), "not right") {
		t.Fatalf("bad secret: exit %d %q", code, e.stderr())
	}
}

// vault repair: phase 1 reports what a repair would rewrite, the user
// types "repair" (C14.confirm), phase 2 applies it (D53).
func TestVaultRepairTwoPhases(t *testing.T) {
	e := newEnv(t)
	e.daemon.repairRes = []ipc.VaultRepairResp{{RecipientChanged: true}, {RecipientChanged: true, Exposed: []string{"claude-code/u/g000002.pcap"}}}
	e.tty.lines = []string{wordRepair}
	if code := e.run("vault", "repair", "--root", e.h.Root); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if n := len(e.daemon.repairs); n != 2 || e.daemon.repairs[0].Confirmed || !e.daemon.repairs[1].Confirmed || e.daemon.repairs[0].VaultID != "root-acme" {
		t.Fatalf("repairs %+v", e.daemon.repairs)
	}
	// CC-32: the dry run and the confirmed call share one connection, so
	// the daemon unwraps (one presence prompt) only for the dry run.
	if len(e.dials) != 1 || e.daemon.closed != 1 {
		t.Fatalf("dials %d closes %d, want both calls on one connection", len(e.dials), e.daemon.closed)
	}
	if !strings.Contains(e.tty.allPrompts(), ui.Format(ui.MsgVaultRepairConfirm, ui.Vars{Folder: "~/work/acme"})) {
		t.Fatalf("prompts %q", e.tty.allPrompts())
	}
	if !strings.Contains(e.stderr(), ui.Format(ui.MsgVaultRepaired, ui.Vars{Folder: "~/work/acme", N: 1})) {
		t.Fatalf("stderr %q", e.stderr())
	}

	e = newEnv(t)
	e.daemon.repairRes = []ipc.VaultRepairResp{{RecipientChanged: true}}
	e.tty.lines = []string{"no"}
	if code := e.run("vault", "repair", "--global"); code != exitLocked || len(e.daemon.repairs) != 1 {
		t.Fatalf("declined: exit %d repairs %+v", code, e.daemon.repairs)
	}

	e = newEnv(t)
	msg := ui.Format(ui.MsgVaultNotGenuine, ui.Vars{Folder: "~/work/acme"})
	e.daemon.repairErr = &ipc.Error{Code: ipc.CodeVerify, Msg: msg}
	if code := e.run("vault", "repair", "--root", e.h.Root); code != exitVerify || !strings.Contains(e.stderr(), msg) {
		t.Fatalf("not genuine: exit %d %q", code, e.stderr())
	}
}

// vault repair --recovery: the key is typed once and travels with both
// calls of the one connection (the daemon needs it to rewrite the recovery
// recipient at the confirmed call).
func TestVaultRepairRecoveryKeyOnce(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	e.tty.secrets = []string{id.String()}
	e.tty.lines = []string{wordRepair}
	e.daemon.repairRes = []ipc.VaultRepairResp{{RecoveryChanged: true}, {RecoveryChanged: true}}
	if code := e.run("vault", "repair", "--root", e.h.Root, "--recovery"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if len(e.daemon.repairs) != 2 || !e.daemon.repairs[0].UseRecovery || !e.daemon.repairs[1].UseRecovery || len(e.dials) != 1 {
		t.Fatalf("repairs %+v dials %d", e.daemon.repairs, len(e.dials))
	}
	if n := strings.Count(e.tty.allPrompts(), ui.Format(ui.MsgRecoveryPrompt, ui.Vars{})); n != 1 {
		t.Fatalf("recovery key asked %d times", n)
	}
}

func TestVaultRepairUsage(t *testing.T) {
	for _, args := range [][]string{{"vault"}, {"vault", "repair"}, {"vault", "repair", "--global", "--root", "x"}, {"vault", "fix", "--global"}} {
		e := newEnv(t)
		if code := e.run(args...); code != exitUsage {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

// A cancelled type-back offers the recovery key again (it exists only now).
func TestInitRecoveryShownAgainAfterCancel(t *testing.T) {
	e := newEnv(t)
	e.vaults.initialized = false
	fakePluginDir(t, e, "age-plugin-se")
	e.execOut["keygen"] = []byte("# public key: age1se1q\nAGE-PLUGIN-SE-1Q\n")
	tty := &cancelOnceTTY{fakeTTY: e.tty}
	e.tty.yesno = []bool{true, false} // show again; no service
	a := e.app()
	a.sys.openTTY = func() (terminal, error) { return tty, nil }
	if code := a.run([]string{"init"}); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if tty.calls != 2 {
		t.Fatalf("secret screen shown %d times, want 2", tty.calls)
	}
}

type cancelOnceTTY struct {
	*fakeTTY
	calls int
}

func (c *cancelOnceTTY) ShowSecretScreen(h []string, s *memguard.LockedBuffer, n int) error {
	c.calls++
	if c.calls == 1 {
		return ui.ErrCancelled
	}
	return c.fakeTTY.ShowSecretScreen(h, s, n)
}

// pluginStub writes an age plugin identity file the way age-plugin-yubikey
// prints one (comments, then the identity) and returns its path.
func pluginStub(t *testing.T, e *env, body string) string {
	t.Helper()
	p := filepath.Join(e.h.Dir, "identity.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const yubikeyStub = "#       Serial: 1, Slot: 1\n#   PIN policy: Once\n#     Recipient: age1yubikey1qexample\nAGE-PLUGIN-YUBIKEY-1QEXAMPLE\n"

// CC-09: plugin factors take --identity-stub FILE and --presence POLICY or
// --no-presence-ack, in init and in factor add.
func TestPluginFactorFlags(t *testing.T) {
	e := newEnv(t)
	e.vaults.initialized = false
	fakePluginDir(t, e, "age-plugin-yubikey")
	stub := pluginStub(t, e, yubikeyStub)
	e.tty.secrets = []string{"a long enough passphrase 4 tests", "a long enough passphrase 4 tests"}
	e.tty.yesno = []bool{false} // no background service
	code := e.run("init", "--factor", "passphrase", "--factor", "plugin:age1yubikey1qexample",
		"--identity-stub", stub, "--presence", "touch-always", "--recovery-out", filepath.Join(e.h.Dir, "rec.txt"))
	if code != exitOK {
		t.Fatalf("init: exit %d (%s)", code, e.stderr())
	}
	var plugin *vault.FactorSpec
	for i, f := range e.vaults.initOpts[0].Factors {
		if f.Kind == vault.FactorPlugin {
			plugin = &e.vaults.initOpts[0].Factors[i]
		}
	}
	if plugin == nil || plugin.IdentityStub != "AGE-PLUGIN-YUBIKEY-1QEXAMPLE" || plugin.PresencePolicy != "touch-always" ||
		plugin.NoPresenceAck || plugin.Recipient != "age1yubikey1qexample" || !strings.HasSuffix(plugin.PluginPath, "age-plugin-yubikey") {
		t.Fatalf("plugin spec %+v", plugin)
	}

	e = newEnv(t)
	fakePluginDir(t, e, "age-plugin-yubikey")
	stub = pluginStub(t, e, yubikeyStub)
	if code := e.run("factor", "add", "plugin:age1yubikey1qexample", "--identity-stub", stub, "--no-presence-ack"); code != exitOK {
		t.Fatalf("factor add: exit %d (%s)", code, e.stderr())
	}
	if r := e.daemon.factors[0]; r.Kind != "plugin" || r.IdentityStub != "AGE-PLUGIN-YUBIKEY-1QEXAMPLE" || !r.NoPresenceAck || r.PresencePolicy != "" {
		t.Fatalf("factor_add %+v", r)
	}

	// Refusals, before anything is read or asked.
	for name, args := range map[string][]string{
		"no presence":         {"factor", "add", "plugin:age1yubikey1qexample", "--identity-stub", "x"},
		"both":                {"factor", "add", "plugin:age1yubikey1qexample", "--identity-stub", "x", "--presence", "pin-once", "--no-presence-ack"},
		"unknown policy":      {"factor", "add", "plugin:age1yubikey1qexample", "--identity-stub", "x", "--presence", "always"},
		"no stub":             {"factor", "add", "plugin:age1yubikey1qexample", "--presence", "pin-once"},
		"not a plugin":        {"factor", "add", "passphrase", "--presence", "pin-once"},
		"other subcommand":    {"factor", "list", "--no-presence-ack"},
		"init without plugin": {"init", "--factor", "passphrase", "--presence", "pin-once"},
		"two plugins":         {"init", "--factor", "plugin:age1yubikey1qa", "--factor", "plugin:age1yubikey1qb", "--identity-stub", "x", "--no-presence-ack"},
	} {
		e := newEnv(t)
		if code := e.run(args...); code != exitUsage {
			t.Errorf("%s: exit %d (%s), want 2", name, code, e.stderr())
		}
		if len(e.daemon.factors) != 0 || e.hardened != 0 {
			t.Errorf("%s: acted before refusing", name)
		}
	}

	// A stub file that holds a secret key, or another plugin's identity, is
	// refused and nothing is enrolled.
	for name, body := range map[string]string{
		"secret key":   "AGE-SECRET-KEY-1QEXAMPLEQEXAMPLE\n",
		"other plugin": "AGE-PLUGIN-SE-1QEXAMPLE\n",
		"two":          "AGE-PLUGIN-YUBIKEY-1QA\nAGE-PLUGIN-YUBIKEY-1QB\n",
	} {
		e := newEnv(t)
		fakePluginDir(t, e, "age-plugin-yubikey")
		stub := pluginStub(t, e, body)
		if code := e.run("factor", "add", "plugin:age1yubikey1qexample", "--identity-stub", stub, "--presence", "pin-once"); code != exitUsage {
			t.Errorf("%s: exit %d (%s), want 2", name, code, e.stderr())
		}
		if len(e.daemon.factors) != 0 {
			t.Errorf("%s: enrolled", name)
		}
		if strings.Contains(e.stderr(), "QEXAMPLE") || strings.Contains(e.stderr(), "1QA") {
			t.Errorf("%s: the file's content was printed: %q", name, e.stderr())
		}
	}
}

// D75: factor repin shows the pinned path, both hashes, owner and mtime,
// asks for the typed word repin and re-pins through the store; refused in
// agent contexts and without a terminal or the word.
func TestFactorRepin(t *testing.T) {
	setup := func(t *testing.T) (*env, string, string) {
		e := newEnv(t)
		bin := filepath.Join(e.h.Dir, "age-plugin-se")
		if err := os.WriteFile(bin, []byte("new plugin build\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte("new plugin build\n"))
		newSHA := hex.EncodeToString(sum[:])
		m := e.vaults.metas[vault.GlobalID]
		m.Factors[0].PluginPath, m.Factors[0].PluginSHA256 = bin, strings.Repeat("a", 64)
		e.vaults.metas[vault.GlobalID] = m
		e.vaults.repinOld, e.vaults.repinNew = strings.Repeat("a", 64), newSHA
		return e, bin, newSHA
	}
	e, _, newSHA := setup(t)
	e.tty.lines = []string{wordRepin}
	if code := e.run("factor", "repin", "se"); code != exitOK {
		t.Fatalf("repin: exit %d (%s)", code, e.stderr())
	}
	if len(e.vaults.repinned) != 1 || e.vaults.repinned[0] != "se" {
		t.Fatalf("repinned %v", e.vaults.repinned)
	}
	out := e.stderr()
	for _, want := range []string{strings.Repeat("a", 64), newSHA, "(uid ", "modified", "age-plugin-se"} {
		if !strings.Contains(out, want) {
			t.Errorf("repin output lacks %q: %q", want, out)
		}
	}
	if !strings.Contains(e.tty.allPrompts(), `Type "repin" to confirm`) {
		t.Errorf("prompts %q", e.tty.allPrompts())
	}

	// Without the typed word nothing is re-pinned.
	e, _, _ = setup(t)
	e.tty.lines = []string{"yes"}
	if code := e.run("factor", "repin", "se"); code != exitLocked || len(e.vaults.repinned) != 0 {
		t.Fatalf("no typed word: exit %d repinned %v", code, e.vaults.repinned)
	}
	// Agent context and no terminal: refused before anything is shown.
	e, _, _ = setup(t)
	e.agentCtx = true
	if code := e.run("factor", "repin", "se"); code != exitLocked || len(e.vaults.repinned) != 0 || strings.Contains(e.stderr(), "SHA-256") {
		t.Fatalf("agent context: exit %d (%s)", code, e.stderr())
	}
	e, _, _ = setup(t)
	e.tty = nil
	if code := e.run("factor", "repin", "se"); code != exitLocked || len(e.vaults.repinned) != 0 {
		t.Fatalf("no terminal: exit %d", code)
	}
	// A binary that changed again after the display: exit 5, warned.
	e, _, _ = setup(t)
	e.tty.lines = []string{wordRepin}
	e.vaults.repinNew = strings.Repeat("b", 64)
	if code := e.run("factor", "repin", "se"); code != exitVerify || !strings.Contains(e.stderr(), "changed again") {
		t.Fatalf("changed again: exit %d (%s)", code, e.stderr())
	}
	// Already pinned to this binary: nothing to do.
	e, _, newSHA = setup(t)
	m := e.vaults.metas[vault.GlobalID]
	m.Factors[0].PluginSHA256 = newSHA
	e.vaults.metas[vault.GlobalID] = m
	if code := e.run("factor", "repin", "se"); code != exitOK || len(e.vaults.repinned) != 0 {
		t.Fatalf("unchanged: exit %d repinned %v", code, e.vaults.repinned)
	}
	// A repin that failed half way: the global vault pins the new binary,
	// root-acme the old one. Repin runs again (for root-acme).
	e, bin, newSHA := setup(t)
	m = e.vaults.metas[vault.GlobalID]
	m.Factors[0].PluginSHA256 = newSHA
	e.vaults.metas[vault.GlobalID] = m
	r := e.vaults.metas["root-acme"]
	r.Factors = []vault.Factor{{Name: "se", Kind: vault.FactorSE, PluginPath: bin, PluginSHA256: strings.Repeat("a", 64)}}
	e.vaults.metas["root-acme"] = r
	e.tty.lines = []string{wordRepin}
	if code := e.run("factor", "repin", "se"); code != exitOK || len(e.vaults.repinned) != 1 {
		t.Fatalf("half-done repin: exit %d repinned %v (%s)", code, e.vaults.repinned, e.stderr())
	}
	// Not a plugin factor.
	e, _, _ = setup(t)
	if code := e.run("factor", "repin", "recovery"); code != exitUsage {
		t.Fatalf("recovery: exit %d", code)
	}
}

// UX-07: an Init that fails after the key was confirmed says the key of
// this run is not used, and leaves no recovery file behind.
func TestInitFailureAfterTheKeyWasConfirmed(t *testing.T) {
	e := newEnv(t)
	e.vaults.initialized = false
	fakePluginDir(t, e, "age-plugin-se")
	e.execOut["keygen"] = []byte("# public key: age1se1q\nAGE-PLUGIN-SE-1Q\n")
	a := e.app()
	inner := a.sys.vaults
	a.sys.vaults = func(l paths.Layout) vaultStore { return failAfterConfirm{inner(l)} }
	out := filepath.Join(e.h.Dir, "recovery.txt")
	if code := a.run([]string{"init", "--recovery-out", out}); code != exitError {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if !strings.Contains(e.stderr(), textInitKeyUnused) {
		t.Fatalf("stderr %q", e.stderr())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("recovery file of a failed init left behind")
	}
}

// failAfterConfirm is a store whose Init fails after Confirm accepted the
// key (a factor that could not be wrapped).
type failAfterConfirm struct{ vaultStore }

func (f failAfterConfirm) Init(ctx context.Context, o vault.InitOptions) (*memguard.LockedBuffer, error) {
	rec := memguard.NewBufferFromBytes([]byte("TEST-RECOVERY-PLACEHOLDER"))
	defer rec.Destroy()
	if err := o.Confirm(rec); err != nil {
		return nil, err
	}
	return nil, errors.New("wrapping a factor failed")
}
