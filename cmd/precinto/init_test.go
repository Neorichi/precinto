package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/ipc"
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
	e = newEnv(t)
	if code := e.run("factor", "test", "se"); code != exitOK {
		t.Fatalf("test: exit %d (%s)", code, e.stderr())
	}
	if r := e.daemon.unlocks[0]; !r.Global || r.Factor != "se" || r.TTL <= 0 {
		t.Fatalf("unlock %+v", r)
	}
	if len(e.daemon.locks) != 1 {
		t.Fatal("test left the global vault unlocked")
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
