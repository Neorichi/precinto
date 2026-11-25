package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/sweep"
	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/internal/ui"
	"github.com/Neorichi/precinto/internal/vault"
)

func mkdir(t *testing.T, p string) string {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// protect lists the folder in config.toml and roots.list (the shim reads
// it, D22) before asking the daemon to create its vault.
func TestProtectNewFolder(t *testing.T) {
	e := newEnv(t)
	fakePluginDir(t, e, "codex") // Codex is installed: C10.consent is asked
	dir := mkdir(t, filepath.Join(e.h.HomeDir, "work", "beta"))
	e.cwd = e.h.HomeDir
	e.vaults.metas["x"] = e.vaults.metas["root-acme"]
	if code := e.run("protect", "work/beta", "--md", "all", "--on-enter", "notify"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	c := e.loadConfig()
	if len(c.Roots) != 2 {
		t.Fatalf("roots %+v", c.Roots)
	}
	r := c.Roots[1]
	if r.Path != dir || r.MD != config.MDAll || r.OnEnter != config.OnEnterNotify || len(r.ID) != 32 || r.ProtectedAt.IsZero() {
		t.Fatalf("root %+v", r)
	}
	if !slices.Equal(r.Harnesses, []string{"claude-code", "codex"}) {
		t.Fatalf("harnesses %v", r.Harnesses)
	}
	list, err := config.ReadRootsList(e.h.Layout.RootsList)
	if err != nil || !slices.Contains(list, dir) {
		t.Fatalf("roots.list %v err %v", list, err)
	}
	if len(e.daemon.creates) != 1 || e.daemon.creates[0] != (ipc.VaultCreateReq{RootID: r.ID, RootPath: dir}) {
		t.Fatalf("vault_create %+v", e.daemon.creates)
	}
	if !e.dials[0].Autostart {
		t.Fatal("protect must autostart the daemon (SPEC §13.1)")
	}
	if !e.eng.called("Sweep") || e.eng.sweepOpts[0].Scope.RootIDs[0] != r.ID {
		t.Fatalf("no sweep scoped to the folder: %+v", e.eng.sweepOpts)
	}
	// The Claude home of this environment is registered (SPEC §7.0).
	homes := c.Harness["claude-code"].Homes
	found := false
	for _, h := range homes {
		found = found || h.Dir == e.h.ClaudeConfig
	}
	if !found {
		t.Fatalf("claude home not registered: %+v", homes)
	}
	if !strings.Contains(e.tty.allPrompts(), "Protect Codex in ~/work/beta?") {
		t.Fatalf("no Codex consent asked (C10.consent): %q", e.tty.allPrompts())
	}
}

// Declining C10.consent keeps Codex unmanaged in the folder.
func TestProtectCodexDeclined(t *testing.T) {
	e := newEnv(t)
	fakePluginDir(t, e, "codex")
	mkdir(t, filepath.Join(e.h.HomeDir, "beta"))
	e.tty.yesno = []bool{false}
	if code := e.run("protect", filepath.Join(e.h.HomeDir, "beta")); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if r := e.loadConfig().Roots[1]; !slices.Equal(r.Harnesses, []string{"claude-code"}) {
		t.Fatalf("harnesses %v", r.Harnesses)
	}
}

// D72: Codex consent is recorded in the folder's harness list. Without
// Codex installed, or without a terminal to answer, protect does not ask
// and the folder does not list codex (precinto run codex asks later);
// --harness naming codex is the consent itself.
func TestProtectCodexConsentRecorded(t *testing.T) {
	cases := []struct {
		name      string
		installed bool
		tty       bool
		args      []string
		asked     bool
		want      []string
	}{
		{"not installed", false, true, nil, false, []string{"claude-code"}},
		{"no terminal", true, false, nil, false, []string{"claude-code"}},
		{"explicit", false, true, []string{"--harness", "claude-code,codex"}, false, []string{"claude-code", "codex"}},
		{"installed, yes", true, true, nil, true, []string{"claude-code", "codex"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			if c.installed {
				fakePluginDir(t, e, "codex")
			}
			if !c.tty {
				e.tty, e.interactive = nil, false
			} else {
				e.tty.yesno = []bool{true}
			}
			dir := mkdir(t, filepath.Join(e.h.HomeDir, "beta"))
			if code := e.run(append([]string{"protect", dir}, c.args...)...); code != exitOK {
				t.Fatalf("exit %d (%s)", code, e.stderr())
			}
			if r := e.loadConfig().Roots[1]; !slices.Equal(r.Harnesses, c.want) {
				t.Fatalf("harnesses %v, want %v", r.Harnesses, c.want)
			}
			if asked := e.tty != nil && strings.Contains(e.tty.allPrompts(), "Protect Codex in"); asked != c.asked {
				t.Fatalf("C10.consent asked=%v, want %v", asked, c.asked)
			}
		})
	}
}

// D72: a yes to run's C10.consent adds codex to the folder (the wrapper
// runs Prepare only after it); the plan's own Prepare still runs.
func TestRunCodexConsentAddsCodex(t *testing.T) {
	e := newEnv(t)
	c := e.loadConfig()
	c.Roots[0].Harnesses = []string{"claude-code"}
	e.saveConfig(c)
	prepared := false
	e.eng.plan = harness.LaunchPlan{
		Mode: harness.LaunchInteractive, Roots: []config.Root{c.Roots[0]}, Confirm: string(ui.MsgCodexConsent),
		Prepare: func(context.Context) error { prepared = true; return nil },
	}
	b := newBackend(e.app(), e.eng)
	plan, err := b.Plan(context.Background(), harness.Codex, e.h.Root, []string{"codex"})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.loadConfig().Roots[0].Harnesses; slices.Contains(got, "codex") {
		t.Fatalf("codex added before the answer: %v", got)
	}
	if err := plan.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := e.loadConfig().Roots[0].Harnesses; !slices.Equal(got, []string{"claude-code", "codex"}) || !prepared {
		t.Fatalf("after yes: harnesses %v, prepared %v", got, prepared)
	}
	// Any other plan is left as it is.
	e.eng.plan = harness.LaunchPlan{Mode: harness.LaunchInteractive, Roots: []config.Root{c.Roots[0]}}
	plan, err = b.Plan(context.Background(), harness.ClaudeCode, e.h.Root, []string{"claude"})
	if err != nil || plan.Prepare != nil {
		t.Fatalf("plan without consent got a Prepare: %v", err)
	}
}

func TestProtectRefusals(t *testing.T) {
	// Overlap without a terminal is refused; nothing is written.
	e := newEnv(t)
	sub := mkdir(t, filepath.Join(e.h.Root, "sub"))
	e.tty, e.interactive = nil, false
	if code := e.run("protect", sub); code != exitError {
		t.Fatalf("overlap: exit %d", code)
	}
	if len(e.loadConfig().Roots) != 1 || len(e.daemon.creates) != 0 {
		t.Fatal("overlap: protected anyway")
	}
	// Overlap on a terminal: the default answer is no.
	e = newEnv(t)
	mkdir(t, filepath.Join(e.h.Root, "sub"))
	e.tty.yesno = []bool{false}
	if code := e.run("protect", filepath.Join(e.h.Root, "sub")); code != exitLocked {
		t.Fatalf("overlap declined: exit %d", code)
	}
	// precinto's own data folder is never inside a folder.
	e = newEnv(t)
	if code := e.run("protect", e.h.Dir); code != exitError {
		t.Fatalf("own data: exit %d", code)
	}
	// Not set up yet.
	e = newEnv(t)
	e.vaults.initialized = false
	if code := e.run("protect", mkdir(t, filepath.Join(e.h.HomeDir, "c"))); code != exitError {
		t.Fatalf("no init: exit %d", code)
	}
	if !strings.Contains(e.stderr(), "precinto init") {
		t.Fatalf("stderr %q", e.stderr())
	}
	// Bad enum.
	e = newEnv(t)
	if code := e.run("protect", e.h.HomeDir, "--md", "some"); code != exitUsage {
		t.Fatalf("enum: exit %d", code)
	}
}

// Protecting an already protected folder whose vault exists is a no-op;
// one whose vault is missing (an earlier vault_create failed) gets it now.
func TestProtectIdempotentAndRetry(t *testing.T) {
	e := newEnv(t)
	if code := e.run("protect", e.h.Root); code != exitOK || len(e.daemon.creates) != 0 {
		t.Fatalf("exit %d creates %v", code, e.daemon.creates)
	}
	if !strings.Contains(e.stderr(), "already protected") {
		t.Fatalf("stderr %q", e.stderr())
	}
	e = newEnv(t)
	delete(e.vaults.metas, "root-acme")
	if code := e.run("protect", e.h.Root); code != exitOK || len(e.daemon.creates) != 1 || e.daemon.creates[0].RootID != "root-acme" {
		t.Fatalf("exit %d creates %v", code, e.daemon.creates)
	}
}

// A failed vault_create keeps the folder protected (fail closed) and says
// how to retry.
func TestProtectVaultCreateFails(t *testing.T) {
	e := newEnv(t)
	dir := mkdir(t, filepath.Join(e.h.HomeDir, "beta"))
	e.daemon.createErr = &ipc.Error{Code: ipc.CodeInternal, Msg: "precinto: could not create the vault"}
	if code := e.run("protect", dir); code != exitError {
		t.Fatalf("exit %d", code)
	}
	if len(e.loadConfig().Roots) != 2 {
		t.Fatal("folder dropped after a failed vault_create")
	}
	if !strings.Contains(e.stderr(), "Run precinto protect ~/beta again") {
		t.Fatalf("stderr %q", e.stderr())
	}
}

// --claude-settings merges precinto's keys into .claude/settings.local.json
// and keeps every other key; .git/info/exclude gets *.md.precinto with
// consent.
func TestProtectClaudeSettingsAndGitExclude(t *testing.T) {
	e := newEnv(t)
	dir := mkdir(t, filepath.Join(e.h.HomeDir, "repo"))
	mkdir(t, filepath.Join(dir, ".git", "info"))
	mkdir(t, filepath.Join(dir, ".claude"))
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.local.json"), []byte(`{"model":"x","idleCompaction":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "info", "exclude"), []byte("# git ls-files --others --exclude-from=.git/info/exclude"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakePluginDir(t, e, "codex")
	e.tty.yesno = []bool{true, true} // Codex consent, git exclude
	if code := e.run("protect", dir, "--claude-settings"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	var got map[string]any
	b, _ := os.ReadFile(filepath.Join(dir, ".claude", "settings.local.json"))
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["model"] != "x" || got["idleCompaction"] != false || got["awaySummaryEnabled"] != false {
		t.Fatalf("settings %v", got)
	}
	ex, _ := os.ReadFile(filepath.Join(dir, ".git", "info", "exclude"))
	if !strings.HasSuffix(string(ex), "\n*.md.precinto\n") {
		t.Fatalf("exclude %q", ex)
	}
	if !e.loadConfig().Roots[1].ClaudeSettings {
		t.Fatal("claude_settings not recorded")
	}
	// A second protect does not add the line twice.
	e.vaults.metas[e.loadConfig().Roots[1].ID] = e.vaults.metas["root-acme"]
	e.run("protect", dir)
	ex, _ = os.ReadFile(filepath.Join(dir, ".git", "info", "exclude"))
	if strings.Count(string(ex), "*.md.precinto") != 1 {
		t.Fatalf("exclude %q", ex)
	}
}

// Without a terminal nothing is written into the repository.
func TestProtectNoGitExcludeWithoutConsent(t *testing.T) {
	e := newEnv(t)
	dir := mkdir(t, filepath.Join(e.h.HomeDir, "repo"))
	mkdir(t, filepath.Join(dir, ".git"))
	e.tty, e.interactive = nil, false
	if code := e.run("protect", dir); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if _, err := os.Stat(filepath.Join(dir, ".git", "info", "exclude")); !os.IsNotExist(err) {
		t.Fatal("exclude written without consent")
	}
}

// unprotect restores everything first (purpose restore-all), then drops
// the folder; pending policy changes are confirmed only on a yes. The
// vault and the capsules are kept (never delete).
func TestUnprotectFlow(t *testing.T) {
	e := newEnv(t)
	e.eng.units = []sweep.UnitInfo{{Unit: "u", RootIDs: []string{"root-acme"}}}
	e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}}
	e.daemon.pending = []string{"roots[root-acme] removed"}
	e.tty.lines = []string{wordUnprotect}
	e.tty.yesno = []bool{true}
	if code := e.run("unprotect", e.h.Root); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if !e.eng.called("Restore") || !e.eng.called("RestoreMarkdown") || !e.eng.called("MergeHistory") {
		t.Fatalf("calls %v", e.eng.calls)
	}
	if e.eng.restores[0].Purpose != ipc.PurposeRestoreAll {
		t.Fatalf("purpose %q", e.eng.restores[0].Purpose)
	}
	if len(e.loadConfig().Roots) != 0 {
		t.Fatal("folder still protected")
	}
	if n := len(e.daemon.policies); n != 2 || !e.daemon.policies[1].Confirm {
		t.Fatalf("policy calls %+v", e.daemon.policies)
	}
	// UX-14: the review happens now, in this terminal: C13.review, never
	// C13.policy's "at your next unlock".
	if !strings.Contains(e.stderr(), ui.Format(ui.MsgPolicyReview, ui.Vars{N: 1})) || strings.Contains(e.stderr(), ui.Format(ui.MsgPolicyPending, ui.Vars{N: 1})) {
		t.Fatalf("stderr %q", e.stderr())
	}
}

// A failed restore keeps the folder protected.
func TestUnprotectKeepsProtectionOnFailure(t *testing.T) {
	e := newEnv(t)
	e.eng.units = []sweep.UnitInfo{{Unit: "u", RootIDs: []string{"root-acme"}}}
	e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}}
	e.eng.restoreErr = sweep.ErrKeyDenied
	e.tty.lines = []string{wordUnprotect}
	if code := e.run("unprotect", e.h.Root); code != exitLocked {
		t.Fatalf("exit %d", code)
	}
	if len(e.loadConfig().Roots) != 1 {
		t.Fatal("protection dropped after a failed restore")
	}
}

func TestUnprotectNotAFolder(t *testing.T) {
	e := newEnv(t)
	if code := e.run("unprotect", e.h.HomeDir); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
}

// A folder inside a harness home or precinto's data is never protected.
func TestProtectRefusesHarnessAndOwnData(t *testing.T) {
	for _, dir := range []func(e *env) string{
		func(e *env) string { return mkdir(t, filepath.Join(e.h.ClaudeConfig, "projects")) },
		func(e *env) string { return mkdir(t, filepath.Join(e.h.Base, "capsules")) },
	} {
		e := newEnv(t)
		d := dir(e)
		if code := e.run("protect", d); code != exitError {
			t.Fatalf("%s: exit %d", d, code)
		}
		if len(e.loadConfig().Roots) != 1 {
			t.Fatalf("%s protected", d)
		}
	}
}

// CC-43: --root takes a path only (the daemon's workers get the folder's
// absolute path): a folder id with no such directory is a usage error.
func TestRootArgIsAPath(t *testing.T) {
	for _, args := range [][]string{
		{"sweep", "--root", "root-acme", "--quiet"},
		{"seal", "--root", "root-acme"},
		{"restore", "--root", "root-acme"},
		{"lock", "--root", "root-acme"},
		{"unlock", "--root", "root-acme"},
		{"ls", "--root", "root-acme"},
	} {
		e := newEnv(t)
		e.cwd = e.h.HomeDir
		if code := e.run(args...); code != exitUsage {
			t.Errorf("%v from outside the folder: exit %d (%s), want 2", args, code, e.stderr())
		}
		if len(e.eng.sweepOpts)+len(e.eng.sealOpts)+len(e.eng.restores)+len(e.daemon.locks)+len(e.daemon.unlocks)+len(e.eng.listOpts) != 0 {
			t.Errorf("%v acted on a folder id", args)
		}
	}
	// The workers' form: the folder's absolute path, from any directory.
	e := newEnv(t)
	e.cwd = "/"
	if code := e.run("sweep", "--root", e.h.Root, "--quiet"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if ids := e.eng.sweepOpts[0].Scope.RootIDs; len(ids) != 1 || ids[0] != "root-acme" {
		t.Fatalf("scope %v", ids)
	}
}

// D74: protecting a folder whose retired vault still exists (root_path
// equal after realpath) reuses that id: no new vault is created and the
// old capsules serve again; another folder's retired vault is not taken.
func TestProtectReusesRetiredVault(t *testing.T) {
	e := newEnv(t)
	dir := mkdir(t, filepath.Join(e.h.HomeDir, "beta"))
	e.vaults.metas["root-old"] = vault.Meta{ID: "root-old", RootPath: dir, CreatedAt: testkit.Epoch}
	e.vaults.metas["root-older"] = vault.Meta{ID: "root-older", RootPath: dir, CreatedAt: testkit.Epoch.Add(-time.Hour)}
	e.vaults.metas["root-other"] = vault.Meta{ID: "root-other", RootPath: filepath.Join(e.h.HomeDir, "gamma")}
	if code := e.run("protect", dir); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	c := e.loadConfig()
	if len(c.Roots) != 2 || c.Roots[1].ID != "root-old" || c.Roots[1].Path != dir {
		t.Fatalf("roots %+v, want the retired id root-old", c.Roots)
	}
	if len(e.daemon.creates) != 0 {
		t.Fatalf("vault_create %+v for a folder whose vault exists", e.daemon.creates)
	}
	if !strings.Contains(e.stderr(), "was protected before") {
		t.Fatalf("stderr %q", e.stderr())
	}
	// A folder protected for the first time gets a fresh id and a vault.
	e = newEnv(t)
	other := mkdir(t, filepath.Join(e.h.HomeDir, "delta"))
	e.vaults.metas["root-old"] = vault.Meta{ID: "root-old", RootPath: filepath.Join(e.h.HomeDir, "beta")}
	if code := e.run("protect", other); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if c := e.loadConfig(); c.Roots[1].ID == "root-old" || len(e.daemon.creates) != 1 {
		t.Fatalf("roots %+v creates %+v", c.Roots, e.daemon.creates)
	}
}

// DC-42: unprotect removes from .claude/settings.local.json only the keys
// that still hold the value precinto wrote; every other key stays.
func TestUnprotectRemovesOnlyPrecintoSettings(t *testing.T) {
	e := newEnv(t)
	c := e.loadConfig()
	c.Roots[0].ClaudeSettings = true
	e.saveConfig(c)
	settings := filepath.Join(mkdir(t, filepath.Join(e.h.Root, ".claude")), "settings.local.json")
	// idleCompaction as precinto wrote it; awaySummaryEnabled changed by the
	// user since; precomputeCompactionEnabled absent; model is the user's.
	if err := os.WriteFile(settings, []byte(`{"model":"x","idleCompaction":false,"awaySummaryEnabled":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}}
	e.tty.lines = []string{wordUnprotect}
	if code := e.run("unprotect", e.h.Root); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	var got map[string]any
	b, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["model"] != "x" || got["awaySummaryEnabled"] != true {
		t.Fatalf("settings after unprotect %v", got)
	}
	// Without --claude-settings at protect time the file is never touched.
	e = newEnv(t)
	settings = filepath.Join(mkdir(t, filepath.Join(e.h.Root, ".claude")), "settings.local.json")
	if err := os.WriteFile(settings, []byte(`{"idleCompaction":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}}
	e.tty.lines = []string{wordUnprotect}
	if code := e.run("unprotect", e.h.Root); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if b, _ := os.ReadFile(settings); string(b) != `{"idleCompaction":false}` {
		t.Fatalf("settings changed without claude_settings: %q", b)
	}
}

// SPEC §4.6 (D95, SEC-F5): protect hardens before it creates a vault,
// whose passphrase prompt is relayed to its terminal.
func TestProtectHardens(t *testing.T) {
	e := newEnv(t)
	mkdir(t, filepath.Join(e.h.HomeDir, "work", "beta"))
	e.cwd = e.h.HomeDir
	e.vaults.metas["x"] = e.vaults.metas["root-acme"]
	if code := e.run("protect", "work/beta", "--harness", "claude-code"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if len(e.daemon.creates) != 1 || e.hardened != 1 {
		t.Fatalf("vault_create calls %d, harden calls %d", len(e.daemon.creates), e.hardened)
	}
	e2 := newEnv(t)
	mkdir(t, filepath.Join(e2.h.HomeDir, "work", "beta"))
	e2.cwd = e2.h.HomeDir
	e2.hardenErr = errors.New("ptrace attach allowed")
	if code := e2.run("protect", "work/beta", "--harness", "claude-code"); code == exitOK || len(e2.daemon.creates) != 0 {
		t.Fatalf("protect went on after a failed harden: exit %d, %d vault_create", code, len(e2.daemon.creates))
	}
}

// D144 (D6-2): every config.toml edit applies its own change to the file as
// it is on disk under the config lock, never the copy the command loaded
// at its start: a folder another command protected or unprotected while
// integrate ran its plugin commands, or while unprotect restored, stays as
// that command left it, in config.toml and in roots.list.
func TestConfigEditsKeepChangesMadeMeanwhile(t *testing.T) {
	other := func(e *env, edit func(c config.Config) config.Config) {
		e.t.Helper()
		// Another terminal saves its edit (under the config lock).
		if _, err := e.app().editConfig(func(disk config.Config) (config.Config, error) { return edit(disk), nil }); err != nil {
			e.t.Error(err)
		}
	}
	added := func(e *env) config.Root {
		r := config.Root{ID: "root-new", Path: filepath.Join(e.h.HomeDir, "work", "new"), MD: config.MDLedger}
		if err := os.MkdirAll(r.Path, 0o700); err != nil {
			e.t.Fatal(err)
		}
		return r
	}
	check := func(e *env, keep, gone []string) {
		e.t.Helper()
		c := e.loadConfig()
		list, _ := config.ReadRootsList(e.h.Layout.RootsList)
		for _, p := range keep {
			if _, ok := rootByPath(c, p); !ok || !slices.Contains(list, p) {
				e.t.Errorf("%s was dropped (config.toml %v, roots.list %v)", p, c.Roots, list)
			}
		}
		for _, p := range gone {
			if _, ok := rootByPath(c, p); ok || slices.Contains(list, p) {
				e.t.Errorf("%s came back (config.toml %v, roots.list %v)", p, c.Roots, list)
			}
		}
	}

	t.Run("protect during integrate", func(t *testing.T) {
		e := newEnv(t)
		fakePluginDir(t, e, "claude")
		e.execOut["--version"] = []byte("2.1.329 (Claude Code)\n")
		r := added(e)
		exe := filepath.Join(e.h.Dir, "precinto-bin")
		if err := os.WriteFile(exe, []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
		a := e.app()
		a.sys.executable = func() (string, error) { return exe, nil }
		inner := a.sys.exec
		once := false
		a.sys.exec = func(ctx context.Context, c execSpec) ([]byte, error) {
			if len(c.Argv) > 1 && c.Argv[1] == "plugin" && !once {
				once = true
				other(e, func(c config.Config) config.Config { c.Roots = append(c.Roots, r); return c })
			}
			return inner(ctx, c)
		}
		if code := a.run([]string{"integrate", "claude-code"}); code != exitOK {
			t.Fatalf("integrate: exit %d (%s)", code, e.stderr())
		}
		check(e, []string{e.h.Root, r.Path}, nil)
		if e.loadConfig().Harness["claude-code"].Bin == "" {
			t.Error("integrate did not record the harness")
		}
	})

	t.Run("protect during unprotect", func(t *testing.T) {
		e := newEnv(t)
		r := added(e)
		e.eng.units = []sweep.UnitInfo{{Unit: "u", RootIDs: []string{"root-acme"}}}
		e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}}
		e.eng.restoreFn = func(sweep.KeySource, sweep.RestoreRequest) {
			other(e, func(c config.Config) config.Config { c.Roots = append(c.Roots, r); return c })
		}
		e.tty.lines = []string{wordUnprotect}
		if code := e.run("unprotect", e.h.Root); code != exitOK {
			t.Fatalf("unprotect: exit %d (%s)", code, e.stderr())
		}
		check(e, []string{r.Path}, []string{e.h.Root})
	})

	t.Run("two unprotects", func(t *testing.T) {
		e := newEnv(t)
		beta := e.h.Protect(t, "work/beta")
		e.eng.units = []sweep.UnitInfo{{Unit: "u", RootIDs: []string{"root-acme"}}}
		e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}}
		e.eng.restoreFn = func(sweep.KeySource, sweep.RestoreRequest) {
			// The other terminal unprotects beta meanwhile.
			other(e, func(c config.Config) config.Config {
				c.Roots = slices.DeleteFunc(slices.Clone(c.Roots), func(x config.Root) bool { return x.ID == beta.ID })
				return c
			})
		}
		e.tty.lines = []string{wordUnprotect}
		if code := e.run("unprotect", e.h.Root); code != exitOK {
			t.Fatalf("unprotect: exit %d (%s)", code, e.stderr())
		}
		check(e, nil, []string{e.h.Root, beta.Path})
	})
}

// D146 (U6-1): unprotect reviews the folder's removal and confirms it over
// one connection to the agent. The agent signs the confirmed settings with
// the key of a vault of those settings (D145): when no folder stays
// protected that is the global vault, which unprotect asks to unlock
// (C13.signer) over the same connection, a terminal unlock, before it
// confirms; a folder that stays protected and is open signs without a
// question. A declined question confirms nothing: unprotect then says the
// folder stays protected until a terminal unlock confirms the change, and
// exits 3, never "is no longer protected" (U6-1).
func TestUnprotectConfirmsTheRemoval(t *testing.T) {
	signer := ui.Format(ui.MsgPolicySigner, ui.Vars{Folder: "the global vault"})
	for _, tc := range []struct {
		name      string
		beta      bool // another folder stays protected and is open
		yes       []bool
		confirmed bool
	}{
		{"the global vault signs", false, []bool{true, true}, true},
		{"an open folder that stays signs", true, []bool{true}, true},
		{"the signer question declined", false, []bool{true, false}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			open := []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}
			if tc.beta {
				beta := e.h.Protect(t, "work/beta")
				open = append(open, ipc.VaultStatus{VaultID: beta.ID, State: "unlocked"})
			}
			e.eng.units = []sweep.UnitInfo{{Unit: "u", RootIDs: []string{"root-acme"}}}
			e.daemon.status = ipc.StatusResp{Vaults: open}
			e.daemon.pending = []string{"roots[root-acme]: " + e.h.Root + " → "}
			e.tty.lines = []string{wordUnprotect}
			e.tty.yesno = tc.yes
			want := exitOK
			if !tc.confirmed {
				want = exitLocked
			}
			if code := e.run("unprotect", e.h.Root); code != want {
				t.Fatalf("exit %d, want %d (%s)", code, want, e.stderr())
			}
			out := e.stderr()
			// The review names the folder, never its id.
			if !strings.Contains(out, "~/work/acme: no longer protected") || strings.Contains(out, "roots[root-acme]") {
				t.Errorf("review %q", out)
			}
			asked := slices.Contains(e.tty.prompts, signer)
			if asked == tc.beta {
				t.Errorf("signer question asked=%v (prompts %q)", asked, e.tty.prompts)
			}
			n := len(e.daemon.policies)
			if got := n > 0 && e.daemon.policies[n-1].Confirm; got != tc.confirmed {
				t.Fatalf("confirmed=%v (policy calls %+v)", got, e.daemon.policies)
			}
			if tc.confirmed {
				last := e.daemon.unlocks[len(e.daemon.unlocks)-1]
				if !last.TTY || (!tc.beta && !last.Global) || (tc.beta && (last.Global || len(last.RootIDs) != 1 || last.RootIDs[0] != "root-beta")) {
					t.Errorf("signer unlock %+v", last)
				}
			}
			done := strings.Contains(out, fmt.Sprintf(textUnprotectDone, "~/work/acme"))
			waits := strings.Contains(out, fmt.Sprintf(textUnprotectWaits, "~/work/acme", "~/work/acme"))
			if done != tc.confirmed || waits == tc.confirmed {
				t.Errorf("confirmed=%v: \"no longer protected\" shown %v, \"stays protected\" shown %v: %q", tc.confirmed, done, waits, out)
			}
		})
	}
}

// U6-1: an agent that refuses the confirmation is quoted as its own line,
// never behind "unprotect:", and a cancelled unlock of the global vault
// that would sign names "the global vault", never its id; either way the
// folder stays protected (exit 3).
func TestUnprotectSaysWhyTheRemovalWaits(t *testing.T) {
	for _, tc := range []struct {
		name       string
		unlockErr  error
		policyErr  error
		want, lose string
	}{
		{"the signer unlock is cancelled", &ipc.Error{Code: ipc.CodeCancelled, Msg: "precinto: unlock cancelled. global stays locked."}, nil,
			ui.Format(ui.MsgUnlockCancelled, ui.Vars{Folder: "the global vault"}), "global stays locked"},
		{"the agent refuses the confirmation", nil, &ipc.Error{Code: ipc.CodeUnauthorized, Msg: "precinto: confirm settings right after unlocking in a terminal"}, "precinto: confirm settings right after unlocking in a terminal", "unprotect: precinto:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.eng.units = []sweep.UnitInfo{{Unit: "u", RootIDs: []string{"root-acme"}}}
			e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}}
			e.daemon.pending = []string{"roots[root-acme]: " + e.h.Root + " → "}
			e.daemon.unlockErr = tc.unlockErr
			e.daemon.policyErr = tc.policyErr
			e.tty.lines = []string{wordUnprotect}
			e.tty.yesno = []bool{true, true}
			if code := e.run("unprotect", e.h.Root); code != exitLocked {
				t.Fatalf("exit %d, want %d (%s)", code, exitLocked, e.stderr())
			}
			out := e.stderr()
			if !strings.Contains(out, tc.want+"\n") || strings.Contains(out, tc.lose) || strings.Contains(out, "unprotect: precinto") {
				t.Errorf("stderr %q, want the line %q and never %q", out, tc.want, tc.lose)
			}
			if !strings.Contains(out, fmt.Sprintf(textUnprotectWaits, "~/work/acme", "~/work/acme")) || strings.Contains(out, "is no longer protected") {
				t.Errorf("stderr %q", out)
			}
		})
	}
}
