package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/ui"
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
	mkdir(t, filepath.Join(e.h.HomeDir, "beta"))
	e.tty.yesno = []bool{false}
	if code := e.run("protect", filepath.Join(e.h.HomeDir, "beta")); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if r := e.loadConfig().Roots[1]; !slices.Equal(r.Harnesses, []string{"claude-code"}) {
		t.Fatalf("harnesses %v", r.Harnesses)
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
	if !strings.Contains(e.stderr(), ui.Format(ui.MsgPolicyPending, ui.Vars{N: 1})) {
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

// --root accepts a folder id (the daemon's workers), not only a path.
func TestRootArgByID(t *testing.T) {
	e := newEnv(t)
	e.cwd = "/"
	if code := e.run("sweep", "--root", "root-acme", "--quiet"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if ids := e.eng.sweepOpts[0].Scope.RootIDs; len(ids) != 1 || ids[0] != "root-acme" {
		t.Fatalf("scope %v", ids)
	}
	if code := e.run("sweep", "--root", "root-nope"); code != exitUsage {
		t.Fatalf("unknown id: exit %d", code)
	}
}
