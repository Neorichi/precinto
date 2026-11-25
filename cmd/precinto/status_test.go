package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/doctor"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/sweep"
	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/internal/ui"
	"github.com/Neorichi/precinto/internal/vault"
)

// statusEnv has a running daemon with the folder unlocked, one running and
// one ungated session, plaintext on disk and a sealed session.
func statusEnv(t *testing.T) *env {
	e := newEnv(t)
	until := testkit.Epoch.Add(8 * time.Hour)
	e.daemon.status = ipc.StatusResp{
		Version: "0.2.0-test", PID: 321, Started: testkit.Epoch, ScreenWatch: true,
		Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked", Since: testkit.Epoch,
			IdleDeadline: testkit.Epoch.Add(15 * time.Minute), AbsDeadline: until}},
		Sessions: []ipc.SessionStatus{
			{Harness: "claude-code", SID: "s1", RootIDs: []string{"root-acme"}, State: "running", HooksSeen: true, Registered: true, Version: "2.1.329"},
			{Harness: "codex", SID: "s2", Proc: platform.ProcID{PID: 77}, RootIDs: []string{"root-acme"}, State: "running"},
		},
		Attention: []ipc.Attention{{Code: ipc.AttnConflict, Folder: "~/work/acme", Count: 1, Fix: "precinto resolve FILE"}},
	}
	e.eng.plain = []sweep.Plaintext{{RootID: "root-acme", Files: 3, Bytes: 4200, ByReason: map[string]int{"running": 2, "notes": 1}}}
	e.eng.wrongHome = map[string]int{"root-acme": 2, "": 1}
	e.eng.units = []sweep.UnitInfo{
		{Kind: capsule.KindClaudeSession, Unit: "a", RootIDs: []string{"root-acme"}, Gens: []sweep.Generation{{Gen: 1}}},
		{Kind: capsule.KindClaudeSession, Unit: "b", RootIDs: []string{"root-acme"}, Gens: []sweep.Generation{{Gen: 1}}, Plaintext: true, Reason: "restored"},
	}
	return e
}

// status --json is schema v1 (SPEC §16.4): the golden file fixes every key
// and the attention vocabulary.
func TestStatusJSONGolden(t *testing.T) {
	e := statusEnv(t)
	if code := e.run("status", "--json"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	got := bytes.ReplaceAll(e.out.Bytes(), []byte(e.h.Dir), []byte("/FAKEHOME"))
	testkit.Golden(t, "status_v1.json", got)

	var s map[string]any
	if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"v", "vault", "agent", "folders", "harnesses", "attention"} {
		if _, ok := s[k]; !ok {
			t.Errorf("schema v1 key %q missing", k)
		}
	}
	if s["v"].(float64) != 1 {
		t.Errorf("v = %v", s["v"])
	}
}

// Without a daemon every folder is locked, arrays are never null, and
// --check exits 3 when a locked folder still has unencrypted files.
func TestStatusNoDaemonAndCheck(t *testing.T) {
	e := newEnv(t)
	e.dialErr = ipc.ErrNoDaemon
	e.eng.plain = []sweep.Plaintext{{RootID: "root-acme", Files: 1, Bytes: 10, ByReason: map[string]int{"running": 1}}}
	if code := e.run("status", "--json", "--check"); code != exitLocked {
		t.Fatalf("exit %d, want 3", code)
	}
	var s statusV1
	if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.Agent.Running || len(s.Folders) != 1 || s.Folders[0].State != "locked" {
		t.Fatalf("status %+v", s)
	}
	if !hasAttention(s.Attention, ipc.AttnUnsealed) || !hasAttention(s.Attention, ipc.AttnRecoveryTested) {
		t.Fatalf("attention %+v", s.Attention)
	}
	for _, null := range []string{`"folders": null`, `"harnesses": null`, `"attention": null`, `"factors": null`} {
		if strings.Contains(e.stdout(), null) {
			t.Errorf("JSON has %s", null)
		}
	}
	// No unencrypted files: --check passes.
	e = newEnv(t)
	e.dialErr = ipc.ErrNoDaemon
	if code := e.run("status", "--check"); code != exitOK {
		t.Fatalf("clean --check exit %d", code)
	}
}

// Before init, status reports it and never builds the engine (which would
// create precinto's directories).
func TestStatusBeforeInit(t *testing.T) {
	e := newEnv(t)
	e.vaults.initialized = false
	e.dialErr = ipc.ErrNoDaemon
	if code := e.run("status", "--json"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var s statusV1
	if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.Vault.Initialized || len(e.engExp) != 0 {
		t.Fatalf("initialized %v, engine built %d times", s.Vault.Initialized, len(e.engExp))
	}
}

func TestStatusHuman(t *testing.T) {
	e := statusEnv(t)
	e.vaults.metas[vault.GlobalID] = vault.Meta{Factors: []vault.Factor{{Name: "passphrase", Kind: vault.FactorPassphrase}}, RecoveryVerifiedAt: testkit.Epoch}
	if code := e.run("status"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	out := e.stdout()
	for _, want := range []string{
		"vault    unlock with passphrase · recovery key: tested " + testkit.Epoch.Format("2006-01-02"), // the fixture's RecoveryVerifiedAt
		"agent    running (pid 321)",
		"FOLDERS\n  ~/work/acme  unlocked until 17:00 (locks after 15 min idle)",
		"sessions: 1 running, 0 working, 0 paused, 1 restored, 1 sealed, 1 without hooks",
		"unencrypted: 3 files (4 kB): notes 1, running 2",
		"AGENTS\n  claude-code",
		"NEEDS ATTENTION\n  conflict",
		"ungated-session",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"root", "grant", "soft", "hard"} {
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(strings.ToLower(line), bad) && !strings.Contains(line, "--root") {
				t.Errorf("status line uses the forbidden word %q: %q", bad, line)
			}
		}
	}
}

// SPEC §16.4: AGENTS shows the harness version reported at register (the
// newest running one, CC-49); codex-wrong-home names the folder with
// C9.codexoutside (CC-18); a locked folder holding plaintext only because
// of weak liveness evidence is hold-capped (D63); C9.ungated names its
// harness (CC-48).
func TestStatusVersionWrongHomeHoldCapped(t *testing.T) {
	e := statusEnv(t)
	e.daemon.status.Sessions = append(e.daemon.status.Sessions,
		ipc.SessionStatus{Harness: "claude-code", SID: "s3", RootIDs: []string{"root-acme"}, State: "running", HooksSeen: true, Version: "2.1.30"})
	e.daemon.status.Vaults[0].State = "locked"
	e.eng.plain[0].ByReason[ipc.AttnHoldCapped] = 1
	if code := e.run("status", "--json"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	var s statusV1
	if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.Harnesses[0].ID != "claude-code" || s.Harnesses[0].Version != "2.1.329" {
		t.Fatalf("harnesses %+v, want claude-code at 2.1.329 (the newest)", s.Harnesses)
	}
	want := map[string]ipc.Attention{
		ipc.AttnCodexWrongHome: {Code: ipc.AttnCodexWrongHome, Folder: "~/work/acme", Count: 2,
			Detail: ui.Format(ui.MsgCodexOutside, ui.Vars{N: 2, Folder: "~/work/acme"}), Fix: "precinto run codex"},
		ipc.AttnHoldCapped: {Code: ipc.AttnHoldCapped, Folder: "~/work/acme", Count: 1, Fix: "precinto doctor"},
	}
	for code, w := range want {
		found := false
		for _, at := range s.Attention {
			if at.Code == code {
				found = true
				if at != w {
					t.Errorf("%s: %+v, want %+v", code, at, w)
				}
			}
		}
		if !found {
			t.Errorf("no %s item in %+v", code, s.Attention)
		}
	}
	for _, at := range s.Attention {
		if at.Code == ipc.AttnUngatedSession && at.Harness != "codex" {
			t.Errorf("ungated item without its harness: %+v", at)
		}
		if at.Code == ipc.AttnCodexWrongHome && at.Folder == "" {
			t.Errorf("uncheckable rollouts reported as a folder: %+v", at)
		}
	}
	e.out.Reset()
	if code := e.run("status"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(e.stdout(), "claude-code  enabled · version 2.1.329 · hooks OK") {
		t.Errorf("AGENTS line lacks the version:\n%s", e.stdout())
	}
	for _, c := range []struct {
		a, b string
		want int
	}{{"2.1.329", "2.1.30", 1}, {"1.2", "1.10", -1}, {"2.1.329", "2.1.329", 0}} {
		if got := cmpDotted(c.a, c.b); got != c.want {
			t.Errorf("cmpDotted(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func hasAttention(list []ipc.Attention, code string) bool {
	for _, a := range list {
		if a.Code == code {
			return true
		}
	}
	return false
}

func TestMergeAttentionDedupes(t *testing.T) {
	got := mergeAttention(
		[]ipc.Attention{{Code: "a", Folder: "x"}},
		[]ipc.Attention{{Code: "a", Folder: "x"}, {Code: "a", Folder: "y"}},
	)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
}

// C9.ungated names the command the user types: an ungated Claude Code
// session says "precinto run claude", never the harness id claude-code
// (the agent and doctor map it the same way, CC-48).
func TestStatusUngatedClaudeNamesTheCommand(t *testing.T) {
	e := statusEnv(t)
	e.daemon.status.Sessions = append(e.daemon.status.Sessions,
		ipc.SessionStatus{Harness: "claude-code", SID: "s4", Proc: platform.ProcID{PID: 88}, RootIDs: []string{"root-acme"}, State: "running"})
	if code := e.run("status", "--json"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	var s statusV1
	if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	want := ipc.Attention{Code: ipc.AttnUngatedSession, Folder: "~/work/acme", PID: 88, Harness: "claude",
		Detail: ui.Format(ui.MsgUngatedSession, ui.Vars{Harness: "claude", PID: 88, Folder: "~/work/acme"}), Fix: "precinto run claude"}
	found := false
	for _, at := range s.Attention {
		if at.Code == ipc.AttnUngatedSession && at.PID == 88 {
			found = true
			if at != want {
				t.Errorf("ungated Claude item %+v, want %+v", at, want)
			}
			if strings.Contains(at.Detail, "claude-code") {
				t.Errorf("C9.ungated names the harness id: %q", at.Detail)
			}
		}
	}
	if !found {
		t.Fatalf("no ungated item for the Claude session: %+v", s.Attention)
	}
}

// UX-09: status still answers when config.toml does not load: the error,
// with its key and line, is an attention item (doctor's config code), and
// the folders come from the settings precinto last confirmed and the
// agent's status.
func TestStatusWithBrokenConfig(t *testing.T) {
	e := statusEnv(t)
	writeBrokenConfig(t, e)
	e.daemon.status.Vaults[0].RootPath = e.h.Root
	if code := e.run("status", "--json"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	var s statusV1
	if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, at := range s.Attention {
		if at.Code == doctor.CheckConfig {
			found = true
			if !strings.Contains(at.Detail, "policy.min_free") || !strings.Contains(at.Detail, "line 3") || at.Fix == "" {
				t.Errorf("config item %+v", at)
			}
		}
	}
	if !found {
		t.Fatalf("no %s attention item: %+v", doctor.CheckConfig, s.Attention)
	}
	if len(s.Folders) != 1 || s.Folders[0].ID != "root-acme" || s.Folders[0].State != "unlocked" {
		t.Fatalf("folders %+v", s.Folders)
	}
	e.out.Reset()
	if code := e.run("status"); code != exitOK {
		t.Fatalf("human: exit %d (%s)", code, e.stderr())
	}
	if !strings.Contains(e.stdout(), "\n  config  ") || !strings.Contains(e.stdout(), "policy.min_free") {
		t.Errorf("human status lacks the config item:\n%s", e.stdout())
	}
}

// UX-12: the AGENTS line's fix for a missing wrapper is a command that
// runs: shell-init needs the shell's name, taken from $SHELL when it is
// one precinto supports.
func TestStatusWrapperHintNamesTheShell(t *testing.T) {
	for shell, want := range map[string]string{
		"/bin/zsh":               "wrapper not installed (precinto shell-init zsh --install)",
		"/opt/homebrew/bin/fish": "wrapper not installed (precinto shell-init fish --install)",
		"/bin/bash":              "wrapper not installed (precinto shell-init bash --install)",
		"/usr/local/bin/tcsh":    "wrapper not installed (precinto shell-init zsh|bash|fish --install)",
		"":                       "wrapper not installed (precinto shell-init zsh|bash|fish --install)",
	} {
		e := statusEnv(t)
		e.h.Env = e.h.Env.With("SHELL", shell)
		if code := e.run("status"); code != exitOK {
			t.Fatalf("%q: exit %d", shell, code)
		}
		if !strings.Contains(e.stdout(), want) {
			t.Errorf("SHELL=%q: status lacks %q:\n%s", shell, want, e.stdout())
		}
		if strings.Contains(e.stdout(), "shell-init --install") {
			t.Errorf("SHELL=%q: status suggests the invalid shell-init --install", shell)
		}
	}
}

// UX-14: status quotes the idle time in force: an unconfirmed weakening
// edit of config.toml (idle_soft 15m → 30m) is not what locks the folder.
func TestStatusQuotesTheIdleInForce(t *testing.T) {
	e := statusEnv(t)
	pinPolicy(t, e, e.loadConfig())
	c := e.loadConfig()
	c.Policy.IdleSoft = config.Duration(30 * time.Minute)
	e.saveConfig(c)
	if code := e.run("status"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(e.stdout(), "unlocked until 17:00 (locks after 15 min idle)") {
		t.Errorf("status quotes config.toml's unconfirmed value:\n%s", e.stdout())
	}
}

// UX-09 (regression of the first fix): a config.toml that does not load
// never makes `status --check` pass. The folders are still scanned, with
// the settings standing in for the file (the settings confirmed last, or
// the defaults, plus every folder whose vault records its path, as
// newSweepEngine builds the engine from them): plaintext in a locked
// folder is exit 3 as always; finding none is exit 1, because the file may
// hold more than the stand-in settings show. The counts say how they were
// found, and the JSON marks them incomplete.
func TestStatusCheckWithBrokenConfig(t *testing.T) {
	// The settings confirmed last know the folder; it has a note.
	e := newEnv(t)
	e.dialErr = ipc.ErrNoDaemon
	pinPolicy(t, e, e.loadConfig())
	writeBrokenConfig(t, e)
	e.eng.plain = []sweep.Plaintext{{RootID: "root-acme", Files: 1, Bytes: 11, ByReason: map[string]int{"notes": 1}}}
	if code := e.run("status", "--check"); code != exitLocked {
		t.Fatalf("plaintext in a locked folder: exit %d, want 3 (%s)", code, e.stderr())
	}
	if len(e.engCfg) != 1 || len(e.engCfg[0].Roots) != 1 || e.engCfg[0].Roots[0].ID != "root-acme" {
		t.Fatalf("engine settings %+v, want the confirmed folder", e.engCfg)
	}
	for _, w := range []string{
		"unencrypted: 1 files (11 B): notes 1, found with the settings confirmed last (config.toml does not load)",
		"\n  unsealed  ~/work/acme · 1 · fix: precinto doctor\n", "\n  config  config.toml line 3, policy.min_free",
	} {
		if !strings.Contains(e.stdout(), w) {
			t.Errorf("status lacks %q:\n%s", w, e.stdout())
		}
	}

	// Nothing found with them: exit 1, never 0, and the file is named.
	e = newEnv(t)
	e.dialErr = ipc.ErrNoDaemon
	pinPolicy(t, e, e.loadConfig())
	writeBrokenConfig(t, e)
	if code := e.run("status", "--check"); code != exitError {
		t.Fatalf("broken config, nothing found: exit %d, want 1", code)
	}
	if !strings.Contains(e.stdout(), "unencrypted: none found with the settings confirmed last (config.toml does not load)") {
		t.Errorf("status:\n%s", e.stdout())
	}
	if want := "precinto: " + fmt.Sprintf(textCheckConfig, `config.toml line 3, policy.min_free: size "2GB" (use e.g. "512MiB" or "2GiB")`) + "\n"; e.stderr() != want {
		t.Errorf("stderr %q, want %q", e.stderr(), want)
	}

	// No pin and no agent: the folder comes from its vault, never
	// "FOLDERS none", and the JSON marks its counts incomplete.
	e = newEnv(t)
	e.dialErr = ipc.ErrNoDaemon
	writeBrokenConfig(t, e)
	e.vaults.metas["root-acme"] = vault.Meta{ID: "root-acme", RootPath: e.h.Root}
	if err := os.MkdirAll(e.h.Layout.VaultsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if code := e.run("status", "--json", "--check"); code != exitError {
		t.Fatalf("no pin: exit %d, want 1", code)
	}
	var s statusV1
	if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Folders) != 1 || s.Folders[0].ID != "root-acme" || s.Folders[0].Path != e.h.Root || !s.Folders[0].Unencrypted.Incomplete {
		t.Fatalf("folders %+v", s.Folders)
	}
	if len(e.engCfg) != 1 || len(e.engCfg[0].Roots) != 1 || e.engCfg[0].Roots[0].Path != e.h.Root {
		t.Fatalf("engine settings %+v, want the folder of its vault", e.engCfg)
	}
	e.out.Reset()
	if code := e.run("status"); code != exitOK || strings.Contains(e.stdout(), "none (protect one") ||
		!strings.Contains(e.stdout(), "unencrypted: none found with the default settings (config.toml does not load)") {
		t.Errorf("no pin, human: exit %d\n%s", code, e.stdout())
	}
}

// A locked folder that could not be scanned is "unknown", never "none",
// and --check does not pass on it (exit 1).
func TestStatusCheckWhenTheScanFails(t *testing.T) {
	e := newEnv(t)
	e.dialErr = ipc.ErrNoDaemon
	e.engErr = errors.New("name salt unreadable")
	if code := e.run("status", "--check"); code != exitError {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(e.stdout(), "unencrypted: unknown (the folders could not be scanned)") {
		t.Errorf("status:\n%s", e.stdout())
	}
	if want := "precinto: " + fmt.Sprintf(textCheckUnscanned, textPlainUnscanned) + "\n"; e.stderr() != want {
		t.Errorf("stderr %q, want %q", e.stderr(), want)
	}
	// An unlocked folder may hold plaintext: the check passes.
	e = statusEnv(t)
	e.engErr = errors.New("name salt unreadable")
	if code := e.run("status", "--check"); code != exitOK {
		t.Fatalf("unlocked folder: exit %d (%s)", code, e.stderr())
	}
}

// The stand-in settings take a pin's folders only when they are safe to
// scan: a pin is never validated, so a forged one listing / or a relative
// path adds nothing; a vault's folder joins once.
func TestStandInConfigKeepsSafeFolders(t *testing.T) {
	e := newEnv(t)
	c := e.loadConfig()
	c.Roots = append(c.Roots, config.Root{ID: "slash", Path: "/"}, config.Root{ID: "rel", Path: "work/x"}, config.Root{ID: "", Path: "/u/none"})
	pinPolicy(t, e, c)
	e.vaults.metas["root-acme"] = vault.Meta{ID: "root-acme", RootPath: e.h.Root}
	e.vaults.metas["root-beta"] = vault.Meta{ID: "root-beta", RootPath: "/u/beta"}
	if err := os.MkdirAll(e.h.Layout.VaultsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	a := e.app()
	got, what := a.standInConfig(e.h.Layout)
	var ids []string
	for _, r := range got.Roots {
		ids = append(ids, r.ID+"="+r.Path)
	}
	if want := []string{"root-acme=" + e.h.Root, "root-beta=/u/beta"}; strings.Join(ids, ",") != strings.Join(want, ",") || what != textStandInPinned {
		t.Fatalf("stand-in folders %v (%s), want %v", ids, what, want)
	}
}

// D149 (S6-8): the settings standing in for a config.toml that does not
// load take their folders from state/policy.pinned and vault.toml, which
// are never validated: a folder whose path could not be saved (a control
// character) is left out, and every path the CLI prints is shown with its
// control and format characters escaped, so a forged path cannot repaint
// status.
func TestStandInDropsFolderPathsWithControls(t *testing.T) {
	forged := "/tmp/a\r\x1b[2K  ~/work/acme  locked\n      unencrypted: none\x1b[8m"
	var cfg config.Config
	addStandInRoot(&cfg, "root-x", forged)
	addStandInRoot(&cfg, "root-y", "/tmp/c1\u0085x")
	addStandInRoot(&cfg, "root-z", "/tmp/fine")
	if len(cfg.Roots) != 1 || cfg.Roots[0].ID != "root-z" {
		t.Fatalf("stand-in roots %+v, want only the clean path", cfg.Roots)
	}
	e := newEnv(t)
	a := e.app()
	var out bytes.Buffer
	a.printStatus(&out, statusV1{Folders: []statusFolder{
		{ID: "root-x", Path: forged, State: "locked"},
		{ID: "root-b", Path: "/tmp/b\u202eidi", State: "locked"},
	}})
	s := out.String()
	if strings.ContainsAny(s, "\x1b\r\u202e") {
		t.Fatalf("status prints a path with its controls: %q", s)
	}
	if !strings.Contains(s, `\x1b[2K`) || !strings.Contains(s, `\u202e`) {
		t.Fatalf("status does not show the escaped paths: %q", s)
	}
	if got := a.display("/tmp/plain dir/acme"); got != "/tmp/plain dir/acme" {
		t.Errorf("a plain path is shown as %q", got)
	}
}

// D145 (S6-1): settings that name no folder are signed by the global vault
// alone, which only unlock --global checks. While they are confirmed,
// status names the folders whose vault is kept but that nothing protects
// (every folder dropped from config.toml with such a pin, or folders the
// user stopped protecting), with the command that checks those settings;
// the item never fails --check. A pin that names a folder is checked by
// that folder's unlock: nothing is shown.
func TestStatusNamesUnprotectedFolders(t *testing.T) {
	setup := func(t *testing.T, pinRoots bool) *env {
		e := newEnv(t)
		e.dialErr = ipc.ErrNoDaemon
		beta := e.h.HomeDir + "/work/beta"
		if err := os.MkdirAll(e.h.Layout.VaultsDir, 0o700); err != nil {
			t.Fatal(err)
		}
		e.vaults.metas["root-acme"] = vault.Meta{ID: "root-acme", RootPath: e.h.Root}
		e.vaults.metas["root-beta"] = vault.Meta{ID: "root-beta", RootPath: beta}
		c := e.loadConfig()
		macs := map[string]string{"root-acme": strings.Repeat("ab", 32)}
		if !pinRoots {
			c.Roots = nil
			macs = map[string]string{vault.GlobalID: strings.Repeat("ab", 32)}
		}
		e.saveConfig(c)
		if err := os.MkdirAll(e.h.Layout.StateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := config.SavePinned(e.h.Layout.PolicyPinned, config.Pinned{Config: c, MACs: macs}); err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := setup(t, false)
	if code := e.run("status", "--json", "--check"); code != exitOK {
		t.Fatalf("status --check: exit %d (%s)", code, e.stderr())
	}
	var s statusV1
	if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	var got *ipc.Attention
	for i, at := range s.Attention {
		if at.Code == doctor.CheckUnprotectedFolders {
			got = &s.Attention[i]
		}
	}
	if got == nil || got.Count != 2 || got.Fix != "precinto unlock --global" ||
		!strings.Contains(got.Detail, "~/work/acme, ~/work/beta: their vaults are kept, but no setting protects them") {
		t.Fatalf("attention %+v", s.Attention)
	}
	e = setup(t, true)
	e.run("status", "--json")
	if strings.Contains(e.stdout(), doctor.CheckUnprotectedFolders) {
		t.Fatalf("a pin that names a folder: %s", e.stdout())
	}
}
