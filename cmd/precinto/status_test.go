package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
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
		"vault    unlock with passphrase · recovery key: tested 2026-11-21",
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
