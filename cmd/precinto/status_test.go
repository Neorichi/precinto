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
			{Harness: "claude-code", SID: "s1", RootIDs: []string{"root-acme"}, State: "running", HooksSeen: true, Registered: true},
			{Harness: "codex", SID: "s2", Proc: platform.ProcID{PID: 77}, RootIDs: []string{"root-acme"}, State: "running"},
		},
		Attention: []ipc.Attention{{Code: ipc.AttnConflict, Folder: "~/work/acme", Count: 1, Fix: "precinto resolve FILE"}},
	}
	e.eng.plain = []sweep.Plaintext{{RootID: "root-acme", Files: 3, Bytes: 4200, ByReason: map[string]int{"running": 2, "notes": 1}}}
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
