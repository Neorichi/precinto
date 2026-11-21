package doctor_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault"
)

const (
	unitA = "0123456789abcdef0123456789abcdef"
	unitB = "fedcba9876543210fedcba9876543210"
	unitC = "00112233445566778899aabbccddeeff"
)

// capsuleFile writes ciphertext-looking bytes at capsules/<rel>.
func (f *fixture) capsuleFile(rel string) string {
	f.t.Helper()
	return writeFile(f.t, filepath.Join(f.h.Layout.CapsulesDir, filepath.FromSlash(rel)), "age-encryption.org/v1\n-> X25519 x\n--- y\n", 0o600)
}

func TestQuarantine(t *testing.T) {
	f := newFixture(t)
	want(t, f.run(), doctor.CheckQuarantine, doctor.OK)

	writeFile(t, filepath.Join(f.h.Layout.QuarantineDir, "op1", "g000001.pcap"), "x", 0o600)
	writeFile(t, filepath.Join(f.h.Layout.QuarantineDir, "op2", "state_5.sqlite-wal"), "x", 0o600)
	fs := f.run()
	want(t, fs, doctor.CheckQuarantine, doctor.Warn, "1 capsule without provenance is quarantined")
	want(t, fs, doctor.CheckQuarantine, doctor.Info, "1 file displaced at restore")

	// The store against the provenance log.
	g := newFixture(t)
	logged := g.capsuleFile("claude-code/" + unitA + "/g000001.pcap")
	g.capsuleFile("claude-code/" + unitA + "/g000002.pcap")       // forged: not logged
	g.capsuleFile("codex/" + unitB + "/blobs/" + unitC + ".pcap") // not logged either
	g.capsuleFile("claude-code/" + unitC + "/g000003.pcap")       // named by a pending journal record
	writeFile(t, g.h.Layout.CapsuleLog, "", 0o600)
	mkdir(t, g.h.Layout.JournalDir, 0o700)
	entries := []capslog.Entry{
		{Path: "claude-code/" + unitA + "/g000001.pcap", HeaderSHA256: "aa"},
		{Path: "claude-code/" + unitB + "/g000001.pcap", HeaderSHA256: "bb"}, // lost
	}
	g.d.CapsuleLog = func() ([]capslog.Entry, error) { return entries, nil }
	g.d.JournalPending = func() ([]*journal.Record, error) {
		return []*journal.Record{{ID: "op", Kind: journal.KindSeal, Harness: "claude-code", Unit: unitC, Phase: journal.PhasePrepared, Capsule: "g000003.pcap"}}, nil
	}
	g.d.CapsuleHeaderSHA = func(p string) (string, error) {
		if p == logged {
			return "AA", nil // hex case does not matter
		}
		return "", errors.New("unexpected header read of " + p)
	}
	fs = g.run()
	got := want(t, fs, doctor.CheckQuarantine, doctor.Warn, "2 files in the capsule store are not in the provenance log")
	if got.Fix != "precinto sweep" {
		t.Errorf("fix %q", got.Fix)
	}
	want(t, fs, doctor.CheckQuarantine, doctor.Warn, "1 logged capsule is missing")
	none(t, fs, doctor.CheckQuarantine, doctor.Fail)

	// A logged capsule whose header changed was replaced.
	g.d.CapsuleHeaderSHA = func(string) (string, error) { return "cc", nil }
	want(t, g.run(), doctor.CheckQuarantine, doctor.Fail, "no longer matches its log entry")
}

func TestUnsealed(t *testing.T) {
	f := newFixture(t)
	f.d.Plaintext = func(context.Context) ([]sweep.Plaintext, error) {
		return []sweep.Plaintext{
			{RootID: "root-acme", Files: 3, Bytes: 12_000, ByReason: map[string]int{"restored": 2, "remove-failed": 1}},
			{RootID: "root-beta", Files: 2, Bytes: 10, ByReason: map[string]int{"running": 2}},
			{RootID: "root-gone", Files: 0},
		}, nil
	}
	beta := f.h.Protect(t, "work/beta")
	f.o.Cfg = f.h.Cfg
	fs := f.run()
	got := want(t, fs, doctor.CheckUnsealed, doctor.Warn, "3 files (12 kB) of "+f.tilde(f.h.Root)+" are unencrypted although the folder is locked: remove-failed 1, restored 2")
	if got.Fix != "precinto sweep" {
		t.Errorf("fix %q", got.Fix)
	}
	want(t, fs, doctor.CheckUnsealed, doctor.Info, "2 files", f.tilde(beta.Path), "running 2")

	// An unlocked folder's plaintext is expected.
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) {
		return ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}, {VaultID: beta.ID, State: "unlocked"}}}, nil
	}
	want(t, f.run(), doctor.CheckUnsealed, doctor.OK)

	f.d.Plaintext = func(context.Context) ([]sweep.Plaintext, error) { return nil, errors.New("scan failed") }
	want(t, f.run(), doctor.CheckUnsealed, doctor.Info, "could not scan")
}

func TestUnsealedInterruptedOperations(t *testing.T) {
	f := newFixture(t)
	mkdir(t, f.h.Layout.JournalDir, 0o700)
	f.h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 5000, StartUS: 1}, PPID: 1})
	f.d.JournalPending = func() ([]*journal.Record, error) {
		return []*journal.Record{
			{ID: "1", Kind: journal.KindSeal, PID: 5001, Updated: now.Add(-time.Minute)},      // owner gone
			{ID: "2", Kind: journal.KindRestore, PID: 5000, Updated: now.Add(-3 * time.Hour)}, // stuck
			{ID: "3", Kind: journal.KindSeal, PID: 5000, Updated: now.Add(-time.Minute)},      // in flight
		}, nil
	}
	got := want(t, f.run(), doctor.CheckUnsealed, doctor.Warn, "2 interrupted operations (restore 1, seal 1) wait for recovery")
	if got.Fix != "precinto sweep" {
		t.Errorf("fix %q", got.Fix)
	}

	// Seal requests that gave up, or wait for long.
	g := newFixture(t)
	mkdir(t, g.h.Layout.QueueDir, 0o700)
	g.d.QueueList = func() ([]queue.Request, error) {
		return []queue.Request{
			{ID: "a", Harness: "codex", At: now.Add(-8 * time.Hour), Deadline: now.Add(-2 * time.Hour)},
			{ID: "b", Harness: "claude-code", At: now.Add(-2 * time.Hour)},
			{ID: "c", Harness: "claude-code", At: now.Add(-time.Minute)},
		}, nil
	}
	fs := g.run()
	want(t, fs, doctor.CheckUnsealed, doctor.Warn, "1 seal request gave up waiting")
	want(t, fs, doctor.CheckUnsealed, doctor.Info, "1 seal request has been waiting")
}

func TestResidue(t *testing.T) {
	f := newFixture(t)
	want(t, f.run(), doctor.CheckResidue, doctor.OK)

	// Restore staging: an abandoned directory, and one a pending record
	// still owns.
	orphan := mkdir(t, filepath.Join(f.h.Layout.StagingDir, "op-orphan"), 0o700)
	writeFile(t, filepath.Join(orphan, "f000001"), "plaintext", 0o600)
	owned := mkdir(t, filepath.Join(f.h.Layout.StagingDir, "op-owned"), 0o700)
	mkdir(t, f.h.Layout.JournalDir, 0o700)
	f.d.JournalPending = func() ([]*journal.Record, error) {
		return []*journal.Record{{ID: "op-owned", Kind: journal.KindRestore, Phase: journal.PhaseStaged, Staging: owned, Updated: now}}, nil
	}
	fs := f.run()
	got := want(t, fs, doctor.CheckResidue, doctor.Warn, f.h.Layout.StagingDir+"/op-orphan is an abandoned restore staging folder with 1 decrypted file")
	if got.Fix != "rm -r "+orphan {
		t.Errorf("fix %q", got.Fix)
	}
	for _, x := range of(fs, doctor.CheckResidue) {
		if strings.Contains(x.Message, "op-owned") {
			t.Errorf("staging owned by a journal record reported: %q", x.Message)
		}
	}

	// Claude's temp folder must be private (S7); stale shell snapshots.
	if err := os.Chmod(f.h.ClaudeTmp, 0o755); err != nil {
		t.Fatal(err)
	}
	snap := writeFile(t, filepath.Join(f.h.ClaudeConfig, "shell-snapshots", "snapshot-zsh-1.sh"), "export X=1\n", 0o600)
	setMtime(t, snap, 48*time.Hour)
	writeFile(t, filepath.Join(f.h.ClaudeConfig, "shell-snapshots", "snapshot-zsh-2.sh"), "export X=1\n", 0o600) // fresh: in use
	setMtime(t, filepath.Join(f.h.ClaudeConfig, "shell-snapshots", "snapshot-zsh-2.sh"), time.Hour)
	fs = f.run()
	want(t, fs, doctor.CheckResidue, doctor.Warn, "Claude's temp folder "+f.h.ClaudeTmp+" can be read by other users")
	want(t, fs, doctor.CheckResidue, doctor.Warn, "1 old shell snapshot in")

	// --leaks: usage data, edit diffs, Codex hook outputs.
	g := newFixture(t)
	writeFile(t, filepath.Join(g.h.ClaudeConfig, "usage-data", "2026-11", "a.json"), "{}", 0o600)
	writeFile(t, filepath.Join(g.h.ClaudeConfig, "projects", "p", "bash-edit-diff", "d1"), "diff", 0o600)
	tmp := g.o.Env.Get("TMPDIR")
	writeFile(t, filepath.Join(tmp, "codex-hook_outputs-x", "out.txt"), "output", 0o600)
	none(t, g.run(), doctor.CheckResidue, doctor.Info, doctor.Warn)
	g.o.Leaks = true
	fs = g.run()
	want(t, fs, doctor.CheckResidue, doctor.Info, "usage-data holds 1 file")
	want(t, fs, doctor.CheckResidue, doctor.Warn, "bash-edit-diff holds 1 file")
	want(t, fs, doctor.CheckResidue, doctor.Warn, "Codex hook outputs")
}

func TestPendingAndTamperedPolicy(t *testing.T) {
	f := newFixture(t)
	fs := f.run()
	none(t, fs, doctor.CheckPendingPolicy)
	none(t, fs, doctor.CheckPolicyTampered)

	// A pinned policy with one more root and a shorter idle_soft than
	// config.toml now has: two weakening edits are pending.
	pinnedCfg := f.h.Cfg
	pinnedCfg.Roots = append(append([]config.Root{}, f.h.Cfg.Roots...), config.Root{ID: "root-gone", Path: filepath.Join(f.h.HomeDir, "work", "gone"), MD: config.MDLedger})
	pinnedCfg.Policy.IdleSoft = config.Duration(5 * time.Minute)
	mac := strings.Repeat("ab", 32)
	p := config.Pinned{Version: config.PinnedVersion, ConfirmedAt: now, Config: pinnedCfg, MACs: map[string]string{"root-acme": mac}}
	if err := config.SavePinned(f.h.Layout.PolicyPinned, p); err != nil {
		t.Fatal(err)
	}
	fs = f.run()
	got := want(t, fs, doctor.CheckPendingPolicy, doctor.Warn, "waiting for your confirmation (2)", "folder ~/work/gone removed, policy.idle_soft")
	if !strings.Contains(got.Fix, "precinto unlock") {
		t.Errorf("fix %q", got.Fix)
	}
	want(t, fs, doctor.CheckPolicyTampered, doctor.OK)

	// Same policy: nothing pending.
	p.Config = f.h.Cfg
	if err := config.SavePinned(f.h.Layout.PolicyPinned, p); err != nil {
		t.Fatal(err)
	}
	want(t, f.run(), doctor.CheckPendingPolicy, doctor.OK)

	// Tampering shapes (D55).
	for name, mutate := range map[string]func(*config.Pinned){
		"no MAC":        func(p *config.Pinned) { p.MACs = nil },
		"malformed MAC": func(p *config.Pinned) { p.MACs = map[string]string{"root-acme": "zz"} },
	} {
		q := p
		mutate(&q)
		if err := config.SavePinned(f.h.Layout.PolicyPinned, q); err != nil {
			t.Fatal(err)
		}
		want(t, f.run(), doctor.CheckPolicyTampered, doctor.Fail, "changed outside precinto")
		_ = name
	}
	q := p
	q.MACs = map[string]string{"root-acme": mac, "9f0e1d2c3b4a59687766554433221100": mac}
	if err := config.SavePinned(f.h.Layout.PolicyPinned, q); err != nil {
		t.Fatal(err)
	}
	want(t, f.run(), doctor.CheckPolicyTampered, doctor.Warn, "names 1 vault that no protected folder uses")
	writeFile(t, f.h.Layout.PolicyPinned, `{"v":1,"unknown_key":true}`, 0o600)
	want(t, f.run(), doctor.CheckPolicyTampered, doctor.Fail, "cannot be read")
	none(t, f.run(), doctor.CheckPendingPolicy)

	// A FIFO at the pinned path never blocks doctor.
	os.Remove(f.h.Layout.PolicyPinned)
	if err := syscall.Mkfifo(f.h.Layout.PolicyPinned, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan []doctor.Finding, 1)
	go func() {
		fs, _ := doctor.RunWith(context.Background(), f.o, f.d)
		done <- fs
	}()
	select {
	case fs := <-done:
		want(t, fs, doctor.CheckPolicyTampered, doctor.Fail, "unsafe path")
	case <-time.After(20 * time.Second):
		t.Fatal("doctor blocked on a FIFO at state/policy.pinned")
	}
}

func TestPolicyPinnedMissingAfterUnlocks(t *testing.T) {
	f := newFixture(t)
	f.d.OpenVault = func(id string) (*vault.Vault, error) {
		return &vault.Vault{Meta: vault.Meta{ID: id, RecoveryVerifiedAt: now, LastAudit: now.Add(-time.Hour)}}, nil
	}
	want(t, f.run(), doctor.CheckPolicyTampered, doctor.Warn, "is missing although folders have been unlocked before")
}

func TestConflict(t *testing.T) {
	f := newFixture(t)
	var asked bool
	f.d.Units = func(_ context.Context, conflicts bool) ([]sweep.UnitInfo, error) {
		asked = conflicts
		return []sweep.UnitInfo{
			{Unit: unitA, RootIDs: []string{"root-acme"}, Conflicts: 2},
			{Unit: unitB, RootIDs: []string{"root-acme"}, Conflicts: 1},
			{Unit: unitC, Conflicts: 0},
		}, nil
	}
	got := want(t, f.run(), doctor.CheckConflict, doctor.Warn, "3 files of "+f.tilde(f.h.Root)+" have two versions kept side by side")
	if !asked || got.Fix != "precinto ls --conflicts, then precinto resolve FILE" {
		t.Errorf("asked conflicts=%v, fix %q", asked, got.Fix)
	}
	f.d.Units = func(context.Context, bool) ([]sweep.UnitInfo, error) { return nil, errors.New("x") }
	want(t, f.run(), doctor.CheckConflict, doctor.Info, "could not list")
}

func TestHoldCapped(t *testing.T) {
	f := newFixture(t)
	none(t, f.run(), doctor.CheckHoldCapped) // only the agent tracks holds
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) { return ipc.StatusResp{PID: 9}, nil }
	want(t, f.run(), doctor.CheckHoldCapped, doctor.OK)
}

func TestUngatedSessionScan(t *testing.T) {
	f := newFixture(t)
	old := now.Add(-time.Hour).UnixMicro()
	claudeProc := platform.ProcInfo{ID: platform.ProcID{PID: 6000, StartUS: old}, PPID: 1, Exe: "/Users/u/.local/share/claude/versions/2.1.329", Comm: "2.1.329"}
	codexProc := platform.ProcInfo{ID: platform.ProcID{PID: 6001, StartUS: old}, PPID: 1, Exe: "/opt/homebrew/bin/codex"}
	young := platform.ProcInfo{ID: platform.ProcID{PID: 6002, StartUS: now.Add(-5 * time.Second).UnixMicro()}, PPID: 1, Exe: "/opt/homebrew/bin/claude"}
	outside := platform.ProcInfo{ID: platform.ProcID{PID: 6003, StartUS: old}, PPID: 1, Exe: "/opt/homebrew/bin/claude"}
	shell := platform.ProcInfo{ID: platform.ProcID{PID: 6004, StartUS: old}, PPID: 1, Exe: "/bin/zsh", Comm: "claude"}
	for _, p := range []platform.ProcInfo{claudeProc, codexProc, young, outside, shell} {
		f.h.Procs.Add(p)
		f.h.Procs.SetCwd(p.ID.PID, filepath.Join(f.h.Root, "src"))
	}
	f.h.Procs.SetCwd(outside.ID.PID, filepath.Join(f.h.Dir, "elsewhere"))
	mkdir(t, f.h.Layout.SessionsDir, 0o700)
	f.d.Sessions = func(h harness.ID) ([]ledger.Session, error) {
		if h == harness.Codex {
			return []ledger.Session{{Harness: "codex", SID: "00000000-0000-7000-8000-000000000001", CurrentProc: codexProc.ID}}, nil
		}
		return nil, nil
	}
	fs := f.run()
	got := want(t, fs, doctor.CheckUngatedSession, doctor.Warn, "claude (pid 6000) runs in "+f.tilde(f.h.Root)+" without precinto's hooks")
	if got.Fix != "quit it, or start it with: precinto run claude" {
		t.Errorf("fix %q", got.Fix)
	}
	for _, x := range of(fs, doctor.CheckUngatedSession) {
		for _, pid := range []string{"6001", "6002", "6003", "6004"} {
			if strings.Contains(x.Message, "pid "+pid) {
				t.Errorf("pid %s reported: %q", pid, x.Message)
			}
		}
	}

	// An unreadable ledger makes no claim; the agent's own scan wins when
	// it runs.
	f.d.Sessions = func(harness.ID) ([]ledger.Session, error) { return nil, errors.New("unreadable") }
	none(t, f.run(), doctor.CheckUngatedSession, doctor.Warn)
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) { return ipc.StatusResp{PID: 9}, nil }
	want(t, f.run(), doctor.CheckUngatedSession, doctor.OK)
	_ = testkit.Epoch
}

// An unreadable part of the store is not taken for lost capsules.
func TestQuarantineUnreadableStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	f := newFixture(t)
	f.capsuleFile("claude-code/" + unitA + "/g000001.pcap")
	writeFile(t, f.h.Layout.CapsuleLog, "", 0o600)
	f.d.CapsuleLog = func() ([]capslog.Entry, error) {
		return []capslog.Entry{{Path: "claude-code/" + unitA + "/g000001.pcap", HeaderSHA256: "aa"}}, nil
	}
	dir := filepath.Join(f.h.Layout.CapsulesDir, "claude-code", unitA)
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	fs := f.run()
	none(t, fs, doctor.CheckQuarantine, doctor.Warn, doctor.Fail)
	want(t, fs, doctor.CheckQuarantine, doctor.Info, "could not be fully listed")
}

// An unreadable process table makes the local ungated scan claim nothing.
func TestUngatedScanUnreadableProcessTable(t *testing.T) {
	f := newFixture(t)
	p := platform.ProcInfo{ID: platform.ProcID{PID: 6100, StartUS: now.Add(-time.Hour).UnixMicro()}, PPID: 1, Exe: "/opt/homebrew/bin/claude"}
	f.h.Procs.Add(p)
	f.h.Procs.SetCwd(p.ID.PID, f.h.Root)
	want(t, f.run(), doctor.CheckUngatedSession, doctor.Warn, "pid 6100")
	f.h.Procs.SetErr(fakeplatform.OpCwd, errors.New("proc_pidinfo denied"))
	none(t, f.run(), doctor.CheckUngatedSession, doctor.Warn)
	f.h.Procs.SetErr(fakeplatform.OpCwd, nil)
	f.h.Procs.SetErr(fakeplatform.OpList, errors.New("sysctl failed"))
	none(t, f.run(), doctor.CheckUngatedSession, doctor.Warn)
}
