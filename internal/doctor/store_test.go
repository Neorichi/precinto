package doctor_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	got := want(t, f.run(), doctor.CheckInterrupted, doctor.Warn, "2 interrupted operations (restore 1, seal 1) wait for recovery")
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
	got := want(t, fs, doctor.CheckInterrupted, doctor.Warn, f.h.Layout.StagingDir+"/op-orphan is an abandoned restore staging folder with 1 decrypted file")
	if got.Fix != "rm -r "+orphan {
		t.Errorf("fix %q", got.Fix)
	}
	for _, x := range of(fs, doctor.CheckInterrupted) {
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
	want(t, fs, doctor.CheckPermissions, doctor.Warn, "Claude's temp folder "+f.h.ClaudeTmp+" can be read by other users")
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

// TestVolumeStaging (FX-G7sup-06): a restore into a file system other than
// <base>'s stages in <volume>/.precinto-staging (fsx.NewStaging). doctor
// lists that directory of every volume holding a restore target, like
// <base>/staging, reports what no pending journal record names, and never
// lists one that is not a private directory of the user.
func TestVolumeStaging(t *testing.T) {
	f := newFixture(t)
	// A second "volume", mounted at a directory of the test tree, holding a
	// protected folder; every other path stays on the test's own volume.
	vol := mkdir(t, filepath.Join(f.h.Dir, "Volumes", "USB"), 0o700)
	usb := config.Root{ID: "root-usb", Path: mkdir(t, filepath.Join(vol, "notes"), 0o700), MD: config.MDLedger}
	f.o.Cfg.Roots = append(append([]config.Root{}, f.h.Cfg.Roots...), usb)
	var asked []string
	f.d.VolumeRoot = func(p string) string {
		asked = append(asked, p)
		if strings.HasPrefix(p, vol+string(filepath.Separator)) || p == vol {
			return vol
		}
		return f.h.Dir
	}
	none(t, f.run(), doctor.CheckInterrupted, doctor.Warn)
	if !slices.Contains(asked, usb.Path) || !slices.Contains(asked, f.h.Root) || !slices.Contains(asked, f.h.ClaudeConfig) {
		t.Errorf("volumes looked up for %q", asked)
	}

	staging := mkdir(t, filepath.Join(vol, ".precinto-staging"), 0o700)
	orphan := mkdir(t, filepath.Join(staging, "op-orphan"), 0o700)
	writeFile(t, filepath.Join(orphan, "f000001"), "plaintext", 0o600)
	writeFile(t, filepath.Join(orphan, "f000002"), "plaintext", 0o600)
	owned := mkdir(t, filepath.Join(staging, "op-owned"), 0o700)
	mkdir(t, f.h.Layout.JournalDir, 0o700)
	f.d.JournalPending = func() ([]*journal.Record, error) {
		return []*journal.Record{{ID: "op-owned", Kind: journal.KindRestore, Phase: journal.PhaseStaged, Staging: owned, Updated: now}}, nil
	}
	fs := f.run()
	got := want(t, fs, doctor.CheckInterrupted, doctor.Warn, orphan+" is an abandoned restore staging folder with 2 decrypted files")
	if got.Fix != "rm -r "+orphan {
		t.Errorf("fix %q", got.Fix)
	}
	for _, x := range of(fs, doctor.CheckInterrupted) {
		if strings.Contains(x.Message, "op-owned") {
			t.Errorf("staging owned by a journal record reported: %q", x.Message)
		}
	}
	none(t, fs, doctor.CheckPermissions, doctor.Warn, doctor.Fail)

	// Readable by others: reported, and still listed (it is the user's).
	if err := os.Chmod(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	fs = f.run()
	want(t, fs, doctor.CheckPermissions, doctor.Warn, staging+" can be read by other users (mode 0755)")
	want(t, fs, doctor.CheckInterrupted, doctor.Warn, orphan+" is an abandoned restore staging folder")

	// A symlink planted there is never listed (its target is not staging).
	if err := os.RemoveAll(staging); err != nil {
		t.Fatal(err)
	}
	decoy := mkdir(t, filepath.Join(f.h.Dir, "decoy"), 0o700)
	mkdir(t, filepath.Join(decoy, "op-decoy"), 0o700)
	if err := os.Symlink(decoy, staging); err != nil {
		t.Fatal(err)
	}
	fs = f.run()
	want(t, fs, doctor.CheckPermissions, doctor.Fail, staging+" is a symbolic link")
	for _, x := range of(fs, doctor.CheckInterrupted) {
		if strings.Contains(x.Message, "op-decoy") {
			t.Errorf("the target of a symlinked staging directory was listed: %q", x.Message)
		}
	}
}

// volumeRoot mirrors fsx's choice of <volume>/.precinto-staging: the
// highest ancestor on the same device, from the deepest existing prefix.
func TestVolumeRoot(t *testing.T) {
	dir := t.TempDir()
	v := doctor.VolumeRoot(dir)
	if v == "" || (v != dir && !strings.HasPrefix(dir, strings.TrimSuffix(v, "/")+"/")) {
		t.Fatalf("VolumeRoot(%s) = %q: not an ancestor", dir, v)
	}
	if got := doctor.VolumeRoot(filepath.Join(dir, "missing", "deeper")); got != v {
		t.Errorf("a missing path below %s: %q, want %q", dir, got, v)
	}
	if !doctor.SameDevice(v, dir) {
		t.Errorf("%s is not on the device of %s", v, dir)
	}
	if up := filepath.Dir(v); up != v && doctor.SameDevice(up, dir) {
		t.Errorf("the parent %s of %s is on the same device", up, v)
	}
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

	// Tampering shapes (D55, D91: the daemon's config.Pinned.CheckShape).
	for name, mutate := range map[string]func(*config.Pinned){
		"no MAC":        func(p *config.Pinned) { p.MACs = nil },
		"malformed MAC": func(p *config.Pinned) { p.MACs = map[string]string{"root-acme": "zz"} },
		"MAC of a vault outside the pinned settings": func(p *config.Pinned) {
			p.MACs = map[string]string{"root-acme": mac, "9f0e1d2c3b4a59687766554433221100": mac}
		},
	} {
		q := p
		mutate(&q)
		if err := config.SavePinned(f.h.Layout.PolicyPinned, q); err != nil {
			t.Fatal(err)
		}
		want(t, f.run(), doctor.CheckPolicyTampered, doctor.Fail, "changed outside precinto")
		_ = name
	}
	// A vault of the pinned settings that config.toml no longer lists (a
	// pending removal) is pending-policy's, named by its folder, never by
	// its vault id (U6-1); the copy itself is well-formed.
	const oldID = "9f0e1d2c3b4a59687766554433221100"
	q := p
	q.Config = f.h.Cfg
	q.Config.Roots = append(append([]config.Root{}, f.h.Cfg.Roots...), config.Root{ID: oldID, Path: filepath.Join(f.h.HomeDir, "work", "old"), MD: config.MDLedger})
	q.MACs = map[string]string{"root-acme": mac, oldID: mac}
	if err := config.SavePinned(f.h.Layout.PolicyPinned, q); err != nil {
		t.Fatal(err)
	}
	fs = f.run()
	want(t, fs, doctor.CheckPolicyTampered, doctor.OK)
	want(t, fs, doctor.CheckPendingPolicy, doctor.Warn, "folder ~/work/old removed")
	for _, x := range fs {
		if strings.Contains(x.Message, oldID) {
			t.Errorf("a finding names the vault id: %+v", x)
		}
	}
	// A vault that does not exist (D91).
	opened := f.d.OpenVault
	f.d.OpenVault = func(id string) (*vault.Vault, error) {
		if id == oldID {
			return nil, os.ErrNotExist
		}
		return opened(id)
	}
	want(t, f.run(), doctor.CheckPolicyTampered, doctor.Fail, "a vault that does not exist")
	f.d.OpenVault = opened
	writeFile(t, f.h.Layout.PolicyPinned, `{"v":1,"unknown_key":true}`, 0o600)
	want(t, f.run(), doctor.CheckPolicyTampered, doctor.Fail, "cannot be read")
	none(t, f.run(), doctor.CheckPendingPolicy)

	// A FIFO at the pinned path never blocks doctor.
	os.Remove(f.h.Layout.PolicyPinned)
	if err := testkit.Mkfifo(f.h.Layout.PolicyPinned, 0o600); err != nil {
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
		m := vault.Meta{ID: id, RecoveryVerifiedAt: now}
		if id != "global" {
			m.LastAudit = now.Add(-time.Hour)
		}
		return &vault.Vault{Meta: m}, nil
	}
	want(t, f.run(), doctor.CheckPolicyTampered, doctor.Warn, "is missing although folders have been unlocked before")
	// The folders gone from config.toml too: the vaults on disk still
	// tell (D145).
	f.o.Cfg.Roots = nil
	none(t, f.run(), doctor.CheckPolicyTampered)
	if err := os.MkdirAll(filepath.Join(f.h.Layout.VaultsDir, "root-acme"), 0o700); err != nil {
		t.Fatal(err)
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

// TestHoldCapped is the doctor side of SEC-20 and D63: files a sweep keeps
// unsealed in a locked folder only because of weak evidence carry the
// PlaintextSummary reason hold-capped; doctor reports them per folder, and
// merges the agent's own hold-capped items.
func TestHoldCapped(t *testing.T) {
	f := newFixture(t)
	want(t, f.run(), doctor.CheckHoldCapped, doctor.OK)

	beta := f.h.Protect(t, "work/beta")
	f.o.Cfg = f.h.Cfg
	f.d.Plaintext = func(context.Context) ([]sweep.Plaintext, error) {
		return []sweep.Plaintext{
			{RootID: "root-acme", Files: 3, Bytes: 30, ByReason: map[string]int{doctor.CheckHoldCapped: 2, "restored": 1}},
			{RootID: beta.ID, Files: 1, Bytes: 10, ByReason: map[string]int{doctor.CheckHoldCapped: 1}},
		}, nil
	}
	fs := f.run()
	got := want(t, fs, doctor.CheckHoldCapped, doctor.Warn, "2 files of "+f.tilde(f.h.Root)+" stay unencrypted although the folder is locked", "weak signs")
	if !strings.HasSuffix(got.Fix, "precinto sweep") {
		t.Errorf("fix %q", got.Fix)
	}
	want(t, fs, doctor.CheckHoldCapped, doctor.Warn, "1 file of "+f.tilde(beta.Path)+" stays unencrypted")
	want(t, fs, doctor.CheckUnsealed, doctor.Warn, "3 files", "hold-capped 2") // still unencrypted plaintext

	// An unlocked folder has no hold cap yet (it needs a persistent
	// observer, DF-01); the agent's items are merged next to doctor's.
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) {
		return ipc.StatusResp{PID: 9, Vaults: []ipc.VaultStatus{{VaultID: beta.ID, State: "unlocked"}},
			Attention: []ipc.Attention{{Code: ipc.AttnHoldCapped, Folder: "~/work/acme", Count: 1}}}, nil
	}
	fs = f.run()
	want(t, fs, doctor.CheckHoldCapped, doctor.Warn, "2 files of "+f.tilde(f.h.Root))
	want(t, fs, doctor.CheckHoldCapped, doctor.Warn, "1 unit in ~/work/acme is kept unsealed only by weak signs of activity")
	for _, x := range of(fs, doctor.CheckHoldCapped) {
		if strings.Contains(x.Message, f.tilde(beta.Path)) {
			t.Errorf("an unlocked folder reported hold-capped: %q", x.Message)
		}
	}

	// The agent alone, with nothing held.
	f.d.Plaintext = func(context.Context) ([]sweep.Plaintext, error) { return nil, nil }
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) { return ipc.StatusResp{PID: 9}, nil }
	want(t, f.run(), doctor.CheckHoldCapped, doctor.OK)

	// Neither the scan nor the agent answered: nothing is claimed.
	f.d.Plaintext = func(context.Context) ([]sweep.Plaintext, error) { return nil, errors.New("scan failed") }
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) { return ipc.StatusResp{}, ipc.ErrNoDaemon }
	none(t, f.run(), doctor.CheckHoldCapped)
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

// An unreadable working directory counts as "may be inside" (D47, D52):
// the process is reported as ungated without a folder. An unreadable
// process table makes the local scan claim nothing.
func TestUngatedScanUnreadableProcessTable(t *testing.T) {
	f := newFixture(t)
	p := platform.ProcInfo{ID: platform.ProcID{PID: 6100, StartUS: now.Add(-time.Hour).UnixMicro()}, PPID: 1, Exe: "/opt/homebrew/bin/claude"}
	f.h.Procs.Add(p)
	f.h.Procs.SetCwd(p.ID.PID, f.h.Root)
	want(t, f.run(), doctor.CheckUngatedSession, doctor.Warn, "pid 6100", f.tilde(f.h.Root))
	f.h.Procs.SetErr(fakeplatform.OpCwd, errors.New("proc_pidinfo denied"))
	got := want(t, f.run(), doctor.CheckUngatedSession, doctor.Warn, "claude (pid 6100) runs without precinto's hooks and its working folder cannot be read")
	if strings.Contains(got.Message, f.tilde(f.h.Root)) || got.Fix != "quit it, or start it with: precinto run claude" {
		t.Errorf("finding %+v", got)
	}
	// No folder protects Claude Code: an unknown cwd cannot be in one.
	f.o.Cfg.Roots[0].Harnesses = []string{"codex"}
	none(t, f.run(), doctor.CheckUngatedSession, doctor.Warn)
	f.o.Cfg.Roots[0].Harnesses = nil
	f.h.Procs.SetErr(fakeplatform.OpCwd, nil)
	f.h.Procs.SetErr(fakeplatform.OpList, errors.New("sysctl failed"))
	none(t, f.run(), doctor.CheckUngatedSession, doctor.Warn)
}

// goneProcs reports one pid as exited at its cwd lookup (it ended between
// the listing and the lookup).
type goneProcs struct {
	*fakeplatform.Procs
	gone int
}

func (g goneProcs) Cwd(id platform.ProcID) (string, error) {
	if id.PID == g.gone {
		return "", platform.ErrNotSame
	}
	return g.Procs.Cwd(id)
}

// FX-G7sup-06: processes whose cwd is unknown ("" from the process table)
// are reported without a folder unless a hook recorded them; one that
// exited meanwhile is not reported at all.
func TestUngatedScanUnknownCwd(t *testing.T) {
	f := newFixture(t)
	old := now.Add(-time.Hour).UnixMicro()
	unknown := platform.ProcInfo{ID: platform.ProcID{PID: 6200, StartUS: old}, PPID: 1, Exe: "/opt/homebrew/bin/codex"}
	hooked := platform.ProcInfo{ID: platform.ProcID{PID: 6201, StartUS: old}, PPID: 1, Exe: "/opt/homebrew/bin/claude"}
	exited := platform.ProcInfo{ID: platform.ProcID{PID: 6202, StartUS: old}, PPID: 1, Exe: "/opt/homebrew/bin/claude"}
	for _, p := range []platform.ProcInfo{unknown, hooked, exited} {
		f.h.Procs.Add(p) // no SetCwd: the table cannot tell their cwd
	}
	f.o.Procs = goneProcs{Procs: f.h.Procs, gone: exited.ID.PID}
	mkdir(t, f.h.Layout.SessionsDir, 0o700)
	f.d.Sessions = func(h harness.ID) ([]ledger.Session, error) {
		if h == harness.ClaudeCode {
			return []ledger.Session{{Harness: "claude-code", SID: "00000000-0000-4000-8000-000000000003", CurrentProc: hooked.ID}}, nil
		}
		return nil, nil
	}
	fs := f.run()
	got := want(t, fs, doctor.CheckUngatedSession, doctor.Warn, "codex (pid 6200) runs without precinto's hooks and its working folder cannot be read")
	if got.Fix != "quit it, or start it with: precinto run codex" {
		t.Errorf("fix %q", got.Fix)
	}
	for _, x := range of(fs, doctor.CheckUngatedSession) {
		for _, pid := range []string{"6201", "6202"} {
			if strings.Contains(x.Message, "pid "+pid) {
				t.Errorf("pid %s reported: %q", pid, x.Message)
			}
		}
	}
}

// D148: an integrate stopped between the two renames that replace
// <base>/marketplace left the plugin Claude Code loads in place only under
// its hidden name: doctor fails it and names the command that puts it back.
func TestHiddenMarketplaceIsReported(t *testing.T) {
	f := newFixture(t)
	hidden := filepath.Join(f.h.Layout.Base, ".marketplace.old-0123456789ab", "plugin")
	if err := os.MkdirAll(hidden, 0o700); err != nil {
		t.Fatal(err)
	}
	got := want(t, f.run(), doctor.CheckInterrupted, doctor.Fail, "is missing after an interrupted precinto integrate")
	if got.Fix != "precinto integrate claude-code" {
		t.Errorf("fix %q", got.Fix)
	}
	// With the live tree in place the leftover is no finding.
	if err := os.MkdirAll(f.h.Layout.Marketplace, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, x := range f.run() {
		if x.Code == doctor.CheckInterrupted && strings.Contains(x.Message, "plugin folder") {
			t.Errorf("a live marketplace is reported: %+v", x)
		}
	}
}

// D145: doctor finds root vaults as the agent does, on disk, so a pin of
// a shape precinto never writes is forged even when config.toml names no
// folder any more (a forged pin that names folders, next to a config.toml
// emptied with it).
func TestPolicyTamperedSeesTheVaultsOnDisk(t *testing.T) {
	f := newFixture(t)
	f.o.Cfg.Roots = nil
	pinned := f.h.Cfg
	p := config.Pinned{Version: config.PinnedVersion, ConfirmedAt: now, Config: pinned, MACs: map[string]string{"global": strings.Repeat("ab", 32)}}
	if err := config.SavePinned(f.h.Layout.PolicyPinned, p); err != nil {
		t.Fatal(err)
	}
	// No vault on disk: no root vault, so the shape is not enforced.
	want(t, f.run(), doctor.CheckPolicyTampered, doctor.OK)
	if err := os.MkdirAll(filepath.Join(f.h.Layout.VaultsDir, "root-acme"), 0o700); err != nil {
		t.Fatal(err)
	}
	want(t, f.run(), doctor.CheckPolicyTampered, doctor.Fail, "names folders but carries no MAC of theirs")
}

// D145 (S6-1): settings that name no folder are signed by the global vault
// alone, and only precinto unlock --global checks that MAC. When folders
// whose vault is kept are protected by nothing then — every folder dropped
// from config.toml next to such a pin, or folders the user stopped
// protecting (D74) — doctor names them and the command that checks the
// settings, as a warning (never a failure: unprotecting is legitimate).
func TestUnprotectedFoldersAreNamed(t *testing.T) {
	f := newFixture(t)
	acme, beta := f.h.Root, filepath.Join(f.h.HomeDir, "work", "beta")
	f.d.OpenVault = func(id string) (*vault.Vault, error) {
		m := vault.Meta{ID: id, RecoveryVerifiedAt: now.Add(-time.Hour), Factors: []vault.Factor{{Name: "se", Kind: vault.FactorSE}}}
		switch id {
		case "root-acme":
			m.RootPath = acme
		case "root-beta":
			m.RootPath = beta
		}
		return &vault.Vault{Meta: m}, nil
	}
	for _, id := range []string{"global", "root-acme", "root-beta"} {
		if err := os.MkdirAll(filepath.Join(f.h.Layout.VaultsDir, id), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	pin := func(c config.Config, macs map[string]string) {
		t.Helper()
		if err := config.SavePinned(f.h.Layout.PolicyPinned, config.Pinned{Version: config.PinnedVersion, ConfirmedAt: now, Config: c, MACs: macs}); err != nil {
			t.Fatal(err)
		}
	}
	mac := strings.Repeat("ab", 32)
	// A pin that names a folder: that folder's next unlock checks it.
	pin(f.h.Cfg, map[string]string{"root-acme": mac})
	want(t, f.run(), doctor.CheckUnprotectedFolders, doctor.OK, "whose next unlock checks them")

	// Every folder dropped, from config.toml and from a pin that keeps
	// only a "global" MAC.
	empty := f.h.Cfg
	empty.Roots = nil
	f.o.Cfg = empty
	pin(empty, map[string]string{"global": mac})
	got := want(t, f.run(), doctor.CheckUnprotectedFolders, doctor.Warn, "protect no folder", "2 folders", "~/work/acme", "~/work/beta")
	if got.Fix != "precinto unlock --global (in a terminal)" {
		t.Errorf("fix %q", got.Fix)
	}
	// config.toml still protects one of them: only the other is named.
	f.o.Cfg = f.h.Cfg
	got = want(t, f.run(), doctor.CheckUnprotectedFolders, doctor.Warn, "1 folder", "~/work/beta")
	if strings.Contains(got.Message, "~/work/acme") {
		t.Errorf("a protected folder is named: %q", got.Message)
	}
	// A folder the agent enforces (it found the settings tampered) is
	// protected.
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) {
		return ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-beta", RootPath: beta, State: "locked"}}}, nil
	}
	want(t, f.run(), doctor.CheckUnprotectedFolders, doctor.OK, "left without protection")
}
