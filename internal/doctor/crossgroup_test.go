//go:build crossgroup

package doctor_test

// Tests against the real implementations of the other groups (vault,
// capslog, journal, queue, ledger, sweep, harness adapters, ipc and the
// in-process agent). They compile in every tree (go vet -tags
// testing,crossgroup) and pass once those packages are integrated. The OS
// facilities stay faked: they run system tools (fdesetup, mdfind, tmutil)
// or the user's login shell, which tests never do.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/agent/agenttest"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/harness/codex/codextest"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

// realDeps are the production dependencies of the fixture with the OS
// facilities replaced by the fakes of safeDeps.
func realDeps(f *fixture) *doctor.Deps {
	d := doctor.DefaultDeps(f.o)
	safe := safeDeps(time.Now())
	d.DiskEncryption = safe.DiskEncryption
	d.CloudSynced = safe.CloudSynced
	d.SpotlightIndexed = safe.SpotlightIndexed
	d.BackupExcluded = safe.BackupExcluded
	d.Executable = safe.Executable
	d.SystemBins = nil
	d.RunShell = safe.RunShell
	return d
}

// TestCrossgroupVaultTripwire is the doctor side of SEC-9: a recovery
// recipient swapped in vault.toml while locked trips the verified copy, and
// doctor reports vault-tampered naming `precinto vault repair`.
func TestCrossgroupVaultTripwire(t *testing.T) {
	f := newFixture(t)
	fx := vaulttest.New(t, f.h.Base, "root-acme")
	f.d = realDeps(f)
	want(t, f.run(), doctor.CheckVaultTampered, doctor.OK)

	fx.TamperRecipient(t, "root-acme", true)
	got := want(t, f.run(), doctor.CheckVaultTampered, doctor.Fail, f.tilde(f.h.Root)+"'s vault file was changed outside precinto")
	if got.Fix != "precinto vault repair --root "+f.tilde(f.h.Root) {
		t.Errorf("fix %q", got.Fix)
	}
	// vaulttest wraps with a weak scrypt work factor for speed: reported.
	want(t, f.run(), doctor.CheckPassphraseFactor, doctor.Warn, "work factor below the minimum")
}

// TestCrossgroupUnloggedCapsule: a capsule planted in the store without a
// provenance entry is reported (SEC-1, D8); one named by a pending journal
// record is not (O7).
func TestCrossgroupUnloggedCapsule(t *testing.T) {
	f := newFixture(t)
	vaulttest.New(t, f.h.Base, "root-acme")
	f.d = realDeps(f)
	if err := capslog.Open(f.h.Layout.CapsuleLog).Append(capslog.Entry{V: capslog.Version, Path: "claude-code/" + unitB + "/g000001.pcap",
		Unit: unitB, Harness: "claude-code", Kind: "claude-session", VaultID: "root-acme", Gen: 1, SealedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	f.capsuleFile("claude-code/" + unitA + "/g000001.pcap")
	want(t, f.run(), doctor.CheckQuarantine, doctor.Warn, "1 file in the capsule store are not in the provenance log")

	if _, err := journal.Open(f.h.Layout.JournalDir).Begin(journal.KindSeal, "claude-code", unitA); err != nil {
		t.Fatal(err)
	}
	none(t, f.run(), doctor.CheckQuarantine, doctor.Warn, doctor.Fail)
}

// TestCrossgroupHistoryAndWrongHome: the adapters' real parsers on the
// synthetic Claude history and Codex homes.
func TestCrossgroupHistoryAndWrongHome(t *testing.T) {
	f := newFixture(t)
	vaulttest.New(t, f.h.Base, "root-acme")
	marker := testkit.Marker(t)
	f.secret(marker)
	l := claudetest.New(t, f.h.Dir)
	l.WriteHistory(t, f.h.Root, "00000000-0000-4000-8000-000000000001", 2, marker)
	f.userCodexHome(1)
	f.d = realDeps(f)
	fs := f.run()
	want(t, fs, doctor.CheckHistoryPending, doctor.Warn, "2 lines of Claude's prompt history")
	want(t, fs, doctor.CheckCodexWrongHome, doctor.Warn, "1 Codex conversation(s) from")
	// A fresh codextest home has no precinto trust entry.
	for _, x := range of(fs, doctor.CheckCodexHooksTrust) {
		if x.Severity == doctor.OK {
			t.Errorf("untrusted synthetic home reported trusted: %q", x.Message)
		}
	}
}

// TestCrossgroupSettingsDrift uses the adapter's own settings JSON.
func TestCrossgroupSettingsDrift(t *testing.T) {
	f := newFixture(t)
	vaulttest.New(t, f.h.Base, "root-acme")
	f.d = realDeps(f)
	f.o.Cfg.Roots[0].ClaudeSettings = true
	writeFile(t, filepath.Join(f.h.Root, ".claude", "settings.json"), `{"idleCompaction":true}`, 0o644)
	want(t, f.run(), doctor.CheckClaudeSettings, doctor.Warn, "were changed")
}

// TestCrossgroupAgentStatus: doctor asks the real (in-process) agent for
// its status without starting one, and reports it reachable.
func TestCrossgroupAgentStatus(t *testing.T) {
	f := newFixture(t)
	vaulttest.New(t, f.h.Base, "root-acme")
	a := agenttest.Start(t, f.h.Layout, f.h.Clock, f.h.Procs)
	defer a.Stop()
	f.d = realDeps(f)
	fs := f.run()
	none(t, fs, doctor.CheckServiceRunning, doctor.Fail)
	want(t, fs, doctor.CheckUngatedSession, doctor.OK)
}

// TestCrossgroupReadOnly runs every real dependency over a populated fake
// home and requires the tree unchanged (no salt, lock, lease or log file
// created by a dependency either).
func TestCrossgroupReadOnly(t *testing.T) {
	f := newFixture(t)
	vaulttest.New(t, f.h.Base, "root-acme")
	marker := testkit.Marker(t)
	f.secret(marker)
	l := claudetest.New(t, f.h.Dir)
	l.WriteSession(t, claudetest.Session{SID: "00000000-0000-4000-8000-000000000001", Cwd: f.h.Root, Lines: 3, Marker: marker})
	l.WriteHistory(t, f.h.Root, "00000000-0000-4000-8000-000000000001", 2, marker)
	codextest.New(t, f.h.Layout.CodexHome("root-acme"), codextest.Options{Rollouts: 1, Marker: marker})
	f.d = realDeps(f)
	f.o.Leaks = true
	before := snapshot(t, f.h.Dir, f.h.RunDir)
	f.run()
	after := snapshot(t, f.h.Dir, f.h.RunDir)
	for p, d := range before {
		if after[p] != d {
			t.Errorf("changed or removed: %s", p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("created: %s", p)
		}
	}
}
