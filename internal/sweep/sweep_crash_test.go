//go:build failpoints

package sweep

// The crash-injection matrix of docs/TESTPLAN.md §4 for internal/sweep:
// the same test binary is re-run as a child on the parent's fake home,
// with a failpoint (or, where the registry has no name, a test seam)
// armed to SIGKILL it; the parent then recovers keylessly and checks
// O1 (no loss), O4 (dwell), O5 (no clobber), O6 (idempotent recovery)
// and O7 (no false alert), plus each row's expectation.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx/failpoint"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/testkit"
)

func kill() {
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	select {}
}

// arm arms a failpoint spec or a test seam ("hook:<name>").
func arm(te *testEnv, spec string) {
	switch spec {
	case "hook:afterRename":
		te.p.afterRename = kill
	case "hook:afterLog":
		te.p.afterLog = kill
	case "hook:midTmp":
		te.codec.midTmp = kill
	case "hook:extract":
		te.codec.duringExtract = func(n int) {
			if n == 2 {
				kill()
			}
		}
	default:
		failpoint.Set(spec)
	}
}

// crashCase runs act in a child killed at spec, then check in the parent.
func crashCase(t *testing.T, spec string, setup, act, check func(te *testEnv)) {
	if dir := os.Getenv("SWEEP_CRASH_DIR"); dir != "" {
		if os.Getenv("SWEEP_CRASH_TEST") != t.Name() {
			t.Skip("another crash case")
		}
		te := newTestEnvWith(t, homeAt(t, dir, os.Getenv("SWEEP_CRASH_RUN")))
		arm(te, spec)
		act(te)
		os.Exit(7) // the point was never reached
	}
	te := newTestEnv(t)
	setup(te)
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), "SWEEP_CRASH_DIR="+te.h.Dir, "SWEEP_CRASH_RUN="+te.h.RunDir, "SWEEP_CRASH_TEST="+t.Name())
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("child was not killed (%v):\n%s", err, out)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("child status %v, want SIGKILL:\n%s", ee, out)
	}
	check(te)
}

// Shared bodies.

func sessionSetup(te *testEnv) { te.writeSession(sid1, "", nil) }

func sealAct(te *testEnv) {
	te.claude.sids = []string{sid1}
	u := te.scanSession(sid1)
	te.run().sealCommand(context.Background(), []harness.Unit{u}, Options{})
}

// unitFiles is the plaintext of the session before the crash.
type crashState struct {
	u    harness.Unit
	orig map[string][]byte
}

func capture(te *testEnv) crashState {
	te.claude.sids = []string{sid1}
	u := te.scanSession(sid1)
	return crashState{u: u, orig: te.original(u)}
}

// rolledBack: recovery kept every byte of plaintext and the next seal
// works under a fresh number (gaps allowed).
func rolledBack(t *testing.T, te *testEnv, st crashState) {
	te.checkRecovered()
	te.plaintextIntact(st.orig)
	for _, name := range te.unitDirEntries(st.u.Key) {
		if isOpDir(name) {
			t.Fatalf("operation directory left: %s", name)
		}
		if _, err := te.e.Log.Lookup("claude-code/"+st.u.Key+"/"+name, ""); err == nil {
			t.Fatalf("an unlogged capsule %s left", name)
		}
	}
	rep, _ := te.run().sealCommand(context.Background(), []harness.Unit{te.scanSession(sid1)}, Options{})
	if res := outcome(t, rep, st.u.Key); res.Outcome != OutSealed {
		t.Fatalf("seal after recovery %+v", res)
	}
	te.plaintextGone(st.u)
}

// rolledForward: recovery finished the seal (plaintext gone, one
// generation logged, restorable to the original bytes).
func rolledForward(t *testing.T, te *testEnv, st crashState) {
	te.checkRecovered()
	te.plaintextGone(st.u)
	if n := len(te.logged(st.u.Key)); n != 1 {
		t.Fatalf("%d log entries, want exactly one", n)
	}
	te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(st.u)}})
	te.plaintextIntact(st.orig)
}

func sealCrash(t *testing.T, spec string, forward bool) {
	var st crashState
	crashCase(t, spec, func(te *testEnv) {
		sessionSetup(te)
		st = capture(te)
	}, sealAct, func(te *testEnv) {
		if forward {
			rolledForward(t, te, st)
		} else {
			rolledBack(t, te, st)
		}
	})
}

// SEAL-1: SIGKILL after prepared.
func TestCrashSEAL1AfterPrepared(t *testing.T) { sealCrash(t, "seal.prepared", false) }

// SEAL-2: SIGKILL at 50 % of the temporary write.
func TestCrashSEAL2MidTemporary(t *testing.T) { sealCrash(t, "hook:midTmp", false) }

// SEAL-3: SIGKILL after the temporary is FullSynced, before verify.
func TestCrashSEAL3AfterTmpWritten(t *testing.T) { sealCrash(t, "seal.tmp_written", false) }

// SEAL-6: SIGKILL after the no-replace rename, before the log append.
func TestCrashSEAL6AfterRename(t *testing.T) { sealCrash(t, "hook:afterRename", false) }

// SEAL-7: SIGKILL after the log append, before committed is journaled.
func TestCrashSEAL7AfterLogAppend(t *testing.T) { sealCrash(t, "hook:afterLog", true) }

// SEAL-8: SIGKILL after committed, before the first unlink.
func TestCrashSEAL8AfterCommitted(t *testing.T) { sealCrash(t, "seal.committed", true) }

// SEAL-9: SIGKILL after 3 of N unlinks.
func TestCrashSEAL9MidUnlink(t *testing.T) { sealCrash(t, "seal.unlinking:3", true) }

// After the receipt step, before the record is done.
func TestCrashSealAfterReceipt(t *testing.T) { sealCrash(t, "seal.receipt", true) }

// journal.save: SIGKILL before the record write that names the capsule
// (the second write of the seal): nothing was written yet.
func TestCrashSealJournalSave(t *testing.T) { sealCrash(t, "journal.save:2", false) }

// SEAL-8 with a file changed after the crash: only identity-matching
// files are unlinked; the changed one stays for the next generation.
func TestCrashSEAL8ChangedFileStays(t *testing.T) {
	var st crashState
	crashCase(t, "seal.committed", func(te *testEnv) {
		sessionSetup(te)
		st = capture(te)
	}, sealAct, func(te *testEnv) {
		var changed string
		for p := range st.orig {
			changed = p
			break
		}
		mustNoErr(t, os.WriteFile(changed, []byte("written after the crash\n"), 0o600))
		te.checkRecovered()
		if string(readFile(t, changed)) != "written after the crash\n" {
			t.Fatal("I3: a file changed after hashing was deleted")
		}
		for p := range st.orig {
			if p != changed && exists(p) {
				t.Fatalf("%s left", filepath.Base(p))
			}
		}
	})
}

// seal.rescue: SIGKILL right after the rescue milestone: the main
// generation stands, the rescue capsule is handled as tmp_written.
func TestCrashSealRescue(t *testing.T) {
	var st crashState
	crashCase(t, "seal.rescue", func(te *testEnv) {
		sessionSetup(te)
		st = capture(te)
	}, func(te *testEnv) {
		te.claude.sids = []string{sid1}
		u := te.scanSession(sid1)
		w, err := os.OpenFile(transcriptOf(u), os.O_WRONLY|os.O_APPEND, 0)
		mustNoErr(t, err)
		te.p.sleep = func(ctx context.Context, d time.Duration) error {
			_, _ = w.WriteString(`{"uuid":"00000000-0000-4000-8000-00000000dddd"}` + "\n")
			return nil
		}
		te.run().sealCommand(context.Background(), []harness.Unit{u}, Options{})
	}, func(te *testEnv) {
		te.checkRecovered()
		te.plaintextGone(st.u)
		en := te.logged(st.u.Key)
		if len(en) != 1 || en[0].Gen != 1 {
			t.Fatalf("log after a rescue crash %+v", en)
		}
		te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(st.u)}})
		te.plaintextIntact(st.orig)
	})
}

// restore crash cases.

func restoreSetup(st *crashState) func(te *testEnv) {
	return func(te *testEnv) {
		u, orig := te.sealedSession(sid1, nil)
		*st = crashState{u: u, orig: orig}
	}
}

func restoreAct(te *testEnv) {
	te.claude.sids = []string{sid1}
	key := te.sessionKey(sid1)
	te.run().restore(context.Background(), te.keys, RestoreRequest{Units: []harness.UnitRef{{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeSession, Key: key}}})
}

// REST-1: SIGKILL during staging decrypt: nothing placed.
func TestCrashREST1DuringStaging(t *testing.T) {
	var st crashState
	crashCase(t, "hook:extract", restoreSetup(&st), restoreAct, func(te *testEnv) {
		te.checkRecovered()
		for p := range st.orig {
			if exists(p) {
				t.Fatalf("placed: %s", filepath.Base(p))
			}
		}
		if ents, _ := os.ReadDir(te.h.Layout.StagingDir); len(ents) != 0 {
			t.Fatal("staging left")
		}
	})
}

func restoredForward(t *testing.T, te *testEnv, st crashState) {
	rep := te.checkRecovered()
	if res := outcome(t, rep, st.u.Key); res.Outcome != OutRestored {
		t.Fatalf("roll forward %+v", res)
	}
	te.plaintextIntact(st.orig)
	if ents, _ := os.ReadDir(te.h.Layout.StagingDir); len(ents) != 0 {
		t.Fatal("staging left")
	}
	// The unit re-seals as unchanged (the receipt survived recovery).
	rep, _ = te.run().sealCommand(context.Background(), []harness.Unit{te.scanSession(sid1)}, Options{})
	if res := outcome(t, rep, st.u.Key); res.Outcome != OutUnchanged {
		t.Fatalf("re-seal after a rolled-forward restore %+v", res)
	}
}

// SIGKILL after staged: roll forward from staging.
func TestCrashRestoreAfterStaged(t *testing.T) {
	var st crashState
	crashCase(t, "restore.staged", restoreSetup(&st), restoreAct, func(te *testEnv) {
		if exists(transcriptOf(st.u)) {
			t.Fatal("placed before the crash point")
		}
		restoredForward(t, te, st)
	})
}

// REST-3: SIGKILL after staged with 3 of N placed: roll forward,
// <sid>.jsonl last.
func TestCrashREST3MidPlacing(t *testing.T) {
	var st crashState
	crashCase(t, "restore.placing:3", restoreSetup(&st), restoreAct, func(te *testEnv) {
		if exists(transcriptOf(st.u)) {
			t.Fatal("the transcript was placed before the others")
		}
		restoredForward(t, te, st)
	})
}

// After the receipt, before staging removal and done.
func TestCrashRestoreAfterReceipt(t *testing.T) {
	var st crashState
	crashCase(t, "restore.receipt", restoreSetup(&st), restoreAct, func(te *testEnv) {
		restoredForward(t, te, st)
	})
}

// history crash cases.

func historySetup(te *testEnv) {
	var lines []string
	for i := 0; i < 6; i++ {
		lines = append(lines, historyLineFor(te.h.Root, "root "+itoa(i), int64(i), ""), historyLineFor("/elsewhere", "other "+itoa(i), int64(i), ""))
	}
	appendLines(te.t, te.historyPath(), lines...)
}

func historyAct(te *testEnv) { te.run().rotateHistory(context.Background()) }

// historyCheck: after recovery every line is exactly once in history.jsonl
// or a generation, protected lines only in generations (no duplicates
// appended, nothing lost).
func historyCheck(t *testing.T, te *testEnv, all []string) {
	te.checkRecovered()
	inFile := map[string]int{}
	for _, l := range te.historyLines() {
		inFile[l]++
	}
	sealed := map[string]bool{}
	for _, l := range te.sealedHistory() {
		sealed[l] = true
	}
	for _, l := range all {
		if testHistoryLine([]byte(l)).Project == te.h.Root {
			if inFile[l] != 0 || !sealed[l] {
				t.Fatalf("protected line: in file %d, sealed %v", inFile[l], sealed[l])
			}
		} else if inFile[l] != 1 || sealed[l] {
			t.Fatalf("kept line: in file %d times, sealed %v", inFile[l], sealed[l])
		}
	}
	if holds, _ := filepath.Glob(filepath.Join(te.h.ClaudeConfig, ".precinto-hold-*")); len(holds) != 0 {
		t.Fatalf("hold left %v", holds)
	}
}

func historyCrash(t *testing.T, spec string, tail bool) {
	var all []string
	crashCase(t, spec, func(te *testEnv) {
		historySetup(te)
		all = te.historyLines()
	}, func(te *testEnv) {
		if tail {
			// A writer with the file open before the rename appends to the
			// hold inode, which the tail loop processes.
			f, err := os.OpenFile(te.historyPath(), os.O_WRONLY|os.O_APPEND, 0)
			mustNoErr(t, err)
			wrote := false
			te.p.sleep = func(ctx context.Context, d time.Duration) error {
				if !wrote {
					wrote = true
					_, _ = f.WriteString(historyLineFor(te.h.Root, "late root", 50, "") + "\n" + historyLineFor("/elsewhere", "late other", 51, "") + "\n")
				}
				return nil
			}
		}
		historyAct(te)
	}, func(te *testEnv) {
		if tail {
			all = append(all, historyLineFor(te.h.Root, "late root", 50, ""), historyLineFor("/elsewhere", "late other", 51, ""))
		}
		historyCheck(t, te, all)
	})
}

// SIGKILL after the hold link (held): redo from step 3.
func TestCrashHistoryAfterHeld(t *testing.T) { historyCrash(t, "history.held", false) }

// HIST-2: SIGKILL after the generations commit, before the rename.
func TestCrashHIST2AfterSealed(t *testing.T) { historyCrash(t, "history.sealed", false) }

// HIST-3: SIGKILL after the rename, before rewritten is journaled.
func TestCrashHIST3AfterRename(t *testing.T) { historyCrash(t, "history.renamed", false) }

// HIST-4: SIGKILL in the tail loop after the append, before the offset.
func TestCrashHIST4InTail(t *testing.T) { historyCrash(t, "history.tail", true) }

// codex crash cases.

// CODX-1: SIGKILL between blob writes, before the manifest rename: the
// previous snapshot stays authoritative, orphan blobs are collected,
// plaintext is intact.
func TestCrashCODX1BetweenBlobs(t *testing.T) {
	var orig map[string][]byte
	crashCase(t, "codex.blob:2", func(te *testEnv) {
		home := te.codexHome(t)
		orig = map[string][]byte{}
		for _, p := range listFiles(t, home) {
			orig[p] = readFile(t, p)
		}
	}, func(te *testEnv) {
		te.useCodex(t)
		u := te.codexUnit(t)
		te.run().sealCommand(context.Background(), []harness.Unit{u}, Options{})
	}, func(te *testEnv) {
		te.useCodex(t)
		te.checkRecovered()
		for p, b := range orig {
			if !bytes.Equal(readFile(t, p), b) {
				t.Fatalf("plaintext %s changed", filepath.Base(p))
			}
		}
		u := te.codexUnit(t)
		for _, en := range te.allLogged() {
			if en.Blob {
				t.Fatalf("orphan blob %s still logged", en.Unit)
			}
		}
		if len(te.logged(u.Key)) != 0 {
			t.Fatal("a snapshot was committed")
		}
	})
}

// SIGKILL right before the manifest rename (codex.manifest).
func TestCrashCodexBeforeManifestRename(t *testing.T) {
	crashCase(t, "codex.manifest", func(te *testEnv) { te.codexHome(t) }, func(te *testEnv) {
		te.useCodex(t)
		te.run().sealCommand(context.Background(), []harness.Unit{te.codexUnit(t)}, Options{})
	}, func(te *testEnv) {
		te.useCodex(t)
		te.checkRecovered()
		if n := len(te.logged(te.codexUnit(t).Key)); n != 0 {
			t.Fatalf("%d snapshots logged", n)
		}
		for _, en := range te.allLogged() {
			if en.Blob {
				t.Fatal("orphan blob left")
			}
		}
	})
}

// Ensure the crash matrix helpers compile in this build only.
var _ = claudetest.Session{}
var _ = testkit.Epoch
