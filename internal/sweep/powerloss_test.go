//go:build failpoints

package sweep

// Power-loss mode of the crash matrix (docs/TESTPLAN.md §4, CC-27,
// FX-G4-12): a run on the real file system (fsx) is frozen in-process at a
// crash point while fsxtest records every mutating fsx operation; each
// power-loss image of the fake home — only what was durable, everything,
// and random dependency-closed subsets of the rest — is copied over the
// home, and recovery plus one more run must satisfy O1 (no loss), O4
// (dwell), O5 (no clobber), O6 (idempotent recovery) and O7 (no false
// alert) on every image. Images are new files, so every recorded identity
// differs: recovery keeps plaintext whose identity it cannot prove, and
// the next run seals it. The recorder sees every fsx operation of the
// process, so the rows never run in parallel (sequential tests finish
// before any parallel one starts). The recorder is fsxtest's (CC-27): it
// reads the synced files of O_WRONLY descriptors (the journal, receipts,
// counters and capsule log) through a read-only reopen of the same inode.

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/fsx/fsxtest"
	"github.com/Neorichi/precinto/internal/harness"
)

// imagesPerRow bounds the images each row checks (strict, full and random
// subsets of the non-durable operations).
const imagesPerRow = 4

// powerLoss runs act on te over the real file system until it reaches
// point for the n-th time, freezes it there and returns the power-loss
// images of te's home taken at that instant: the durable state first, then
// the full state and random states between them, duplicates dropped (one
// image when everything was durable). The frozen run is released (its
// goroutine exits) when the test ends, before the home is removed.
func powerLoss(t *testing.T, te *testEnv, point string, n int, act func(te *testEnv)) []string {
	t.Helper()
	rec := fsxtest.Record(t)
	reached, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	hits := 0
	te.p.point = func(name string) {
		if name != point {
			return
		}
		mu.Lock()
		hits++
		stop := hits == n
		mu.Unlock()
		if !stop {
			return
		}
		close(reached)
		<-release
		runtime.Goexit() // the process "lost power": nothing after the point runs
	}
	go func() {
		defer close(finished)
		act(te)
	}()
	select {
	case <-reached:
	case <-finished:
		t.Fatalf("the run never reached %s:%d", point, n)
	case <-time.After(time.Minute):
		t.Fatalf("the run did not reach %s:%d within a minute", point, n)
	}
	images := rec.Images(t, te.h.Dir, imagesPerRow)
	if len(images) == 0 {
		t.Fatal("no power-loss image")
	}
	t.Cleanup(func() {
		close(release)
		select {
		case <-finished:
		case <-time.After(time.Minute):
			t.Error("the frozen run did not end")
		}
	})
	te.p.point = nil
	return images
}

// useImage replaces te's home with image (fresh inodes, same paths).
func useImage(t *testing.T, te *testEnv, image string) {
	t.Helper()
	ents, err := os.ReadDir(te.h.Dir)
	mustNoErr(t, err)
	for _, e := range ents {
		p := filepath.Join(te.h.Dir, e.Name())
		_ = filepath.WalkDir(p, func(q string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(q, 0o700)
			}
			return nil
		})
		mustNoErr(t, os.RemoveAll(p))
	}
	err = filepath.WalkDir(image, func(src string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(image, src)
		if err != nil || rel == "." {
			return err
		}
		dst := filepath.Join(te.h.Dir, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.Mkdir(dst, 0o700)
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(src)
			if err != nil {
				return err
			}
			return os.Symlink(target, dst)
		default:
			b, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			return os.WriteFile(dst, b, info.Mode().Perm()&0o700|0o600)
		}
	})
	mustNoErr(t, err)
}

// powerEnv is a test env whose file operations are the real fsx ones
// (fsxtest sees only those).
func powerEnv(t *testing.T) *testEnv {
	te := newTestEnv(t)
	te.p.fs = fsxFS{}
	return te
}

// noLoss is O1/O5 for one session after recovery and one seal: no
// plaintext of it is left (O4), and restoring its generations brings back
// every original byte.
func noLoss(t *testing.T, te *testEnv, st crashState, image string) {
	t.Helper()
	te.checkRecovered()
	if u, ok := te.claude.sessionUnit(te.cc, sid1); ok {
		rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
		if res := outcome(t, rep, u.Key); res.Outcome != OutSealed && res.Outcome != OutUnchanged {
			t.Fatalf("%s: seal after recovery %+v", filepath.Base(image), res)
		}
	}
	te.plaintextGone(st.u)
	te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(st.u)}})
	for p, b := range st.orig {
		if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, b) {
			t.Fatalf("%s: O1: %s not recoverable", filepath.Base(image), filepath.Base(p))
		}
	}
}

// sealPowerLoss is one seal row: freeze the seal at point, then check
// every image. want lists the capsule-directory entries the full image
// (the state at the crash point) holds.
func sealPowerLoss(t *testing.T, point string, want ...string) {
	te := powerEnv(t)
	te.writeSession(sid1, "", nil)
	st := capture(te)
	images := powerLoss(t, te, point, 1, func(te *testEnv) {
		te.run().sealCommand(tctx(t), []harness.Unit{st.u}, Options{})
	})
	full := images[min(1, len(images)-1)]
	ents, _ := os.ReadDir(filepath.Join(full, "base", "capsules", "claude-code", st.u.Key))
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
	}
	if !sameSet(got, want) {
		t.Fatalf("crash state at %s: capsule directory %v, want %v", point, got, want)
	}
	for _, img := range images {
		useImage(t, te, img)
		noLoss(t, te, st, img)
	}
}

// SEAL-3: power loss after the temporary is FullSynced, before verify.
func TestPowerLossSEAL3AfterTmpWritten(t *testing.T) {
	sealPowerLoss(t, "seal.tmp_written", ".g000001.pcap.tmp")
}

// SEAL-6: power loss after the no-replace rename, before the log append.
func TestPowerLossSEAL6AfterRename(t *testing.T) {
	sealPowerLoss(t, "capsule.committed", "g000001.pcap")
}

// SEAL-8: power loss after committed, before the first unlink.
func TestPowerLossSEAL8AfterCommitted(t *testing.T) {
	sealPowerLoss(t, "seal.committed", "g000001.pcap")
}

// REST-3: power loss after staged with 3 of N placed: every image rolls
// forward to the exact unit (the transcript last), or keeps nothing
// half-placed.
func TestPowerLossREST3MidPlacing(t *testing.T) {
	te := powerEnv(t)
	u, orig := te.sealedSession(sid1, nil)
	images := powerLoss(t, te, "restore.placing", 3, func(te *testEnv) {
		te.run().restore(tctx(t), te.keys, RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	})
	for _, img := range images {
		useImage(t, te, img)
		te.checkRecovered()
		for p, b := range orig {
			if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, b) {
				t.Fatalf("%s: %s not rolled forward exactly", filepath.Base(img), filepath.Base(p))
			}
		}
		if ents, _ := os.ReadDir(te.h.Layout.StagingDir); len(ents) != 0 {
			t.Fatalf("%s: staging left", filepath.Base(img))
		}
		// The unit re-seals (O4) and its generations still restore it (O1).
		if res := outcome(t, mustSeal(t, te), u.Key); res.Outcome != OutSealed && res.Outcome != OutUnchanged {
			t.Fatalf("%s: re-seal %+v", filepath.Base(img), res)
		}
		te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
		te.plaintextIntact(orig)
	}
}

func mustSeal(t *testing.T, te *testEnv) *Report {
	t.Helper()
	rep, err := te.run().sealCommand(tctx(t), []harness.Unit{te.scanSession(sid1)}, Options{})
	mustNoErr(t, err)
	return rep
}

// historyPowerLoss is one history row: freeze the rotation at point, then
// on every image recovery plus one rotation leaves every line exactly once
// in history.jsonl or a generation, protected lines only in generations.
// (Images write the hold link as a file of its own, so recovery may take
// the rewrite for done: the next rotation then extracts what was left.)
func historyPowerLoss(t *testing.T, point string) {
	te := powerEnv(t)
	historySetup(te)
	all := te.historyLines()
	images := powerLoss(t, te, point, 1, func(te *testEnv) { te.run().rotateHistory(tctx(t)) })
	for _, img := range images {
		useImage(t, te, img)
		te.checkRecovered()
		te.run().rotateHistory(tctx(t))
		historyCheck(t, te, all)
		for _, l := range te.historyLines() {
			if testHistoryLine([]byte(l)).Project == te.h.Root {
				t.Fatalf("%s: a protected line stayed in history.jsonl", filepath.Base(img))
			}
		}
	}
}

// HIST-2: power loss after the history generations commit, before the
// rename.
func TestPowerLossHIST2AfterSealed(t *testing.T) { historyPowerLoss(t, "history.sealed") }

// HIST-3: power loss after the rename, before rewritten is journaled.
func TestPowerLossHIST3AfterRename(t *testing.T) { historyPowerLoss(t, "history.renamed") }
