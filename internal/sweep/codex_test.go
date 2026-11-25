package sweep

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/harness/codex/codextest"
	"github.com/Neorichi/precinto/internal/live"
	"github.com/Neorichi/precinto/internal/sweep/capslog"
	"github.com/Neorichi/precinto/internal/testkit"
)

func (te *testEnv) codexHomeDir() string { return te.h.Layout.CodexHome(rootID) }

// codexHome writes a synthetic per-root Codex home (with a WAL) and
// registers the fake Codex adapter.
func (te *testEnv) codexHome(t *testing.T) string {
	t.Helper()
	home := te.codexHomeDir()
	mustNoErr(t, os.MkdirAll(filepath.Dir(home), 0o700))
	codextest.New(t, home, codextest.Options{Rollouts: 3, WithWAL: true, Marker: testkit.Marker(t)})
	te.useCodex(t)
	return home
}

func (te *testEnv) useCodex(t *testing.T) {
	if te.codexAd != nil {
		return
	}
	home := te.codexHomeDir()
	te.codexAd = &fakeAdapter{te: te, id: harness.Codex, codex: map[string]string{rootID: home},
		probe: map[string][]live.Evidence{}, mdPaths: map[string][]string{},
		homes: []harness.Home{{Harness: harness.Codex, ID: "c0dec0dec0dec0de", RootID: rootID,
			Bases: map[capsule.BaseID]string{capsule.BaseCodexHome: home}}}}
	te.e.Adapters = append(te.e.Adapters, te.codexAd)
}

func (te *testEnv) codexUnit(t *testing.T) harness.Unit {
	t.Helper()
	u, ok := te.codexAd.codexUnit(rootID, te.codexHomeDir())
	if !ok {
		t.Fatal("no Codex plaintext")
	}
	return u
}

func (te *testEnv) codexKey() string {
	k, err := harness.UnitKeyFor(te.e.Harness.Salt, capsule.KindCodexHome, harness.Codex, "", rootID, "")
	mustNoErr(te.t, err)
	return k
}

func (te *testEnv) allLogged() []capslog.Entry {
	en, err := te.e.Log.All()
	mustNoErr(te.t, err)
	return en
}

// listFiles lists the content files of a Codex home (never-touch and
// -shm files excluded).
func listFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if codexNeverTouch(rel) || strings.HasSuffix(rel, "-shm") {
			return nil
		}
		out = append(out, p)
		return nil
	})
	return out
}

func (te *testEnv) snapshotOf(t *testing.T) map[string][]byte {
	out := map[string][]byte{}
	for _, p := range listFiles(t, te.codexHomeDir()) {
		out[p] = readFile(t, p)
	}
	return out
}

func (te *testEnv) sealCodex(t *testing.T) UnitResult {
	t.Helper()
	u := te.codexUnit(t)
	rep, err := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
	mustNoErr(t, err)
	return outcome(t, rep, u.Key)
}

func (te *testEnv) restoreCodex(t *testing.T) UnitResult {
	t.Helper()
	rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{{Harness: harness.Codex, Kind: capsule.KindCodexHome, Key: te.codexKey()}}})
	return outcome(t, rep, te.codexKey())
}

func blobCount(te *testEnv) int {
	n := 0
	for _, en := range te.allLogged() {
		if en.Blob {
			n++
		}
	}
	return n
}

// D31/D42: a home seals as blobs + one manifest generation, -shm never
// sealed, never-touch files untouched; restore places exactly the snapshot.
func TestCodexSnapshotRoundTrip(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	home := te.codexHome(t)
	orig := te.snapshotOf(t)
	shm := filepath.Join(home, "state_5.sqlite-shm")
	auth := readFile(t, filepath.Join(home, "auth.json"))
	res := te.sealCodex(t)
	if res.Outcome != OutSealed || res.Gen != 1 {
		t.Fatalf("seal %+v", res)
	}
	en := te.logged(te.codexKey())
	if len(en) != 1 || !en[0].Snapshot {
		t.Fatalf("snapshot entry %+v", en)
	}
	// One blob per plain file, one per SQLite group (db + wal together).
	groups := 0
	for p := range orig {
		if !strings.HasSuffix(p, "-wal") {
			groups++
		}
	}
	if blobCount(te) != groups {
		t.Fatalf("%d blobs, want %d", blobCount(te), groups)
	}
	for p := range orig {
		if exists(p) {
			t.Fatalf("plaintext left: %s", filepath.Base(p))
		}
	}
	if !exists(shm) || !bytes.Equal(readFile(t, filepath.Join(home, "auth.json")), auth) {
		t.Fatal("-shm or a never-touch file was sealed or removed")
	}
	if res := te.restoreCodex(t); res.Outcome != OutRestored {
		t.Fatalf("restore %+v", res)
	}
	for p, b := range orig {
		if !bytes.Equal(readFile(t, p), b) {
			t.Fatalf("%s differs", filepath.Base(p))
		}
	}
	if exists(shm) {
		t.Fatal("stale -shm left next to its database (CODX-2)")
	}
	q, _ := filepath.Glob(filepath.Join(te.h.Layout.QuarantineDir, "*", "codex", "state_5.sqlite-shm"))
	if len(q) != 1 {
		t.Fatalf("-shm not moved to quarantine: %v", q)
	}
	rd, ok, _ := LoadReceipt(te.e, te.codexKey())
	if !ok || rd.Gen != 1 || len(rd.Files) != len(orig) {
		t.Fatalf("receipt %+v", rd)
	}
}

// Unchanged files reuse their blob; only changed ones get a new blob.
func TestCodexReusesUnchangedBlobs(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.codexHome(t)
	te.sealCodex(t)
	te.restoreCodex(t)
	before := blobCount(te)
	rollouts := codextestRollouts(t, te)
	f, err := os.OpenFile(rollouts[0], os.O_WRONLY|os.O_APPEND, 0)
	mustNoErr(t, err)
	_, _ = f.WriteString(`{"type":"event"}` + "\n")
	f.Close()
	res := te.sealCodex(t)
	if res.Outcome != OutSealed || res.Gen != 2 || res.Lineage != capsule.LineageSuccessor {
		t.Fatalf("second snapshot %+v", res)
	}
	if blobCount(te) != before+1 {
		t.Fatalf("blobs %d → %d, want one new", before, blobCount(te))
	}
}

func codextestRollouts(t *testing.T, te *testEnv) []string {
	var out []string
	for _, p := range listFiles(t, te.codexHomeDir()) {
		if strings.Contains(p, "rollout-") {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		t.Fatal("no rollouts")
	}
	return out
}

// CODX-3: Codex exits cleanly (WAL checkpointed away): the newest snapshot
// has no WAL and none returns. CODX-4: a deleted rollout stays deleted.
func TestCodexNewestSnapshotIsExact(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	home := te.codexHome(t)
	te.sealCodex(t)
	te.restoreCodex(t)
	wal := filepath.Join(home, "state_5.sqlite-wal")
	mustNoErr(t, os.Remove(wal))
	gone := codextestRollouts(t, te)[0]
	mustNoErr(t, os.Remove(gone))
	res := te.sealCodex(t)
	if res.Gen != 2 || res.Lineage != capsule.LineagePartial {
		t.Fatalf("second snapshot %+v", res)
	}
	if res := te.restoreCodex(t); res.Outcome != OutRestored {
		t.Fatalf("restore %+v", res)
	}
	if exists(wal) {
		t.Fatal("CODX-3: a stale WAL came back")
	}
	if exists(gone) {
		t.Fatal("CODX-4: a deleted rollout came back")
	}
}

// CODX-5: a lease (another wrapper) during a SessionEnd seal: exit 4.
func TestCodexSealRefusesALeasedHome(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.codexHome(t)
	te.live.set(te.codexKey(), live.Verdict{Live: true, Evidence: []live.Evidence{{Reason: live.ReasonLease}}})
	u := te.codexUnit(t)
	rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{})
	if res := outcome(t, rep, u.Key); res.Outcome != OutLeased || !errors.Is(rep.Err(), ErrLive) {
		t.Fatalf("result %+v %v", res, rep.Err())
	}
}

// CODX-7 / R12: Codex ran on the home without precinto: the restore
// refuses (exit 4), seals the diverging plaintext as a diverged generation
// and deletes nothing; reconcile resolves either way.
func TestCodexDivergenceAndReconcile(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("slow (fsync-heavy): skipped with -short")
	}
	for _, prefer := range []CodexPrefer{PreferPlaintext, PreferCapsule} {
		t.Run(string(prefer), func(t *testing.T) {
			te := newTestEnv(t)
			te.codexHome(t)
			capsuleSide := te.snapshotOf(t)
			te.sealCodex(t)
			// Fresh databases and rollouts written outside precinto.
			codextest.New(t, te.codexHomeDir(), codextest.Options{Rollouts: 1, Marker: testkit.Marker(t)})
			plainSide := te.snapshotOf(t)
			res := te.restoreCodex(t)
			if res.Outcome != OutConflict || !strings.HasPrefix(res.Detail, codeConflict+":") {
				t.Fatalf("restore over divergence %+v", res)
			}
			en := te.logged(te.codexKey())
			if len(en) != 2 || capsule.Lineage(en[1].Lineage) != capsule.LineageDiverged {
				t.Fatalf("diverged generation %+v", en)
			}
			for p, b := range plainSide {
				if !bytes.Equal(readFile(t, p), b) {
					t.Fatal("divergence deleted or changed plaintext")
				}
			}
			// Still refused until reconcile, without sealing again.
			if res := te.restoreCodex(t); res.Outcome != OutConflict || len(te.logged(te.codexKey())) != 2 {
				t.Fatalf("second attempt %+v", res)
			}
			rep, err := te.run().reconcileCodex(tctx(t), te.keys, rootID, prefer)
			mustNoErr(t, err)
			if rep.Count(OutFailed) != 0 {
				t.Fatalf("reconcile %+v", rep.Units)
			}
			want := plainSide
			if prefer == PreferCapsule {
				want = capsuleSide
			}
			if res := te.restoreCodex(t); res.Outcome != OutRestored {
				t.Fatalf("restore after reconcile %+v", res)
			}
			got := te.snapshotOf(t)
			for p, b := range want {
				if !bytes.Equal(got[p], b) {
					t.Fatalf("%s: preferred side not in place", filepath.Base(p))
				}
			}
			// Nothing was deleted: both sides stay as generations.
			if n := len(te.logged(te.codexKey())); n < 3 {
				t.Fatalf("%d generations after reconcile", n)
			}
		})
	}
}
