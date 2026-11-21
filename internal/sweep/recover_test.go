package sweep

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/sweep/journal"
)

// crashed is the panic value of a simulated crash.
type crashed struct{}

// simulateCrash runs fn, swallowing the simulated crash: a panic unwinds
// to here, the unit lock is released by its deferred Unlock just as the
// kernel releases a dead process's flocks, and the on-disk state is what
// a SIGKILL at the same point leaves (journal record, capsule, staging).
func simulateCrash(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(crashed); !ok {
				panic(r)
			}
		}
	}()
	fn()
	t.Fatal("the simulated crash point was not reached")
}

func crash() { panic(crashed{}) }

// checkRecovered runs recovery twice (O6 idempotence) and a quarantine
// pass (O7: precinto's own leftovers are never reported as forgeries).
func (te *testEnv) checkRecovered() *Report {
	te.t.Helper()
	r := te.run()
	mustNoErr(te.t, r.recoverAll(tctx(te.t)))
	rep := r.finish()
	r2 := te.run()
	mustNoErr(te.t, r2.recoverAll(tctx(te.t)))
	if len(r2.finish().Units) != 0 {
		te.t.Fatal("O6: a second recovery found work")
	}
	q := te.run()
	mustNoErr(te.t, q.quarantine(tctx(te.t)))
	if n := q.finish().Count(OutQuarantined); n != 0 {
		te.t.Fatalf("O7: %d of precinto's own capsules quarantined", n)
	}
	if p, _ := te.e.Journal.Pending(); len(p) != 0 {
		te.t.Fatalf("records left: %+v", p)
	}
	return rep
}

func (te *testEnv) plaintextIntact(orig map[string][]byte) {
	te.t.Helper()
	for p, b := range orig {
		if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, b) {
			te.t.Fatalf("O1/O5: plaintext %s lost or changed", filepath.Base(p))
		}
	}
}

func (te *testEnv) plaintextGone(u harness.Unit) {
	te.t.Helper()
	for _, p := range te.sessionFiles(u) {
		if exists(p) {
			te.t.Fatalf("O4: plaintext %s left after recovery", filepath.Base(p))
		}
	}
}

func (te *testEnv) original(u harness.Unit) map[string][]byte {
	out := map[string][]byte{}
	for _, p := range te.sessionFiles(u) {
		out[p] = readFile(te.t, p)
	}
	return out
}

func (te *testEnv) unitDirEntries(key string) []string {
	ents, _ := os.ReadDir(filepath.Join(te.h.Layout.CapsulesDir, "claude-code", key))
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// SEAL-2 / SEAL-3: a crash while the temporary is written or before it is
// verified leaves the journaled temporary (capsule.TmpName) and the record
// at prepared or tmp_written, generation 1 reserved; recovery removes the
// temporary and keeps the plaintext. The state is built as a SIGKILL
// leaves it (the crash matrix kills real seals at capsule.streamed and
// seal.tmp_written).
func TestRecoverRemovesAnInterruptedTemporary(t *testing.T) {
	t.Parallel()
	for _, phase := range []journal.Phase{journal.PhasePrepared, journal.PhaseTmpWritten} {
		te := newTestEnv(t)
		te.writeSession(sid1, "", nil)
		u := te.scanSession(sid1)
		orig := te.original(u)
		r := te.run()
		_, caps, err := r.openCapsDir("claude-code", u.Key, true)
		mustNoErr(t, err)
		if n, err := r.nextGen(tctx(t), u.Key, caps); err != nil || n != 1 {
			t.Fatalf("reserve %d %v", n, err)
		}
		rec, err := te.e.Journal.Begin(journal.KindSeal, "claude-code", u.Key)
		mustNoErr(t, err)
		for _, f := range u.Files {
			rec.Files = append(rec.Files, journal.File{Base: string(f.Base), Dir: u.Home.Bases[f.Base], Rel: f.Rel, Snap: f.Snap})
		}
		rec.Tmp, rec.Capsule, rec.Gen = capsule.TmpName("g000001.pcap"), "g000001.pcap", 1
		mustNoErr(t, te.e.Journal.Save(rec))
		if phase != journal.PhasePrepared {
			mustNoErr(t, te.e.Journal.Advance(rec, phase))
		}
		writeAt(t, filepath.Join(caps.Path(), rec.Tmp), []byte(fakeMagic+"half a capsule"))
		te.checkRecovered()
		te.plaintextIntact(orig)
		if ents := te.unitDirEntries(u.Key); len(ents) != 0 {
			t.Fatalf("%s: leftovers: %v", phase, ents)
		}
		// The next seal takes a new number: gaps are allowed (D58).
		rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{te.scanSession(sid1)}, Options{})
		if res := outcome(t, rep, u.Key); res.Outcome != OutSealed || res.Gen != 2 {
			t.Fatalf("%s: next seal %+v", phase, res)
		}
	}
}

// SEAL-6: a crash after the no-replace rename, before the log append.
func TestRecoverDeletesAnUnloggedCapsule(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	orig := te.original(u)
	te.codec.afterRename = crash
	simulateCrash(t, func() { te.run().sealOne(tctx(t), u, Options{}, true) })
	if ents := te.unitDirEntries(u.Key); len(ents) != 1 || ents[0] != "g000001.pcap" {
		t.Fatalf("crash state: %v", ents)
	}
	te.codec.afterRename = nil
	rep := te.checkRecovered()
	if res := outcome(t, rep, u.Key); res.Outcome != OutSkipped {
		t.Fatalf("recovery %+v", res)
	}
	te.plaintextIntact(orig)
	if ents := te.unitDirEntries(u.Key); len(ents) != 0 {
		t.Fatalf("unlogged capsule left: %v", ents)
	}
	rep, _ = te.run().sealCommand(tctx(t), []harness.Unit{te.scanSession(sid1)}, Options{})
	if res := outcome(t, rep, u.Key); res.Gen != 2 {
		t.Fatalf("number reused: %+v", res)
	}
}

// SEAL-8 / SEAL-9: a crash after committed, or after k of N unlinks:
// recovery unlinks only files whose identity still matches.
func TestRecoverResumesIdentityCheckedUnlinks(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	n := 0
	var survivor string
	// Crash before the fourth unlink: three are done and journaled.
	unlinked := 0
	te.fs.onUnlink = func(p string) {
		unlinked++
		if unlinked == 4 {
			crash()
		}
	}
	simulateCrash(t, func() { te.run().sealOne(tctx(t), u, Options{}, true) })
	te.fs.onUnlink = nil
	// A surviving file changes before recovery: it must stay.
	for _, p := range te.sessionFiles(u) {
		if exists(p) {
			n++
			if survivor == "" {
				survivor = p
			}
		}
	}
	if n == 0 || n == len(u.Files) {
		t.Fatalf("crash state: %d of %d files left", n, len(u.Files))
	}
	mustNoErr(t, os.WriteFile(survivor, []byte("changed after the crash\n"), 0o600))
	te.checkRecovered()
	for _, p := range te.sessionFiles(u) {
		if exists(p) && p != survivor {
			t.Fatalf("%s left behind", filepath.Base(p))
		}
	}
	if string(readFile(t, survivor)) != "changed after the crash\n" {
		t.Fatal("a changed file was deleted")
	}
	if len(te.logged(u.Key)) != 1 {
		t.Fatal("recovery created a generation")
	}
	// The survivor is plaintext of the unit with no receipt line (its
	// sealed hash is unknown): it seals as the next generation, nothing
	// hides the others (SEAL-9, lineage partial or diverged).
	rep, _ := te.run().sealCommand(tctx(t), []harness.Unit{te.scanSession(sid1)}, Options{})
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed || res.Gen != 2 {
		t.Fatalf("next seal %+v", res)
	}
}

// REST-3: a crash after staged with k of N placed rolls forward.
func TestRecoverRollsAStagedRestoreForward(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, orig := te.sealedSession(sid1, nil)
	placed := 0
	te.fs.onRename = func(dst string) {
		if bytes.HasPrefix([]byte(dst), []byte(te.h.ClaudeConfig)) || bytes.HasPrefix([]byte(dst), []byte(te.h.ClaudeTmp)) {
			placed++
			if placed == 3 {
				crash()
			}
		}
	}
	simulateCrash(t, func() {
		te.run().restore(tctx(t), te.keys, RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	})
	te.fs.onRename = nil
	if exists(transcriptOf(u)) {
		t.Fatal("the transcript was placed before the other files")
	}
	p, _ := te.e.Journal.Pending()
	if len(p) != 1 || (p[0].Phase != journal.PhasePlacing && p[0].Phase != journal.PhaseStaged) {
		t.Fatalf("crash state %+v", p)
	}
	rep := te.checkRecovered()
	if res := outcome(t, rep, u.Key); res.Outcome != OutRestored {
		t.Fatalf("roll forward %+v", res)
	}
	te.plaintextIntact(orig)
	if ents, _ := os.ReadDir(te.h.Layout.StagingDir); len(ents) != 0 {
		t.Fatal("staging left")
	}
	if rd, ok, _ := LoadReceipt(te.e, u.Key); !ok || len(rd.Files) != len(u.Files) {
		t.Fatalf("receipt after roll forward %+v", rd)
	}
}

// REST-1: a crash while decrypting into staging places nothing.
func TestRecoverAfterACrashDuringStaging(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	te.codec.duringExtract = func(n int) {
		if n == 2 {
			crash()
		}
	}
	simulateCrash(t, func() {
		te.run().restore(tctx(t), te.keys, RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	})
	te.codec.duringExtract = nil
	te.checkRecovered()
	for _, f := range u.Files {
		if exists(filepath.Join(u.Home.Bases[f.Base], f.Rel)) {
			t.Fatal("placed after a crash during staging")
		}
	}
	if ents, _ := os.ReadDir(te.h.Layout.StagingDir); len(ents) != 0 {
		t.Fatalf("staging left: %v", ents)
	}
}

// Recovery never touches the records of an operation still running in
// another process (its unit lock is held).
func TestRecoverSkipsAnOperationInFlight(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	key := te.sessionKey(sid1)
	rec, err := te.e.Journal.Begin(journal.KindSeal, "claude-code", key)
	mustNoErr(t, err)
	rec.Capsule = capsule.GenName(1)
	mustNoErr(t, te.e.Journal.Save(rec))
	lk, err := te.run().lockUnit(key)
	mustNoErr(t, err)
	r := te.run()
	mustNoErr(t, r.recoverAll(tctx(t)))
	if p, _ := te.e.Journal.Pending(); len(p) != 1 {
		t.Fatal("recovered a record whose operation still runs")
	}
	// Quarantine never moves what a pending record names.
	root, caps, err := te.run().openCapsDir("claude-code", key, true)
	mustNoErr(t, err)
	root.Close()
	f, err := os.Create(filepath.Join(caps.Path(), "g000001.pcap"))
	mustNoErr(t, err)
	f.WriteString(fakeMagic + "{}\n")
	f.Close()
	q := te.run()
	mustNoErr(t, q.quarantine(tctx(t)))
	if q.finish().Count(OutQuarantined) != 0 {
		t.Fatal("quarantined a capsule named by a pending record")
	}
	lk.Unlock()
}
