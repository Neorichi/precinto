package sweep

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/precinto/precinto/internal/harness"
)

// openHookFS runs hook once, the first time the capsule store is opened
// as a base: in quarantine() that is after the journal and log reads and
// before the walk.
type openHookFS struct {
	fileSystem
	capsDir string
	once    sync.Once
	hook    func()
}

func (h *openHookFS) OpenBase(p string) (dirHandle, error) {
	if filepath.Clean(p) == filepath.Clean(h.capsDir) {
		h.once.Do(h.hook)
	}
	return h.fileSystem.OpenBase(p)
}

// D82 (DATA-1): a seal that another process commits between quarantine's
// journal and log reads and its walk is precinto's own capsule: it stays
// in the store, the sealer deletes the plaintext, and the unit restores.
func TestQuarantineSparesASealCommittedDuringTheWalk(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	files := te.sessionFiles(u)
	var sealErr error
	var sealed *Report
	qp := te.p
	qp.fs = &openHookFS{fileSystem: te.fs, capsDir: te.h.Layout.CapsulesDir, hook: func() {
		sealed, sealErr = te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{Reason: "wrapper-exit"})
	}}
	q := newRun(te.e, qp)
	mustNoErr(t, q.quarantine(tctx(t)))
	mustNoErr(t, sealErr)
	if sealed.Count(OutSealed) != 1 {
		t.Fatalf("concurrent seal: %+v", sealed.Units)
	}
	if n := q.finish().Count(OutQuarantined); n != 0 {
		t.Fatalf("quarantined %d of precinto's own capsules: %+v", n, q.finish().Units)
	}
	if !exists(filepath.Join(te.h.Layout.CapsulesDir, "claude-code", u.Key, "g000001.pcap")) {
		t.Fatal("the logged capsule left the store")
	}
	if g, _ := filepath.Glob(filepath.Join(te.h.Layout.QuarantineDir, "*", "claude-code", u.Key, "*")); len(g) != 0 {
		t.Fatalf("moved to quarantine: %v", g)
	}
	for _, f := range files {
		if exists(f) {
			t.Fatalf("plaintext left after the seal: %s", f)
		}
	}
	rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{u.Ref()}})
	if rep.Count(OutRestored) != 1 {
		t.Fatalf("restore: %+v", rep.Units)
	}
	for _, f := range files {
		if !exists(f) {
			t.Fatalf("not restored: %s", f)
		}
	}
}

// D82: a candidate whose unit lock is held (an operation in flight) is
// left for the next sweep; once the lock is free it is quarantined.
func TestQuarantineSkipsAUnitWhoseLockIsHeld(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	stray := filepath.Join(te.h.Layout.CapsulesDir, "claude-code", u.Key, "g000007.pcap")
	writeAt(t, stray, []byte("not a capsule of ours"))
	lk, err := te.run().lockUnit(u.Key)
	mustNoErr(t, err)
	r := te.run()
	mustNoErr(t, r.quarantine(tctx(t)))
	if n := r.finish().Count(OutQuarantined); n != 0 || !exists(stray) {
		t.Fatalf("moved while the unit lock was held: %d %+v", n, r.finish().Units)
	}
	lk.Unlock()
	r = te.run()
	mustNoErr(t, r.quarantine(tctx(t)))
	if n := r.finish().Count(OutQuarantined); n != 1 || exists(stray) {
		t.Fatalf("not quarantined once the lock was free: %d %+v", n, r.finish().Units)
	}
	if !exists(filepath.Join(te.h.Layout.CapsulesDir, "claude-code", u.Key, "g000001.pcap")) {
		t.Fatal("a logged capsule was quarantined")
	}
}

// D82 (defence in depth): a seal whose committed capsule left the store
// before the originals are unlinked keeps the plaintext.
func TestSealKeepsPlaintextWhenItsCapsuleVanished(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	files := te.sessionFiles(u)
	capsulePath := filepath.Join(te.h.Layout.CapsulesDir, "claude-code", u.Key, "g000001.pcap")
	te.p.point = func(name string) {
		if name == "seal.committed" {
			_ = os.Remove(capsulePath)
		}
	}
	rep, err := te.run().sealCommand(tctx(t), []harness.Unit{u}, Options{Reason: "wrapper-exit"})
	mustNoErr(t, err)
	if rep.Count(OutFailed) != 1 {
		t.Fatalf("seal: %+v", rep.Units)
	}
	for _, f := range files {
		if !exists(f) {
			t.Fatalf("plaintext deleted although its capsule was gone: %s", f)
		}
	}
}
