//go:build failpoints

package sweep

import (
	"testing"

	"github.com/precinto/precinto/internal/fsx/failpoint"
)

// SEAL-7 in-process: the commit fails right after the capsule-log append
// (failpoint seal.logged), before committed is journaled; the record stays
// and recovery continues the logged capsule as committed. Not parallel:
// failpoints are process-wide.
func TestRecoverContinuesALoggedCapsuleAsCommitted(t *testing.T) {
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	failpoint.Reset()
	failpoint.Set("seal.logged=errno:EIO")
	res := te.run().sealOne(tctx(t), u, Options{}, true)
	failpoint.Reset()
	if res.Outcome == OutSealed {
		t.Fatalf("the seal succeeded although seal.logged failed: %+v", res)
	}
	rep := te.checkRecovered()
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed {
		t.Fatalf("recovery %+v", res)
	}
	te.plaintextGone(u)
	if n := len(te.logged(u.Key)); n != 1 {
		t.Fatalf("%d log entries, want exactly one", n)
	}
}
