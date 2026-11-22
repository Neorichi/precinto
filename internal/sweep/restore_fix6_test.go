package sweep

import (
	"errors"
	"io/fs"
	"strings"
	"syscall"
	"testing"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/live"
)

// D132: a unit of an Optional selector that is live at restore is left as
// it is (skipped, no error) and a StopOnErr restore goes on to the next
// unit; the same unit from a required selector fails and stops it. The
// detail says what the launch gets: the plaintext on disk left as it is,
// or the unit not restored (sealed while in use elsewhere, or its
// liveness check failed, which it names).
func TestD132OptionalUnitInUseIsLeftAsItIs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		optional bool
		onDisk   bool  // the unit's plaintext is on disk when the restore runs
		probeErr error // the liveness probe fails
		detail   string
	}{
		{name: "required", optional: false},
		{name: "optional, sealed", optional: true, detail: detailInUseSealed},
		{name: "optional, plaintext on disk", optional: true, onDisk: true, detail: detailInUse},
		{name: "optional, probe fails", optional: true,
			probeErr: &fs.PathError{Op: "open", Path: "/registry/4711.json", Err: syscall.EACCES},
			detail:   detailProbeFailedAt + "open: permission denied"}, // the path stays out (I7)
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestEnv(t)
			u1, _ := te.sealedSession(sid1, nil)
			u2, _ := te.sealedSession(sid2, nil)
			if tc.onDisk {
				te.writeSession(sid1, "", nil) // another Claude writes it again
			}
			te.claude.probe[u1.Key] = []live.Evidence{{Reason: live.ReasonRegistry, Detail: "registry names the session"}}
			sel := []harness.Selector{{Kind: capsule.KindClaudeSession, Keys: []string{u1.Key}, Optional: tc.optional}}
			if tc.probeErr == nil {
				sel = append(sel, harness.Selector{Kind: capsule.KindClaudeSession, Keys: []string{u2.Key}})
			} else {
				te.claude.probeErr = tc.probeErr // every probe fails: u1 only
			}
			rep, err := te.run().restore(tctx(t), te.keys, RestoreRequest{StopOnErr: true, Select: sel})
			mustNoErr(t, err)
			r1 := outcome(t, rep, u1.Key)
			if !tc.optional {
				if r1.Outcome != OutLive || !errors.Is(rep.Err(), ErrLive) {
					t.Fatalf("required unit in use: %+v, err %v", r1, rep.Err())
				}
				if exists(transcriptOf(u2)) {
					t.Fatal("a StopOnErr restore went on after a required unit failed")
				}
				return
			}
			if r1.Outcome != OutSkipped || r1.Detail != tc.detail || rep.Err() != nil {
				t.Fatalf("optional unit in use: %+v, err %v; want detail %q", r1, rep.Err(), tc.detail)
			}
			if !strings.HasPrefix(r1.Detail, "in use elsewhere") && tc.probeErr == nil {
				t.Fatalf("detail %q", r1.Detail)
			}
			if exists(transcriptOf(u1)) != tc.onDisk {
				t.Fatalf("plaintext on disk %v after the restore, want %v", exists(transcriptOf(u1)), tc.onDisk)
			}
			if tc.probeErr != nil {
				return
			}
			if r2 := outcome(t, rep, u2.Key); r2.Outcome != OutRestored || !exists(transcriptOf(u2)) {
				t.Fatalf("the restore stopped at an optional unit in use: %+v", r2)
			}
		})
	}
}
