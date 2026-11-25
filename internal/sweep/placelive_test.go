package sweep

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/live"
)

// D84 (DATA-4): placement asks the adapter about the unit it restores,
// by its authenticated unit id and registered home, never about "".
func TestPlacementLivenessAsksAboutTheUnit(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, orig := te.sealedSession(sid1, nil)
	tr := transcriptOf(u)
	writeAt(t, tr, append([]byte(nil), orig[tr][:len(orig[tr])/2]...)) // a stale prefix: replaced
	var mu sync.Mutex
	var asked []harness.Unit
	te.claude.onProbe = func(pu harness.Unit) {
		mu.Lock()
		asked = append(asked, pu)
		mu.Unlock()
	}
	rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	if res := outcome(t, rep, u.Key); res.Outcome != OutRestored {
		t.Fatalf("restore %+v", res)
	}
	if len(asked) < 2 {
		t.Fatalf("placement never asked about liveness: %d probe(s)", len(asked))
	}
	for _, pu := range asked {
		if pu.UnitID != sid1 || pu.Home.ID != te.cc.ID {
			t.Fatalf("probed unit id %q home %q, want %q %q", pu.UnitID, pu.Home.ID, sid1, te.cc.ID)
		}
	}
	if string(readFile(t, tr)) != string(orig[tr]) {
		t.Fatal("stale prefix not replaced")
	}
}

// D84: a unit that is live when placement starts is rolled back with
// nothing placed: no file of it appears and no record is left.
func TestPlacementRollsBackAUnitLiveBeforeTheFirstFile(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, orig := te.sealedSession(sid1, nil)
	tr := transcriptOf(u)
	frag := []byte("{\"fragment\":true}\n")
	writeAt(t, tr, frag)
	rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}, BeforePlace: func(string) error {
		te.claude.probe[u.Key] = []live.Evidence{{Reason: live.ReasonRegistry, Detail: "registry names the session"}}
		return nil
	}})
	if res := outcome(t, rep, u.Key); res.Outcome != OutLive {
		t.Fatalf("restore %+v", res)
	}
	for p := range orig {
		if p == tr {
			continue
		}
		if exists(p) {
			t.Fatalf("placed although the unit was live: %s", p)
		}
	}
	if string(readFile(t, tr)) != string(frag) {
		t.Fatal("the live unit's transcript was touched")
	}
	if pending, err := te.e.Journal.Pending(); err != nil || len(pending) != 0 {
		t.Fatalf("records left: %d %v", len(pending), err)
	}
}

// D84: a unit that turns live after some of its files were placed keeps
// its record and staging, gets no receipt without its transcript, and is
// rolled forward by recovery once it is quiet.
func TestPlacementKeepsTheRecordOfAUnitThatTurnedLive(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, orig := te.sealedSession(sid1, nil)
	tr := transcriptOf(u)
	var sub string
	for p := range orig {
		if p != tr && filepath.Ext(p) == ".jsonl" {
			sub = p
		}
	}
	if sub == "" {
		t.Fatal("no subagent transcript in the fixture")
	}
	writeAt(t, tr, append([]byte(nil), orig[tr][:len(orig[tr])/2]...))
	writeAt(t, sub, append([]byte(nil), orig[sub][:len(orig[sub])/2]...))
	var mu sync.Mutex
	te.claude.onProbe = func(pu harness.Unit) {
		mu.Lock()
		defer mu.Unlock()
		if b, err := os.ReadFile(sub); err == nil && string(b) == string(orig[sub]) {
			te.claude.probe[u.Key] = []live.Evidence{{Reason: live.ReasonRegistry, Detail: "resumed"}}
		}
	}
	rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	if res := outcome(t, rep, u.Key); res.Outcome != OutLive {
		t.Fatalf("restore %+v", res)
	}
	pending, err := te.e.Journal.Pending()
	mustNoErr(t, err)
	if len(pending) != 1 || pending[0].Staging == "" || !exists(pending[0].Staging) {
		t.Fatalf("record or staging not kept for the roll-forward: %+v", pending)
	}
	if _, ok, _ := te.run().loadReceipt(u.Key); ok {
		t.Fatal("receipt written for a unit without its transcript")
	}
	// Quiet again: recovery rolls the restore forward.
	mu.Lock()
	te.claude.onProbe = nil
	delete(te.claude.probe, u.Key)
	mu.Unlock()
	mustNoErr(t, te.run().recoverAll(tctx(t)))
	if string(readFile(t, tr)) != string(orig[tr]) {
		t.Fatal("transcript not placed by the roll-forward")
	}
	if _, ok, _ := te.run().loadReceipt(u.Key); !ok {
		t.Fatal("no receipt after the roll-forward")
	}
	if pending, _ := te.e.Journal.Pending(); len(pending) != 0 {
		t.Fatalf("records left: %+v", pending)
	}
}
