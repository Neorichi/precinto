package sweep_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/testkit"
)

// testCtx is the context of an exported call in a test: it ends with the
// test and after 60 s at the latest, so a stuck call fails the test with
// a timeout instead of hanging the package (FX-G4-02).
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// envOf is an Env over a fake HOME using only scaffold-implemented
// dependencies (enough for the exported metadata helpers).
func envOf(t *testing.T) (sweep.Env, *testkit.Home) {
	t.Helper()
	h := testkit.NewHome(t)
	e := sweep.Env{Cfg: h.Cfg, Harness: harness.Env{Cfg: h.Cfg, Layout: h.Layout, Clock: h.Clock, Procs: h.Procs},
		Log: capslog.Open(h.Layout.CapsuleLog), Clock: h.Clock, Procs: h.Procs}
	return e, h
}

func TestMarkerTextIsTwoLinesNamingTheKey(t *testing.T) {
	t.Parallel()
	key := strings.Repeat("0f", 16)
	got := string(sweep.MarkerText(key))
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 2 || lines[1] != "id: "+key || !strings.HasSuffix(got, "\n") {
		t.Fatalf("marker %q", got)
	}
	p := filepath.Join(t.TempDir(), "n.md.precinto")
	if err := os.WriteFile(p, []byte(got), 0o600); err != nil {
		t.Fatal(err)
	}
	if k, err := sweep.ParseMarker(p); err != nil || k != key {
		t.Fatalf("ParseMarker %q %v", k, err)
	}
	if _, err := sweep.ParseMarker(filepath.Join(t.TempDir(), "missing.md.precinto")); err == nil || errors.Is(err, sweep.ErrNotMarker) {
		t.Fatalf("missing marker: %v (an I/O error, not ErrNotMarker)", err)
	}
}

func TestNextGenGenerationsAndReceipts(t *testing.T) {
	t.Parallel()
	e, h := envOf(t)
	unit := strings.Repeat("1a", 16)
	for want := uint64(1); want <= 3; want++ {
		n, err := sweep.NextGen(e, unit)
		if err != nil || n != want {
			t.Fatalf("NextGen = %d, %v; want %d", n, err, want)
		}
	}
	b, err := os.ReadFile(filepath.Join(h.Layout.GensDir, unit))
	if err != nil || strings.TrimSpace(string(b)) != "3" {
		t.Fatalf("counter %q %v", b, err)
	}
	if err := e.Log.Append(capslog.Entry{Path: "claude-code/" + unit + "/g000002.pcap", HeaderSHA256: "h", Unit: unit, Gen: 2, Parent: 1,
		Lineage: "successor", Kind: "claude-session"}); err != nil {
		t.Fatal(err)
	}
	gens, err := sweep.Generations(e, unit)
	if err != nil || len(gens) != 1 || gens[0].Gen != 2 || gens[0].Parent != 1 || gens[0].Lineage != capsule.LineageSuccessor {
		t.Fatalf("generations %+v %v", gens, err)
	}
	if _, ok, err := sweep.LoadReceipt(e, unit); ok || err != nil {
		t.Fatalf("receipt of a never-restored unit: %v %v", ok, err)
	}
	if err := os.WriteFile(filepath.Join(h.Layout.ReceiptsDir, unit+".json"), []byte(`{"v":1,"unit":"`+unit+`","gen":2,"files":[{"base":"claude_config","rel":"x","sha256":"s","size":1,"from_gen":2}],"blobs":{"x":"y"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rd, ok, err := sweep.LoadReceipt(e, unit)
	if err != nil || !ok || rd.Gen != 2 || len(rd.Files) != 1 || rd.Files[0].Rel != "x" {
		t.Fatalf("receipt %+v %v %v", rd, ok, err)
	}
	if _, _, err := sweep.LoadReceipt(e, "../etc"); err == nil {
		t.Fatal("receipt path traversal accepted")
	}
}

func TestReportErrMapsToSentinels(t *testing.T) {
	t.Parallel()
	rep := &sweep.Report{Units: []sweep.UnitResult{
		{Outcome: sweep.OutFailed, Detail: "not-logged: x"},
		{Outcome: sweep.OutFailed, Detail: "key-denied: x"},
		{Outcome: sweep.OutFailed, Detail: "unit-key: x"},
	}}
	err := rep.Err()
	if !errors.Is(err, sweep.ErrNotLogged) || !errors.Is(err, sweep.ErrKeyDenied) || !errors.Is(err, harness.ErrUnitKey) {
		t.Fatalf("Err %v", err)
	}
	if rep.Count(sweep.OutFailed) != 3 {
		t.Fatal("Count")
	}
}
