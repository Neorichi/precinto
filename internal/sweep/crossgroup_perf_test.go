//go:build crossgroup && failpoints

package sweep

// The PERF rows of docs/TESTPLAN.md §4 (FX-G4-18, DF-02), over the real
// stack: opt-in only (PRECINTO_PERF=1), because they need 4–32 GB of
// scratch disk; they run on a disposable machine or a nightly runner, never
// on a laptop. Sizes are the TESTPLAN's; PRECINTO_PERF_SCALE=N divides
// them (a smoke run of the rows themselves). Each row logs its times and
// the peak extra disk under the precinto base.

import (
	"context"
	"crypto/rand"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/fsx/failpoint"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/harness/codex/codextest"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

// perfScale is 1 for the TESTPLAN sizes; PRECINTO_PERF_SCALE divides them.
func perfScale(t *testing.T) int64 {
	t.Helper()
	if os.Getenv("PRECINTO_PERF") != "1" {
		t.Skip("PERF rows run only with PRECINTO_PERF=1 (4–32 GB of scratch disk, DF-02)")
	}
	if s := os.Getenv("PRECINTO_PERF_SCALE"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 1 {
			t.Fatalf("PRECINTO_PERF_SCALE=%q", s)
		}
		return n
	}
	return 1
}

// randomFile writes size random bytes (incompressible, like transcripts
// of tool output) to p.
func randomFile(t *testing.T, p string, size int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(f, rand.Reader, size); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(p, old, old)
}

// diskMeter samples the bytes under dir every 50 ms until stop and
// reports the peak above the first sample.
type diskMeter struct {
	stop chan struct{}
	done chan struct{}
	mu   sync.Mutex
	base int64
	peak int64
}

func treeBytes(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

func meter(dir string) *diskMeter {
	m := &diskMeter{stop: make(chan struct{}), done: make(chan struct{}), base: treeBytes(dir)}
	m.peak = m.base
	go func() {
		defer close(m.done)
		tk := time.NewTicker(50 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-tk.C:
				if n := treeBytes(dir); n > 0 {
					m.mu.Lock()
					m.peak = max(m.peak, n)
					m.mu.Unlock()
				}
			}
		}
	}()
	return m
}

// extra stops the meter and returns the peak extra bytes.
func (m *diskMeter) extra() int64 {
	close(m.stop)
	<-m.done
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.peak - m.base
}

// perfKeys releases file keys of logged capsules from the fixture (the
// daemon's part, D39).
type perfKeys struct {
	fx       *vaulttest.Fixture
	capsules string
	log      *capslog.Log
}

type perfKeySet struct {
	mu   sync.Mutex
	keys map[string]*memguard.LockedBuffer
}

func (s *perfKeySet) Key(p string) (*memguard.LockedBuffer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.keys[p]
	return b, ok
}

func (s *perfKeySet) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.keys {
		b.Destroy()
	}
}

func (k *perfKeys) FileKeys(ctx context.Context, paths []string, purpose string) (FileKeys, error) {
	all, err := k.log.All()
	if err != nil {
		return nil, err
	}
	vaultOf := map[string]string{}
	for _, en := range all {
		vaultOf[en.Path] = en.VaultID
	}
	set := &perfKeySet{keys: map[string]*memguard.LockedBuffer{}}
	for _, p := range paths {
		id, ok := vaultOf[p]
		if !ok {
			continue
		}
		abs := filepath.Join(k.capsules, filepath.FromSlash(p))
		d, err := fsx.OpenBase(filepath.Dir(abs))
		if err != nil {
			return nil, err
		}
		hdr, _, err := capsule.ReadHeader(d, filepath.Base(abs))
		d.Close()
		if err != nil {
			return nil, err
		}
		b, err := k.fx.Keyring.FileKey(id, hdr)
		if err != nil {
			return nil, err
		}
		set.keys[p] = b
	}
	return set, nil
}

// perfSession writes a managed session whose subagent directory holds
// big random files and returns its scanned unit's files on disk.
func perfSession(t *testing.T, h *testkit.Home, sid string, big ...int64) {
	t.Helper()
	paths := claudetest.New(t, h.Dir).WriteSession(t, claudetest.Session{SID: sid, Cwd: h.Root, Subagents: 1,
		ModTime: time.Now().Add(-time.Hour)})
	if err := ledger.Open(h.Layout.SessionsDir).Append(ledger.Event{Type: ledger.TypeTaint, Harness: "claude-code", SID: sid,
		Roots: []string{"root-acme"}, Cwd: h.Root, ConfigDir: h.ClaudeConfig}); err != nil {
		t.Fatal(err)
	}
	var dir string
	for _, p := range paths {
		if strings.HasSuffix(p, string(filepath.Separator)+sid+".jsonl") {
			dir = strings.TrimSuffix(p, ".jsonl")
		}
	}
	if dir == "" {
		t.Fatal("no transcript written")
	}
	for i, n := range big {
		randomFile(t, filepath.Join(dir, "tool-results", "big-"+strconv.Itoa(i)+".bin"), n)
	}
}

func scanSessions(t *testing.T, e Env, sids ...string) []harness.Unit {
	t.Helper()
	units, err := claude.New().Scan(tctx(t), e.Harness, harness.Scope{SIDs: sids, Kinds: []capsule.Kind{capsule.KindClaudeSession}})
	if err != nil || len(units) != len(sids) {
		t.Fatalf("scan %d of %d sessions: %v", len(units), len(sids), err)
	}
	return units
}

// PERF-1: a 4 GB unit killed at 50 % of its seal (capsule.streamed after
// the first of two 2 GB inputs, SEAL-2) recovers with its plaintext
// intact; it then seals, restores, and re-seals unchanged writing 0 bytes.
func TestPERF1LargeUnitKilledHalfway(t *testing.T) {
	scale := perfScale(t)
	const sid = "00000000-0000-4000-8000-00000000f001"
	half := int64(2<<30) / scale
	spec := os.Getenv("SWEEP_PERF_SPEC")
	if dir := os.Getenv("SWEEP_XCRASH_DIR"); dir != "" {
		holdLifeline()
		h := homeAt(t, dir, os.Getenv("SWEEP_XCRASH_RUN"))
		failpoint.Set(spec)
		e := realEnv(t, h)
		_, _ = Seal(tctx(t), e, scanSessions(t, e, sid), Options{Reason: "session-end"})
		os.Exit(7)
	}
	h := testkit.NewHome(t)
	fx := vaulttest.New(t, h.Base, "root-acme")
	perfSession(t, h, sid, half, half)
	e := realEnv(t, h)
	u := scanSessions(t, e, sid)[0]
	first := -1
	for i, f := range u.Files {
		if strings.Contains(f.Rel, "/tool-results/big-") && first < 0 {
			first = i
		}
	}
	if first < 0 {
		t.Fatal("the big inputs are not in the unit")
	}
	start := time.Now()
	runCrashChild(t, "SWEEP_XCRASH_DIR="+h.Dir, "SWEEP_XCRASH_RUN="+h.RunDir, "SWEEP_PERF_SPEC=capsule.streamed:"+strconv.Itoa(first+1))
	t.Logf("PERF-1: killed at 50 %% after %v", time.Since(start))
	r := newRun(e, prodPorts(e))
	if err := r.recoverAll(tctx(t)); err != nil {
		t.Fatal(err)
	}
	for _, f := range u.Files {
		st, err := fsx.Lstat(filepath.Join(u.Home.Bases[f.Base], filepath.FromSlash(f.Rel)))
		if err != nil || !st.Unchanged(f.Snap) {
			t.Fatalf("plaintext %s lost or changed by the crash", filepath.Base(f.Rel))
		}
	}
	m := meter(h.Base)
	start = time.Now()
	rep, err := Seal(tctx(t), e, scanSessions(t, e, sid), Options{Reason: "session-end"})
	if err != nil || rep.Count(OutSealed) != 1 {
		t.Fatalf("seal %+v %v", rep, err)
	}
	t.Logf("PERF-1: seal of %d bytes in %v, peak extra disk %d bytes", 2*half, time.Since(start), m.extra())
	keys := &perfKeys{fx: fx, capsules: h.Layout.CapsulesDir, log: e.Log}
	start = time.Now()
	rep, err = Restore(tctx(t), e, keys, RestoreRequest{Units: []harness.UnitRef{u.Ref()}})
	if err != nil || rep.Count(OutRestored) != 1 {
		t.Fatalf("restore %+v %v", rep, err)
	}
	t.Logf("PERF-1: restore in %v", time.Since(start))
	before := treeBytes(h.Layout.CapsulesDir)
	start = time.Now()
	rep, err = Seal(tctx(t), e, scanSessions(t, e, sid), Options{Reason: "session-end"})
	if err != nil || rep.Count(OutUnchanged) != 1 {
		t.Fatalf("unchanged re-seal %+v %v", rep, err)
	}
	if after := treeBytes(h.Layout.CapsulesDir); after != before {
		t.Fatalf("the unchanged re-seal wrote %d bytes, want 0", after-before)
	}
	t.Logf("PERF-1: unchanged re-seal in %v, 0 bytes written", time.Since(start))
}

// PERF-2: restoring 20 sessions of 1 GB with room for 12 restores the
// newest ones whole, up to the floor, and reports the rest skipped.
func TestPERF2RestoreUpToTheFloor(t *testing.T) {
	scale := perfScale(t)
	unit := int64(1<<30) / scale
	h := testkit.NewHome(t)
	fx := vaulttest.New(t, h.Base, "root-acme")
	var sids []string
	for i := 0; i < 20; i++ {
		sid := "00000000-0000-4000-8000-00000000f2" + strconv.Itoa(10+i)
		sids = append(sids, sid)
		perfSession(t, h, sid, unit)
	}
	e := realEnv(t, h)
	units := scanSessions(t, e, sids...)
	start := time.Now()
	if rep, err := Seal(tctx(t), e, units, Options{Reason: "lock"}); err != nil || rep.Count(OutSealed) != 20 {
		t.Fatalf("seal %+v %v", rep, err)
	}
	t.Logf("PERF-2: sealed 20 × %d bytes in %v", unit, time.Since(start))
	avail, _, err := fsx.Space(h.ClaudeConfig)
	if err != nil {
		t.Fatal(err)
	}
	// Room for 12: every restore needs 1.1 × its bytes above the floor and
	// consumes about its bytes.
	e.Floor = fsx.Floor{MinBytes: int64(avail) - 12*unit - unit/10 - unit/2}
	keys := &perfKeys{fx: fx, capsules: h.Layout.CapsulesDir, log: e.Log}
	m := meter(h.Base)
	start = time.Now()
	rep, err := Restore(tctx(t), e, keys, RestoreRequest{Select: []harness.Selector{{Kind: capsule.KindClaudeSession, RootID: "root-acme"}}, Budget: 1 << 62})
	if err != nil {
		t.Fatal(err)
	}
	restored, skipped := rep.Count(OutRestored), rep.Count(OutSkipped)
	t.Logf("PERF-2: %d restored, %d skipped in %v, peak extra disk %d bytes", restored, skipped, time.Since(start), m.extra())
	if restored+skipped != 20 || (scale == 1 && restored != 12) || restored == 0 {
		t.Fatalf("restored %d, skipped %d: %+v", restored, skipped, rep.Units)
	}
	for _, res := range rep.Units {
		if res.Outcome == OutSkipped && !strings.HasPrefix(res.Detail, codeNoSpace+":") {
			t.Fatalf("skipped for another reason: %+v", res)
		}
	}
}

// PERF-3: a Codex home with a 578 MB rollout and a 2.9 GB thread history:
// after the rollout grows, the re-seal writes only the changed blob (peak
// extra disk ≤ the changed blobs), and a restore needs one staging unit.
func TestPERF3CodexHomeBlobReuse(t *testing.T) {
	scale := perfScale(t)
	h := testkit.NewHome(t)
	fx := vaulttest.New(t, h.Base, "root-acme")
	home := h.Layout.CodexHome("root-acme")
	if err := os.MkdirAll(filepath.Dir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	ch := codextest.New(t, home, codextest.Options{Rollouts: 1, RolloutAge: time.Hour})
	rollout := ch.Rollouts(t)[0]
	randomFile(t, rollout+".big", 578<<20/scale)
	// The big rollout content goes into the rollout itself (appended).
	appendFrom(t, rollout, rollout+".big")
	randomFile(t, filepath.Join(home, "thread_history.jsonl"), 2900<<20/scale)
	e := realEnv(t, h)
	scan := func() []harness.Unit {
		units, err := codex.New().Scan(tctx(t), e.Harness, harness.Scope{RootIDs: []string{"root-acme"}, Kinds: []capsule.Kind{capsule.KindCodexHome}})
		if err != nil || len(units) != 1 {
			t.Fatalf("scan %v %v", units, err)
		}
		return units
	}
	keys := &perfKeys{fx: fx, capsules: h.Layout.CapsulesDir, log: e.Log}
	start := time.Now()
	u := scan()[0]
	if rep, err := Seal(tctx(t), e, []harness.Unit{u}, Options{Reason: "codex-exit"}); err != nil || rep.Count(OutSealed) != 1 {
		t.Fatalf("seal %+v %v", rep, err)
	}
	t.Logf("PERF-3: first snapshot in %v", time.Since(start))
	m := meter(h.Base)
	start = time.Now()
	if rep, err := Restore(tctx(t), e, keys, RestoreRequest{Units: []harness.UnitRef{u.Ref()}}); err != nil || rep.Count(OutRestored) != 1 {
		t.Fatalf("restore %+v %v", rep, err)
	}
	staged := m.extra()
	t.Logf("PERF-3: restore in %v, peak extra disk %d bytes", time.Since(start), staged)
	if total := treeBytes(home); staged > total+total/10 {
		t.Fatalf("restore peak extra disk %d > one staging unit (%d)", staged, total)
	}
	f, err := os.OpenFile(rollout, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{\"type\":\"event\"}\n")
	f.Close()
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(rollout, old, old)
	st, _ := os.Stat(rollout)
	m = meter(h.Base)
	start = time.Now()
	if rep, err := Seal(tctx(t), e, scan(), Options{Reason: "codex-exit"}); err != nil || rep.Count(OutSealed) != 1 {
		t.Fatalf("re-seal %+v %v", rep, err)
	}
	extra := m.extra()
	t.Logf("PERF-3: re-seal in %v, peak extra disk %d bytes (changed rollout %d bytes)", time.Since(start), extra, st.Size())
	if limit := st.Size() + st.Size()/10 + 1<<20; extra > limit {
		t.Fatalf("re-seal peak extra disk %d > the changed blob (%d): an unchanged blob was rewritten", extra, limit)
	}
}

// appendFrom appends src to dst and removes src.
func appendFrom(t *testing.T, dst, src string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	in.Close()
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(dst, old, old)
}
