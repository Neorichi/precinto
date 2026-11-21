//go:build crossgroup

package sweep_test

// Cross-group tests: the exported API over the real implementations of the
// other groups (internal/capsule, internal/fsx, internal/vault with
// vaulttest, the Claude and Codex adapters, internal/live and
// internal/ledger). They compile in G4's worktree and run at integration
// (go test -tags testing,crossgroup ./internal/sweep/).

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/harness/codex/codextest"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

const (
	xRoot = "root-acme"
	xSID  = "00000000-0000-4000-8000-0000000000c1"
	xSID2 = "00000000-0000-4000-8000-0000000000c2"
)

// stack is a fake HOME with every real component wired like cmd/precinto.
type stack struct {
	h    *testkit.Home
	e    sweep.Env
	fx   *vaulttest.Fixture
	keys *vaultKeys
}

func newStack(t *testing.T) *stack {
	t.Helper()
	h := testkit.NewHome(t)
	fx := vaulttest.New(t, h.Base, xRoot)
	salt, err := capsule.LoadSalt(h.Layout.NameSalt)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.Open(h.Layout.SessionsDir)
	// D63: the engine needs two looks a quiet window apart; the run's single
	// wait advances the fake clock (Env.Sleep) instead of sleeping.
	eng := &live.Engine{Procs: h.Procs, Clock: h.Clock, LeasesDir: h.Layout.LeasesDir, Observer: live.NewObserver(h.Clock),
		Quiet: 10 * time.Second, HoldCap: 24 * time.Hour}
	cfg := h.Cfg
	cfg.Policy.QuietWindow = config.Duration(10 * time.Second)
	henv := harness.Env{Cfg: cfg, Layout: h.Layout, Ledger: led,
		Index: func(id string) *ledger.Index { return ledger.OpenIndex(h.Layout.ProjectsDir, id) },
		Live:  eng, Procs: h.Procs, Clock: h.Clock, Salt: salt, Host: h.Env}
	s := &stack{h: h, fx: fx}
	s.keys = &vaultKeys{fx: fx, capsules: h.Layout.CapsulesDir, log: capslog.Open(h.Layout.CapsuleLog)}
	s.e = sweep.Env{Cfg: cfg, Harness: henv, Adapters: []harness.Adapter{claude.New(), codex.New()}, Vaults: fx.Store,
		Log: capslog.Open(h.Layout.CapsuleLog), Journal: journal.Open(h.Layout.JournalDir), Live: eng, Procs: h.Procs,
		Clock: h.Clock, Grants: func(context.Context) (map[string]bool, error) { return map[string]bool{}, nil },
		Floor: fsx.Floor{}, Sealer: "precinto crossgroup", Parallel: 2,
		Sleep: func(ctx context.Context, d time.Duration) error {
			h.Clock.Advance(d)
			return ctx.Err()
		}}
	return s
}

// vaultKeys releases file keys from the vaulttest keyring for logged
// capsules (what the daemon does after its checks, D39).
type vaultKeys struct {
	fx       *vaulttest.Fixture
	capsules string
	log      *capslog.Log
	mu       sync.Mutex
	purposes []string
	deny     bool
}

type keySet struct {
	mu   sync.Mutex
	keys map[string]*memguard.LockedBuffer
}

func (k *keySet) Key(p string) (*memguard.LockedBuffer, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.keys[p]
	return b, ok
}

func (k *keySet) Destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, b := range k.keys {
		b.Destroy()
	}
	k.keys = map[string]*memguard.LockedBuffer{}
}

func (k *vaultKeys) FileKeys(ctx context.Context, paths []string, purpose string) (sweep.FileKeys, error) {
	k.mu.Lock()
	k.purposes = append(k.purposes, purpose)
	deny := k.deny
	k.mu.Unlock()
	if deny {
		return nil, sweep.ErrKeyDenied
	}
	all, err := k.log.All()
	if err != nil {
		return nil, err
	}
	vaultOf := map[string]string{}
	for _, en := range all {
		vaultOf[en.Path] = en.VaultID
	}
	set := &keySet{keys: map[string]*memguard.LockedBuffer{}}
	for _, p := range paths {
		id, ok := vaultOf[p]
		if !ok {
			continue // never for unlogged capsules (I14)
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

// session writes a managed Claude session (tainted in the ledger, as the
// hooks do).
func (s *stack) session(t *testing.T, sid, marker string) []string {
	t.Helper()
	l := claudetest.New(t, s.h.Dir)
	paths := l.WriteSession(t, claudetest.Session{SID: sid, Cwd: s.h.Root, Marker: marker, Subagents: 1,
		ModTime: testkit.Epoch.Add(-time.Hour)})
	if err := s.e.Harness.Ledger.Append(ledger.Event{Type: ledger.TypeTaint, Harness: string(harness.ClaudeCode), SID: sid,
		Roots: []string{xRoot}, Cwd: s.h.Root, ConfigDir: s.h.ClaudeConfig, TmpDir: s.h.ClaudeTmp}); err != nil {
		t.Fatal(err)
	}
	return paths
}

func contents(t *testing.T, paths []string) map[string][]byte {
	out := map[string][]byte{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[p] = b
	}
	return out
}

func resultOfKind(rep *sweep.Report, k capsule.Kind, o sweep.Outcome) *sweep.UnitResult {
	for i := range rep.Units {
		if rep.Units[i].Kind == k && rep.Units[i].Outcome == o {
			return &rep.Units[i]
		}
	}
	return nil
}

// I2/I3/I7 with the real stack: a locked-folder sweep seals a managed
// session into a verified capsule, deletes the plaintext, leaks nothing;
// the restore brings back exact bytes.
func TestCrossgroupClaudeSessionRoundTrip(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	mrk := testkit.Marker(t)
	paths := s.session(t, xSID, mrk)
	sessionPaths := filterSID(paths, xSID)
	orig := contents(t, sessionPaths)
	rep, err := sweep.Sweep(ctx, s.e, sweep.Options{Reason: "lock", Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	res := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutSealed)
	if res == nil {
		t.Fatalf("session not sealed: %+v", rep.Units)
	}
	for p := range orig {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("plaintext left: %s", filepath.Base(p))
		}
	}
	if hits := testkit.GrepTree(t, s.h.Base, mrk, "capsules"); len(hits) != 0 {
		t.Fatalf("I7: marker leaked: %v", hits)
	}
	rep, err = sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: []harness.UnitRef{{Harness: harness.ClaudeCode,
		Kind: capsule.KindClaudeSession, Key: res.Unit}}})
	if err != nil || rep.Count(sweep.OutRestored) != 1 {
		t.Fatalf("restore %+v %v", rep, err)
	}
	for p, b := range orig {
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("%s not restored exactly", filepath.Base(p))
		}
	}
	// Unchanged plaintext re-seals without a new generation (D10).
	rep, _ = sweep.Sweep(ctx, s.e, sweep.Options{})
	if resultOfKind(rep, capsule.KindClaudeSession, sweep.OutUnchanged) == nil {
		t.Fatalf("re-seal %+v", rep.Units)
	}
	gens, _ := sweep.Generations(s.e, res.Unit)
	if len(gens) != 1 {
		t.Fatalf("%d generations", len(gens))
	}
}

func filterSID(paths []string, sid string) []string {
	var out []string
	for _, p := range paths {
		if strings.Contains(p, sid) {
			out = append(out, p)
		}
	}
	return out
}

// SEC-1 with real ciphertext: a capsule sealed to the vault but never
// logged is quarantined, never restored, and gets no key.
func TestCrossgroupForgedCapsuleIsQuarantined(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	s.session(t, xSID, "")
	rep, _ := sweep.Sweep(ctx, s.e, sweep.Options{})
	res := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutSealed)
	if res == nil {
		t.Fatalf("seal %+v", rep.Units)
	}
	// Copy the genuine capsule under an unlogged generation name.
	dir := filepath.Join(s.h.Layout.CapsulesDir, "claude-code", res.Unit)
	b, err := os.ReadFile(filepath.Join(dir, "g000001.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "g000099.pcap"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	q, err := sweep.Quarantine(ctx, s.e)
	if err != nil || q.Count(sweep.OutQuarantined) != 1 {
		t.Fatalf("quarantine %+v %v", q, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "g000099.pcap")); err == nil {
		t.Fatal("forged capsule left in the store")
	}
}

// SEC-2 with real crypto: a logged capsule whose manifest names another
// session's id under this unit's key is refused (exit 5), zero writes.
func TestCrossgroupManifestUnitIDIsAuthenticated(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	s.session(t, xSID, "")
	rep, _ := sweep.Sweep(ctx, s.e, sweep.Options{})
	res := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutSealed)
	if res == nil {
		t.Fatalf("seal %+v", rep.Units)
	}
	recips, fpr, err := s.fx.Store.Recipients(xRoot)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(s.h.Dir, "forge")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "x.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err := fsx.OpenBase(src)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := sd.Lstat("x.jsonl")
	out, err := fsx.OpenBase(filepath.Join(s.h.Layout.CapsulesDir, "claude-code", res.Unit))
	if err != nil {
		t.Fatal(err)
	}
	man := capsule.Manifest{Format: 1, Kind: capsule.KindClaudeSession, Harness: "claude-code", UnitKey: res.Unit, UnitID: xSID2,
		VaultID: xRoot, RootIDs: []string{xRoot}, Gen: 2, Parent: 1, Lineage: capsule.LineageDiverged, RecipientsFpr: fpr}
	sealed, err := capsule.Seal(ctx, capsule.SealRequest{Manifest: man, Recipients: recips, Out: out, Name: "g000002.pcap",
		Inputs: []capsule.Input{{Base: capsule.BaseClaudeConfig, Dir: sd, Rel: "x.jsonl", Snap: st}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.e.Log.Append(capslog.Entry{Path: "claude-code/" + res.Unit + "/g000002.pcap", SHA256: sealed.SHA256,
		HeaderSHA256: sealed.HeaderSHA256, Size: sealed.Size, Kind: "claude-session", Harness: "claude-code", Unit: res.Unit,
		VaultID: xRoot, RootIDs: []string{xRoot}, Gen: 2, Parent: 1, Lineage: "diverged", SealedAt: testkit.Epoch}); err != nil {
		t.Fatal(err)
	}
	before := snapshotFiles(t, s.h.Dir)
	rep, err = sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: []harness.UnitRef{{Kind: capsule.KindClaudeSession, Key: res.Unit}}})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(rep.Err(), harness.ErrUnitKey) {
		t.Fatalf("Err = %v, want ErrUnitKey (exit 5)", rep.Err())
	}
	for p := range snapshotFiles(t, s.h.Dir) {
		if !before[p] && !strings.Contains(p, string(filepath.Separator)+"base"+string(filepath.Separator)) {
			t.Fatalf("written: %s", p)
		}
	}
}

func snapshotFiles(t *testing.T, dir string) map[string]bool {
	out := map[string]bool{}
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			out[p] = true
		}
		return nil
	})
	return out
}

// D16/D51 with the real file system: notes seal with a marker and come
// back at the marker location or their relpath.
func TestCrossgroupNotes(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	p := filepath.Join(s.h.Root, "docs", "notes.md")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("# notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := testkit.Epoch.Add(-time.Hour)
	_ = os.Chtimes(p, old, old)
	if err := s.e.Harness.Ledger.Append(ledger.Event{Type: ledger.TypeMarkdown, Harness: "claude-code", SID: xSID, Path: p, Roots: []string{xRoot}}); err != nil {
		t.Fatal(err)
	}
	_ = s.e.Harness.Ledger.Append(ledger.Event{Type: ledger.TypeEnd, Harness: "claude-code", SID: xSID, Reason: "other"})
	root, _ := s.e.Cfg.RootByID(xRoot)
	rep, err := sweep.SealMarkdown(ctx, s.e, root, sweep.Options{})
	if err != nil || rep.Count(sweep.OutSealed) != 1 {
		t.Fatalf("seal notes %+v %v", rep, err)
	}
	if k, err := sweep.ParseMarker(p + ".precinto"); err != nil || k == "" {
		t.Fatalf("marker %v", err)
	}
	rep, err = sweep.RestoreMarkdown(ctx, s.e, s.keys, root)
	if err != nil || rep.Count(sweep.OutRestored) != 1 {
		t.Fatalf("restore notes %+v %v", rep, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "# notes\n" {
		t.Fatal("note not restored")
	}
}

// D31/D42 with the real Codex adapter: snapshot seal and exact restore.
func TestCrossgroupCodexHome(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	home := s.h.Layout.CodexHome(xRoot)
	if err := os.MkdirAll(filepath.Dir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	codextest.New(t, home, codextest.Options{Rollouts: 2, WithWAL: true, Marker: testkit.Marker(t)})
	units, err := codex.New().Scan(ctx, s.e.Harness, harness.Scope{RootIDs: []string{xRoot}, Kinds: []capsule.Kind{capsule.KindCodexHome}})
	if err != nil || len(units) != 1 {
		t.Fatalf("scan %v %v", units, err)
	}
	var paths []string
	for _, f := range units[0].Files {
		paths = append(paths, filepath.Join(home, filepath.FromSlash(f.Rel)))
	}
	orig := contents(t, paths)
	rep, err := sweep.Seal(ctx, s.e, units, sweep.Options{Reason: "codex-exit"})
	if err != nil || rep.Count(sweep.OutSealed) != 1 {
		t.Fatalf("seal %+v %v", rep, err)
	}
	rep, err = sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: []harness.UnitRef{units[0].Ref()}})
	if err != nil || rep.Count(sweep.OutRestored) != 1 {
		t.Fatalf("restore %+v %v", rep, err)
	}
	for p, b := range orig {
		if got, _ := os.ReadFile(p); !bytes.Equal(got, b) {
			t.Fatalf("%s differs", filepath.Base(p))
		}
	}
}

// D21/D36 with the real history parser: rotation and merge-back.
func TestCrossgroupHistoryRotation(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	l := claudetest.New(t, s.h.Dir)
	l.WriteHistory(t, s.h.Root, xSID, 4, testkit.Marker(t))
	l.WriteHistory(t, filepath.Join(s.h.HomeDir, "elsewhere"), xSID2, 2, testkit.Marker(t))
	before, _ := os.ReadFile(filepath.Join(s.h.ClaudeConfig, "history.jsonl"))
	rep, err := sweep.RotateHistory(ctx, s.e)
	if err != nil || rep.Count(sweep.OutSealed) != 1 {
		t.Fatalf("rotate %+v %v", rep, err)
	}
	after, _ := os.ReadFile(filepath.Join(s.h.ClaudeConfig, "history.jsonl"))
	if bytes.Contains(after, []byte(s.h.Root)) {
		t.Fatal("protected lines left")
	}
	rep, err = sweep.MergeHistory(ctx, s.e, s.keys, xRoot)
	if err != nil || rep.Count(sweep.OutMerged) != 1 {
		t.Fatalf("merge %+v %v", rep, err)
	}
	merged, _ := os.ReadFile(filepath.Join(s.h.ClaudeConfig, "history.jsonl"))
	if len(merged) != len(before) {
		t.Fatalf("merge-back: %d bytes, want %d", len(merged), len(before))
	}
}

// D39/D28: a denied key source writes nothing.
func TestCrossgroupDeniedKeys(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	paths := s.session(t, xSID, "")
	rep, _ := sweep.Sweep(ctx, s.e, sweep.Options{})
	res := resultOfKind(rep, capsule.KindClaudeSession, sweep.OutSealed)
	if res == nil {
		t.Fatal("seal")
	}
	s.keys.deny = true
	rep, _ = sweep.Restore(ctx, s.e, s.keys, sweep.RestoreRequest{Units: []harness.UnitRef{{Kind: capsule.KindClaudeSession, Key: res.Unit}}})
	if !errors.Is(rep.Err(), sweep.ErrKeyDenied) {
		t.Fatalf("Err %v", rep.Err())
	}
	for _, p := range filterSID(paths, xSID) {
		if _, err := os.Lstat(p); err == nil {
			t.Fatal("written without a key")
		}
	}
}
