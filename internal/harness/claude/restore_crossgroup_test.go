//go:build crossgroup

package claude_test

// DC-30 end to end with G4's sweep and G1's vaults: a sealed session whose
// projects/<P> was deleted restores (the project index recorded <P> at the
// seal), and the restored session — its ledger went into the capsule — is
// sealed again by the next sweep of its locked folder.

import (
	"bytes"
	"context"
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
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

// xQuiet is the stability window of the sweeps below.
const xQuiet = 10 * time.Second

// xKeys releases file keys from the vaulttest keyring for logged capsules
// (what the daemon does after its checks, D39).
type xKeys struct {
	fx       *vaulttest.Fixture
	capsules string
	log      *capslog.Log
}

type xKeySet struct {
	mu   sync.Mutex
	keys map[string]*memguard.LockedBuffer
}

func (k *xKeySet) Key(p string) (*memguard.LockedBuffer, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.keys[p]
	return b, ok
}

func (k *xKeySet) Destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, b := range k.keys {
		b.Destroy()
	}
	k.keys = map[string]*memguard.LockedBuffer{}
}

func (k *xKeys) FileKeys(ctx context.Context, paths []string, purpose string) (sweep.FileKeys, error) {
	all, err := k.log.All()
	if err != nil {
		return nil, err
	}
	vaultOf := map[string]string{}
	for _, en := range all {
		vaultOf[en.Path] = en.VaultID
	}
	set := &xKeySet{keys: map[string]*memguard.LockedBuffer{}}
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

// xStack is a fake HOME wired like cmd/precinto, with a clock at the real
// time (files and directories carry real times; a fixed clock in the past
// would make their mtimes "in the future", R16).
type xStack struct {
	h     *testkit.Home
	fx    *vaulttest.Fixture
	keys  *xKeys
	cfg   config.Config
	salt  []byte
	led   *ledger.Ledger
	clock *fakeplatform.Clock
}

func newXStack(t *testing.T) *xStack {
	t.Helper()
	h := testkit.NewHome(t)
	fx := vaulttest.New(t, h.Base, "root-acme")
	salt, err := capsule.LoadSalt(h.Layout.NameSalt)
	if err != nil {
		t.Fatal(err)
	}
	s := &xStack{h: h, fx: fx, cfg: h.Cfg, salt: salt, led: ledger.Open(h.Layout.SessionsDir), clock: fakeplatform.NewClock(time.Now())}
	s.cfg.Policy.QuietWindow = config.Duration(xQuiet)
	s.keys = &xKeys{fx: fx, capsules: h.Layout.CapsulesDir, log: capslog.Open(h.Layout.CapsuleLog)}
	return s
}

// env is one sweep process: its own engine and observer (SPEC §13.1, D63),
// every folder locked, the single quiet-window wait advancing the clock.
func (s *xStack) env() sweep.Env {
	h := s.h
	eng := &live.Engine{Procs: h.Procs, Clock: s.clock, LeasesDir: h.Layout.LeasesDir, Observer: live.NewObserver(s.clock),
		Quiet: xQuiet, HoldCap: 24 * time.Hour}
	henv := harness.Env{Cfg: s.cfg, Layout: h.Layout, Ledger: s.led,
		Index: func(id string) *ledger.Index { return ledger.OpenIndex(h.Layout.ProjectsDir, id) },
		Live:  eng, Procs: h.Procs, Clock: s.clock, Salt: s.salt, Host: h.Env}
	return sweep.Env{Cfg: s.cfg, Harness: henv, Adapters: []harness.Adapter{claude.New()}, Vaults: s.fx.Store,
		Log: capslog.Open(h.Layout.CapsuleLog), Journal: journal.Open(h.Layout.JournalDir), Live: eng, Procs: h.Procs,
		Clock: s.clock, Grants: func(context.Context) (map[string]bool, error) { return map[string]bool{}, nil },
		Floor: fsx.Floor{}, Sealer: "precinto crossgroup", Parallel: 2,
		Sleep: func(ctx context.Context, d time.Duration) error {
			s.clock.Advance(d)
			return ctx.Err()
		}}
}

func unitResult(rep *sweep.Report, k capsule.Kind, o sweep.Outcome) *sweep.UnitResult {
	for i := range rep.Units {
		if rep.Units[i].Kind == k && rep.Units[i].Outcome == o {
			return &rep.Units[i]
		}
	}
	return nil
}

func TestCrossRestoreRecreatesADeletedProjectDir(t *testing.T) {
	s := newXStack(t)
	h := s.h
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	l := claudetest.New(t, h.Dir)
	paths := l.WriteSession(t, claudetest.Session{SID: sid1, Cwd: h.Root, Marker: testkit.Marker(t), Subagents: 1,
		ModTime: time.Now().Add(-time.Hour)})
	if err := s.led.Append(ledger.Event{Type: ledger.TypeStart, Harness: "claude-code", SID: sid1, Source: "startup",
		Roots: []string{"root-acme"}, Cwd: h.Root, ConfigDir: h.ClaudeConfig, TmpDir: h.ClaudeTmp}); err != nil {
		t.Fatal(err)
	}
	orig := map[string][]byte{}
	tmpFiles := 0
	for _, p := range paths {
		if !strings.Contains(p, sid1) {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		orig[p] = b
		if strings.HasPrefix(p, h.ClaudeTmp+string(filepath.Separator)) {
			tmpFiles++
		}
	}
	if tmpFiles == 0 {
		t.Fatal("the fixture has no $TMP files")
	}
	rep, err := sweep.Sweep(ctx, s.env(), sweep.Options{Reason: "lock", Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	res := unitResult(rep, capsule.KindClaudeSession, sweep.OutSealed)
	if res == nil {
		t.Fatalf("session not sealed: %+v", rep.Units)
	}
	for p := range orig {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("plaintext left after the seal: %s", filepath.Base(p))
		}
	}

	// The user (or Claude's cleanup) deletes the project directory while
	// the session is sealed.
	proj := filepath.Dir(paths[0])
	if filepath.Dir(proj) != filepath.Join(h.ClaudeConfig, "projects") {
		t.Fatalf("fixture transcript is not in projects/<P>: %s", paths[0])
	}
	if err := os.RemoveAll(proj); err != nil {
		t.Fatal(err)
	}
	rep, err = sweep.Restore(ctx, s.env(), s.keys, sweep.RestoreRequest{Units: []harness.UnitRef{{Harness: harness.ClaudeCode,
		Kind: capsule.KindClaudeSession, Key: res.Unit}}})
	if err != nil || rep.Count(sweep.OutRestored) != 1 {
		t.Fatalf("restore after projects/<P> was deleted: %+v %v", rep, err)
	}
	for p, b := range orig {
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("%s not restored exactly (%v)", filepath.Base(p), err)
		}
	}
	if fi, err := os.Lstat(proj); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("projects/<P> not recreated 0700: %v %v", fi, err)
	}

	// The next lock, later: a new sweep process seals the restored session
	// again (unchanged: no new generation, D10) although its ledger is gone.
	s.clock.Advance(time.Hour)
	if _, err := s.led.Get("claude-code", sid1); err == nil {
		t.Fatal("the ledger was not archived into the capsule (S13)")
	}
	rep, err = sweep.Sweep(ctx, s.env(), sweep.Options{Reason: "lock", Lock: true})
	if err != nil {
		t.Fatal(err)
	}
	if unitResult(rep, capsule.KindClaudeSession, sweep.OutUnchanged) == nil {
		t.Fatalf("re-seal of the restored session: %+v", rep.Units)
	}
	for p := range orig {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("plaintext left after the re-seal: %s", filepath.Base(p))
		}
	}
	if gens, err := sweep.Generations(s.env(), res.Unit); err != nil || len(gens) != 1 {
		t.Fatalf("%d generations (%v), want 1", len(gens), err)
	}
}
