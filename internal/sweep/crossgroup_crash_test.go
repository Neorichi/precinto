//go:build crossgroup && failpoints

package sweep

// Crash cases over the real stack (capsule, fsx, vault, adapters): the
// keyless seal and rotation paths, killed at sweep's own points and at
// capsule.Seal's internal ones. A crash inside capsule.Seal leaves its
// temporaries (or its renamed capsule) in the journaled operation
// directory, which recovery removes whatever names capsule chose.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/fsx/failpoint"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

const realSID = "00000000-0000-4000-8000-0000000000d1"

// liveClock is the wall clock plus the waits a run skipped: Sleep advances
// it instead of sleeping (D63's quiet window passes at once), and it never
// falls behind real time, so files a test or a restore creates now are
// never "in the future" for the liveness engine (R16), whatever the date
// (a fake clock fixed at testkit.Epoch falls behind once that hour has
// passed).
type liveClock struct {
	mu     sync.Mutex
	origin time.Time
	ahead  time.Duration
}

func newLiveClock() *liveClock { return &liveClock{origin: time.Now()} }

func (c *liveClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.ahead).Round(0).UTC()
}

func (c *liveClock) Mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.origin) + c.ahead
}

// Advance moves the clock d ahead of real time.
func (c *liveClock) Advance(d time.Duration) {
	if d > 0 {
		c.mu.Lock()
		c.ahead += d
		c.mu.Unlock()
	}
}

// sleepOn is an Env.Sleep that advances c instead of sleeping.
func sleepOn(c *liveClock) func(ctx context.Context, d time.Duration) error {
	return func(ctx context.Context, d time.Duration) error {
		c.Advance(d)
		return ctx.Err()
	}
}

// realEnv wires the real components over a fake home whose vault store
// already exists (sealing needs only its public recipients).
func realEnv(t *testing.T, h *testkit.Home) Env {
	t.Helper()
	salt, err := capsule.LoadSalt(h.Layout.NameSalt)
	if err != nil {
		t.Fatal(err)
	}
	// D63: the engine needs two looks a quiet window apart; the run's single
	// wait advances the clock (Env.Sleep) instead of sleeping.
	clk := newLiveClock()
	eng := &live.Engine{Procs: h.Procs, Clock: clk, LeasesDir: h.Layout.LeasesDir, Observer: live.NewObserver(clk),
		Quiet: 10 * time.Second}
	cfg := h.Cfg
	cfg.Policy.QuietWindow = config.Duration(10 * time.Second)
	led := ledger.Open(h.Layout.SessionsDir)
	return Env{Cfg: cfg, Harness: harness.Env{Cfg: cfg, Layout: h.Layout, Ledger: led, Live: eng, Procs: h.Procs, Clock: clk,
		Salt: salt, Host: h.Env, Index: func(id string) *ledger.Index { return ledger.OpenIndex(h.Layout.ProjectsDir, id) }},
		Adapters: []harness.Adapter{claude.New(), codex.New()},
		Vaults:   vault.OpenStore(h.Layout.VaultsDir, h.Layout.VerifiedDir, h.Layout.FactorsDir),
		Log:      capslog.Open(h.Layout.CapsuleLog), Journal: journal.Open(h.Layout.JournalDir), Live: eng,
		Procs: h.Procs, Clock: clk, Sealer: "precinto crossgroup", Parallel: 1, Sleep: sleepOn(clk)}
}

func realCrash(t *testing.T, spec string, setup func(h *testkit.Home), act func(e Env), check func(h *testkit.Home, e Env)) {
	if dir := os.Getenv("SWEEP_XCRASH_DIR"); dir != "" {
		if os.Getenv("SWEEP_XCRASH_TEST") != t.Name() {
			t.Skip("another crash case")
		}
		holdLifeline()
		h := homeAt(t, dir, os.Getenv("SWEEP_XCRASH_RUN"))
		failpoint.Set(spec)
		act(realEnv(t, h))
		os.Exit(7)
	}
	h := testkit.NewHome(t)
	vaulttest.New(t, h.Base, "root-acme")
	setup(h)
	runCrashChild(t, "SWEEP_XCRASH_DIR="+h.Dir, "SWEEP_XCRASH_RUN="+h.RunDir, "SWEEP_XCRASH_TEST="+t.Name())
	e := realEnv(t, h)
	r := newRun(e, prodPorts(e))
	if err := r.recoverAll(tctx(t)); err != nil {
		t.Fatal(err)
	}
	r2 := newRun(e, prodPorts(e))
	if err := r2.recoverAll(tctx(t)); err != nil || len(r2.finish().Units) != 0 {
		t.Fatalf("O6: second recovery %v", err)
	}
	q := newRun(e, prodPorts(e))
	if err := q.quarantine(tctx(t)); err != nil || q.finish().Count(OutQuarantined) != 0 {
		t.Fatalf("O7: own leftovers quarantined (%v)", err)
	}
	check(h, e)
}

func writeRealSession(t *testing.T, h *testkit.Home) map[string][]byte {
	l := claudetest.New(t, h.Dir)
	paths := l.WriteSession(t, claudetest.Session{SID: realSID, Cwd: h.Root, Subagents: 1, ModTime: time.Now().Add(-time.Hour)})
	if err := ledger.Open(h.Layout.SessionsDir).Append(ledger.Event{Type: ledger.TypeTaint, Harness: "claude-code", SID: realSID,
		Roots: []string{"root-acme"}, Cwd: h.Root, ConfigDir: h.ClaudeConfig}); err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, p := range paths {
		if strings.Contains(p, realSID) {
			b, _ := os.ReadFile(p)
			out[p] = b
		}
	}
	return out
}

// sessionsOnly scopes a sweep to Claude sessions, so a crash point's
// first hit is the session's seal (the project unit is sealed too
// otherwise, and first).
var sessionsOnly = harness.Scope{Kinds: []capsule.Kind{capsule.KindClaudeSession}}

func sweepAct(e Env) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, _ = Sweep(ctx, e, Options{Reason: "lock", Scope: sessionsOnly})
}

func noOpDirs(t *testing.T, h *testkit.Home) {
	_ = filepath.Walk(h.Layout.CapsulesDir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.IsDir() && strings.HasPrefix(fi.Name(), ".op-") {
			t.Errorf("operation directory left: %s", fi.Name()) // never since CC-01
		}
		return nil
	})
}

// realSessionFiles is the number of files (capsule inputs) of
// writeRealSession's session.
const realSessionFiles = 10

func realSealCrash(t *testing.T, spec string, forward bool) {
	var orig map[string][]byte
	realCrash(t, spec, func(h *testkit.Home) {
		orig = writeRealSession(t, h)
		if len(orig) != realSessionFiles {
			t.Fatalf("the real session has %d files, want %d", len(orig), realSessionFiles)
		}
	}, sweepAct, func(h *testkit.Home, e Env) {
		noOpDirs(t, h)
		for p, b := range orig {
			got, err := os.ReadFile(p)
			switch {
			case forward && err == nil:
				t.Fatalf("plaintext %s left after a committed seal", filepath.Base(p))
			case !forward && (err != nil || string(got) != string(b)):
				t.Fatalf("plaintext %s lost", filepath.Base(p))
			}
		}
		rep, err := Sweep(tctx(t), e, Options{})
		if err != nil || rep.Count(OutFailed) != 0 {
			t.Fatalf("sweep after recovery %+v %v", rep, err)
		}
	})
}

func TestXCrashSealPrepared(t *testing.T) { realSealCrash(t, "seal.prepared", false) }

// SEAL-2 with the real capsule.Seal: killed after the middle input of the
// session is streamed into the temporary.
func TestXCrashCapsuleStreamed(t *testing.T) {
	realSealCrash(t, "capsule.streamed:"+strconv.Itoa(realSessionFiles/2), false)
}

func TestXCrashCapsuleTmpWritten(t *testing.T) { realSealCrash(t, "capsule.tmp_written", false) }
func TestXCrashCapsuleVerified(t *testing.T)   { realSealCrash(t, "capsule.verified", false) }

// SEAL-6 with the real capsule.Seal: renamed, never logged.
func TestXCrashCapsuleRenamed(t *testing.T) { realSealCrash(t, "capsule.renamed", false) }

// SEAL-7 with the real stack: logged, committed never journaled.
func TestXCrashSealLogged(t *testing.T) { realSealCrash(t, "seal.logged", true) }

func TestXCrashSealCommitted(t *testing.T) { realSealCrash(t, "seal.committed", true) }
func TestXCrashSealUnlinking(t *testing.T) { realSealCrash(t, "seal.unlinking:2", true) }

// An errno at the first rename of a seal: the attempt is abandoned
// cleanly and the plaintext stays. Hit counts are process-wide, so the
// point is reset right before it is armed.
func TestXSealRenameEIO(t *testing.T) {
	defer failpoint.Reset()
	h := testkit.NewHome(t)
	vaulttest.New(t, h.Base, "root-acme")
	orig := writeRealSession(t, h)
	e := realEnv(t, h)
	failpoint.Reset()
	failpoint.Set("fsx.rename=errno:EIO:1")
	rep, _ := Sweep(tctx(t), e, Options{Scope: sessionsOnly})
	if failpoint.Hits("fsx.rename") == 0 {
		t.Fatal("the seal renamed nothing: the fault was never reached")
	}
	if rep.Count(OutSealed) != 0 || rep.Count(OutFailed) != 1 {
		t.Fatalf("sealed through a failed rename: %+v", rep.Units)
	}
	failpoint.Reset()
	for p, b := range orig {
		if got, _ := os.ReadFile(p); string(got) != string(b) {
			t.Fatal("plaintext changed")
		}
	}
	noOpDirs(t, h)
	_ = fsx.ErrExist
}
