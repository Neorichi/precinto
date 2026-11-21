//go:build crossgroup && failpoints

package sweep

// Crash cases over the real stack (capsule, fsx, vault, adapters): the
// keyless seal and rotation paths, killed at sweep's own points and at
// capsule.Seal's internal ones. A crash inside capsule.Seal leaves its
// temporaries (or its renamed capsule) in the journaled operation
// directory, which recovery removes whatever names capsule chose.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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

// realEnv wires the real components over a fake home whose vault store
// already exists (sealing needs only its public recipients).
func realEnv(t *testing.T, h *testkit.Home) Env {
	t.Helper()
	salt, err := capsule.LoadSalt(h.Layout.NameSalt)
	if err != nil {
		t.Fatal(err)
	}
	eng := &live.Engine{Procs: h.Procs, Clock: h.Clock, LeasesDir: h.Layout.LeasesDir, Observer: live.NewObserver(h.Clock)}
	cfg := h.Cfg
	cfg.Policy.QuietWindow = config.Duration(0)
	led := ledger.Open(h.Layout.SessionsDir)
	return Env{Cfg: cfg, Harness: harness.Env{Cfg: cfg, Layout: h.Layout, Ledger: led, Live: eng, Procs: h.Procs, Clock: h.Clock,
		Salt: salt, Host: h.Env, Index: func(id string) *ledger.Index { return ledger.OpenIndex(h.Layout.ProjectsDir, id) }},
		Adapters: []harness.Adapter{claude.New(), codex.New()},
		Vaults:   vault.OpenStore(h.Layout.VaultsDir, h.Layout.VerifiedDir, h.Layout.FactorsDir),
		Log:      capslog.Open(h.Layout.CapsuleLog), Journal: journal.Open(h.Layout.JournalDir), Live: eng,
		Procs: h.Procs, Clock: h.Clock, Sealer: "precinto crossgroup", Parallel: 1}
}

func realCrash(t *testing.T, spec string, setup func(h *testkit.Home), act func(e Env), check func(h *testkit.Home, e Env)) {
	if dir := os.Getenv("SWEEP_XCRASH_DIR"); dir != "" {
		if os.Getenv("SWEEP_XCRASH_TEST") != t.Name() {
			t.Skip("another crash case")
		}
		h := homeAt(t, dir, os.Getenv("SWEEP_XCRASH_RUN"))
		failpoint.Set(spec)
		act(realEnv(t, h))
		os.Exit(7)
	}
	h := testkit.NewHome(t)
	vaulttest.New(t, h.Base, "root-acme")
	setup(h)
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), "SWEEP_XCRASH_DIR="+h.Dir, "SWEEP_XCRASH_RUN="+h.RunDir, "SWEEP_XCRASH_TEST="+t.Name())
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("child not killed (%v):\n%s", err, out)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("child status %v:\n%s", ee, out)
	}
	e := realEnv(t, h)
	r := newRun(e, prodPorts(e))
	if err := r.recoverAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	r2 := newRun(e, prodPorts(e))
	if err := r2.recoverAll(context.Background()); err != nil || len(r2.finish().Units) != 0 {
		t.Fatalf("O6: second recovery %v", err)
	}
	q := newRun(e, prodPorts(e))
	if err := q.quarantine(context.Background()); err != nil || q.finish().Count(OutQuarantined) != 0 {
		t.Fatalf("O7: own leftovers quarantined (%v)", err)
	}
	check(h, e)
}

func writeRealSession(t *testing.T, h *testkit.Home) map[string][]byte {
	l := claudetest.New(t, h.Dir)
	paths := l.WriteSession(t, claudetest.Session{SID: realSID, Cwd: h.Root, Subagents: 1, ModTime: testkit.Epoch.Add(-time.Hour)})
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

func sweepAct(e Env) { _, _ = Sweep(context.Background(), e, Options{Reason: "lock"}) }

func noOpDirs(t *testing.T, h *testkit.Home) {
	_ = filepath.Walk(h.Layout.CapsulesDir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.IsDir() && strings.HasPrefix(fi.Name(), ".op-") {
			t.Errorf("operation directory left: %s", fi.Name()) // never since CC-01
		}
		return nil
	})
}

func realSealCrash(t *testing.T, spec string, forward bool) {
	var orig map[string][]byte
	realCrash(t, spec, func(h *testkit.Home) { orig = writeRealSession(t, h) }, sweepAct, func(h *testkit.Home, e Env) {
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
		rep, err := Sweep(context.Background(), e, Options{})
		if err != nil || rep.Count(OutFailed) != 0 {
			t.Fatalf("sweep after recovery %+v %v", rep, err)
		}
	})
}

func TestXCrashSealPrepared(t *testing.T)      { realSealCrash(t, "seal.prepared", false) }
func TestXCrashCapsuleTmpWritten(t *testing.T) { realSealCrash(t, "capsule.tmp_written", false) }
func TestXCrashCapsuleVerified(t *testing.T)   { realSealCrash(t, "capsule.verified", false) }
func TestXCrashCapsuleRenamed(t *testing.T)    { realSealCrash(t, "capsule.renamed", false) }
func TestXCrashSealCommitted(t *testing.T)     { realSealCrash(t, "seal.committed", true) }
func TestXCrashSealUnlinking(t *testing.T)     { realSealCrash(t, "seal.unlinking:2", true) }

// An errno at the first rename of a seal: the attempt is abandoned
// cleanly and the plaintext stays.
func TestXSealRenameEIO(t *testing.T) {
	defer failpoint.Reset()
	h := testkit.NewHome(t)
	vaulttest.New(t, h.Base, "root-acme")
	orig := writeRealSession(t, h)
	e := realEnv(t, h)
	failpoint.Set("fsx.rename=errno:EIO:1")
	rep, _ := Sweep(context.Background(), e, Options{})
	if rep.Count(OutSealed) != 0 {
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
