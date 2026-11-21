//go:build crossgroup

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/precinto/precinto/internal/agent/agenttest"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

// sec26Pass is the passphrase of the SEC-26 vaults (scrypt logN 10: test
// binaries only, SPEC §4.3).
const sec26Pass = "sec26 test passphrase, long enough"

// sec26Home is one SEC-26 install: a testkit home whose vaults (global and
// root-acme, passphrase factor) were made with a known passphrase, one
// capsule of root-acme logged before last_audit (so the genuineness check
// of D53 has something to open), and the in-process daemon.
type sec26Home struct {
	h        *testkit.Home
	store    *vault.Store
	recovery *age.X25519Identity
	fixture  *vaulttest.Fixture // for TamperRecipient (it uses the store only)
	agent    *agenttest.Agent
}

func newSEC26Home(t *testing.T) *sec26Home {
	t.Helper()
	h := testkit.NewHome(t)
	store, recovery := sec26Store(t, h.Layout.Base, h.Root)
	s := &sec26Home{h: h, store: store, recovery: recovery, fixture: &vaulttest.Fixture{Store: store, RootID: "root-acme"}}
	_, fpr, err := store.Recipients("root-acme")
	if err != nil {
		t.Fatal(err)
	}
	m, err := store.Open("root-acme")
	if err != nil {
		t.Fatal(err)
	}
	// A capsule sealed to the folder's real recipients an hour ago, then
	// audited (last_audit after it).
	now := time.Now()
	logCapsule(t, h.Layout, "claude-code/"+strings.Repeat("a", 32)+"/g000001.pcap", []string{m.Meta.Recipient, m.Meta.RecoveryRecipient}, fpr, now.Add(-time.Hour))
	if err := store.MarkAudited("root-acme", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	s.agent = agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	return s
}

// sec26Store creates the vaults of an install under base the way init and
// protect do, with sec26Pass.
func sec26Store(t *testing.T, base, rootPath string) (*vault.Store, *age.X25519Identity) {
	t.Helper()
	ctx := context.Background()
	store := vault.OpenStore(filepath.Join(base, "vaults"), filepath.Join(base, "state", "verified"), filepath.Join(base, "factors"))
	u := &vaulttest.UI{Secrets: []string{sec26Pass, sec26Pass, sec26Pass}, Interactive: true}
	rec, err := store.Init(ctx, vault.InitOptions{
		Factors: []vault.FactorSpec{{Kind: vault.FactorPassphrase, Passphrase: vaulttest.LockedBuffer(t, sec26Pass), ScryptLogN: 10}},
		UI:      u.AsUI(),
		Now:     time.Now,
	})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	recovery, err := age.ParseX25519Identity(rec.String())
	rec.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Create(ctx, "root-acme", rootPath, u.AsUI())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id.Destroy()
	return store, recovery
}

// logCapsule writes an age file encrypted to recipients at rel below the
// capsule store and logs it (capslog), sealed at at.
func logCapsule(t *testing.T, l paths.Layout, rel string, recipients []string, fpr string, at time.Time) {
	t.Helper()
	var rs []age.Recipient
	for _, r := range recipients {
		p, err := age.ParseX25519Recipient(r)
		if err != nil {
			t.Fatal(err)
		}
		rs = append(rs, p)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rs...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "synthetic capsule body"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	ct := buf.Bytes()
	hdr, err := age.ExtractHeader(bytes.NewReader(ct))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(l.CapsulesDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, ct, 0o600); err != nil {
		t.Fatal(err)
	}
	sum, hsum := sha256.Sum256(ct), sha256.Sum256(hdr)
	parts := strings.Split(rel, "/")
	if err := capslog.Open(l.CapsuleLog).Append(capslog.Entry{
		V: capslog.Version, Path: rel, SHA256: hex.EncodeToString(sum[:]), HeaderSHA256: hex.EncodeToString(hsum[:]),
		Size: int64(len(ct)), Kind: "claude-session", Harness: parts[0], Unit: parts[1], VaultID: "root-acme",
		RootIDs: []string{"root-acme"}, Gen: 1, SealedAt: at.UTC(), RecipientsFpr: fpr, Files: 1, Bytes: 22,
	}); err != nil {
		t.Fatal(err)
	}
}

// repairApp is the real CLI wiring over the in-process daemon for a human
// on a terminal: the agent-context probe says "human" (the go test process
// itself runs inside an agent session without a terminal; detection has
// its own tests, the refusals below use the real one).
func (s *sec26Home) repairApp(t *testing.T) (*app, *env) {
	t.Helper()
	a, e := realApp(t, s.h)
	a.sys.agentContext = func(paths.Env, platform.ProcTable) (bool, string) { return false, "" }
	return a, e
}

// SEC-26 (D53): vault repair after a real recipient swap, with a factor and
// with --recovery; refused without a terminal and with CLAUDECODE=1;
// C14.notgenuine when the identity files were replaced as well (nothing
// changed); vault.ErrNeedRecovery when the recovery recipient changed and
// --recovery is missing. Every step goes through the CLI's real wiring and
// the real daemon (agenttest).
func TestCrossgroupSEC26VaultRepair(t *testing.T) {
	t.Run("factor", func(t *testing.T) {
		s := newSEC26Home(t)
		s.fixture.TamperRecipient(t, "root-acme", false)
		if _, _, err := s.store.Recipients("root-acme"); !errors.Is(err, vault.ErrRecipientsChanged) {
			t.Fatalf("after the swap: %v, want the tripwire", err)
		}
		// A capsule sealed to the foreign recipients after last_audit is
		// listed as exposed.
		foreign, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		exposed := "claude-code/" + strings.Repeat("b", 32) + "/g000001.pcap"
		logCapsule(t, s.h.Layout, exposed, []string{foreign.Recipient().String()}, strings.Repeat("f", 64), time.Now())

		a, e := s.repairApp(t)
		// The passphrase answers the daemon's unwrap; "repair" is the typed
		// confirmation (C14.confirm); a daemon still asking its own confirm
		// in the dry run gets yes.
		e.tty.secrets = []string{sec26Pass, sec26Pass}
		e.tty.confirms = []bool{true}
		e.tty.lines = []string{wordRepair}
		if code := a.run([]string{"vault", "repair", "--root", s.h.Root}); code != exitOK {
			t.Fatalf("repair: exit %d (%s)", code, e.stderr())
		}
		// C14.repaired, and the capsule sealed to the foreign recipients is
		// listed as exposed (in the dry run's diff or with the result).
		repaired := strings.SplitN(ui.Format(ui.MsgVaultRepaired, ui.Vars{Folder: "~/work/acme"}), "0 capsule(s)", 2)[0]
		if !strings.Contains(e.stderr(), repaired) || !strings.Contains(e.stderr(), "exposed: "+exposed) {
			t.Fatalf("repair output %q", e.stderr())
		}
		if strings.Contains(e.stderr(), strings.Repeat("a", 32)) {
			t.Fatalf("the genuine capsule was listed as exposed: %q", e.stderr())
		}
		if n := strings.Count(e.tty.allPrompts(), "passphrase"); n < 1 || n > 2 {
			t.Fatalf("%d passphrase prompts", n)
		}
		// Sealing resumes: the recipients match their verified copy again.
		if _, _, err := s.store.Recipients("root-acme"); err != nil {
			t.Fatalf("after repair: %v", err)
		}
	})

	t.Run("recovery", func(t *testing.T) {
		s := newSEC26Home(t)
		s.fixture.TamperRecipient(t, "root-acme", true)
		// Without --recovery the recovery recipient cannot be trusted
		// (vault.ErrNeedRecovery): exit 3, and the command to run.
		a, e := s.repairApp(t)
		e.tty.secrets = []string{sec26Pass, sec26Pass}
		e.tty.confirms = []bool{true}
		e.tty.lines = []string{wordRepair}
		if code := a.run([]string{"vault", "repair", "--root", s.h.Root}); code != exitLocked || !strings.Contains(e.stderr(), "--recovery") {
			t.Fatalf("repair without --recovery: exit %d (%s)", code, e.stderr())
		}
		if _, _, err := s.store.Recipients("root-acme"); !errors.Is(err, vault.ErrRecipientsChanged) {
			t.Fatalf("a refused repair changed the vault: %v", err)
		}
		// With --recovery: the key is typed once at the CLI.
		a, e = s.repairApp(t)
		e.tty.secrets = []string{s.recovery.String()}
		e.tty.confirms = []bool{true}
		e.tty.lines = []string{wordRepair}
		if code := a.run([]string{"vault", "repair", "--root", s.h.Root, "--recovery"}); code != exitOK {
			t.Fatalf("repair --recovery: exit %d (%s)", code, e.stderr())
		}
		if _, _, err := s.store.Recipients("root-acme"); err != nil {
			t.Fatalf("after repair --recovery: %v", err)
		}
		m, err := s.store.Open("root-acme")
		if err != nil || m.Meta.RecoveryRecipient != s.recovery.Recipient().String() {
			t.Fatalf("recovery recipient %v %v", m, err)
		}
	})

	t.Run("not genuine", func(t *testing.T) {
		s := newSEC26Home(t)
		s.fixture.TamperRecipient(t, "root-acme", false)
		// The identity file replaced as well, by one the same passphrase
		// opens (another install's): the unwrap succeeds with a key that
		// does not open the folder's older capsule.
		other, _ := sec26Store(t, t.TempDir(), s.h.Root)
		swap, err := os.ReadFile(filepath.Join(other.VaultsDir, "root-acme", "identity.passphrase.age"))
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(s.store.VaultsDir, "root-acme")
		if err := os.WriteFile(filepath.Join(dir, "identity.passphrase.age"), swap, 0o600); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(filepath.Join(dir, "vault.toml"))
		if err != nil {
			t.Fatal(err)
		}
		a, e := s.repairApp(t)
		e.tty.secrets = []string{sec26Pass, sec26Pass}
		e.tty.confirms = []bool{true}
		e.tty.lines = []string{wordRepair}
		if code := a.run([]string{"vault", "repair", "--root", s.h.Root}); code != exitVerify {
			t.Fatalf("not genuine: exit %d (%s)", code, e.stderr())
		}
		// C14.notgenuine (the daemon names the folder as it knows it).
		notGenuine := ui.Format(ui.MsgVaultNotGenuine, ui.Vars{Folder: "F"})
		notGenuine = notGenuine[strings.Index(notGenuine, "F")+1 : strings.Index(notGenuine, "Use your")]
		if !strings.Contains(e.stderr(), notGenuine) {
			t.Fatalf("stderr %q, want C14.notgenuine", e.stderr())
		}
		if after, _ := os.ReadFile(filepath.Join(dir, "vault.toml")); !bytes.Equal(after, before) {
			t.Fatal("vault.toml changed although the key was not genuine")
		}
	})

	t.Run("refusals", func(t *testing.T) {
		s := newSEC26Home(t)
		s.fixture.TamperRecipient(t, "root-acme", false)
		// No terminal: refused (exit 3) before the daemon is asked.
		a, e := s.repairApp(t)
		a.sys.openTTY = func() (terminal, error) { return nil, errors.New("no controlling terminal") }
		if code := a.run([]string{"vault", "repair", "--root", s.h.Root}); code != exitLocked {
			t.Fatalf("no terminal: exit %d (%s)", code, e.stderr())
		}
		// CLAUDECODE=1, through the real agent-context detection.
		marked := *s.h
		marked.Env = s.h.Env.With("CLAUDECODE", "1")
		a, e = realApp(t, &marked)
		if code := a.run([]string{"vault", "repair", "--root", s.h.Root}); code != exitLocked ||
			!strings.Contains(e.stderr(), "from inside an AI agent session") {
			t.Fatalf("CLAUDECODE=1: exit %d (%s)", code, e.stderr())
		}
		if len(e.tty.prompts) != 0 {
			t.Fatalf("an agent was prompted: %q", e.tty.prompts)
		}
		if _, _, err := s.store.Recipients("root-acme"); !errors.Is(err, vault.ErrRecipientsChanged) {
			t.Fatalf("a refused repair changed the vault: %v", err)
		}
	})
}
