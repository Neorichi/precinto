package vault_test

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

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/vault"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

func TestMarkAudited(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	if err := fx.Store.MarkAudited("root-acme", at); err != nil {
		t.Fatal(err)
	}
	v, err := fx.Store.Open("root-acme")
	if err != nil || !v.Meta.LastAudit.Equal(at) {
		t.Fatalf("last_audit %v %v, want %v", v.Meta.LastAudit, err, at)
	}
	// Never backwards.
	if err := fx.Store.MarkAudited("root-acme", at.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if v, _ := fx.Store.Open("root-acme"); !v.Meta.LastAudit.Equal(at) {
		t.Fatalf("last_audit moved backwards to %v", v.Meta.LastAudit)
	}
	// Never past now.
	if err := fx.Store.MarkAudited("root-acme", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("a future last_audit was accepted")
	}
	if err := fx.Store.MarkAudited("no-such-vault", at); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("unknown vault: %v", err)
	}
	// The rewrite stays outside the recipients MAC: the vault still verifies.
	v, _ = fx.Store.Open("root-acme")
	id := vaulttest.LockedBuffer(t, fx.Identity.String())
	if err := fx.Store.Verify(v, id); err != nil {
		t.Fatalf("Verify after MarkAudited: %v", err)
	}
	if _, _, err := fx.Store.Recipients("root-acme"); err != nil {
		t.Fatalf("Recipients after MarkAudited: %v", err)
	}
}

// Concurrent rewrites of vault.toml never lose each other's fields.
func TestMarkAuditedConcurrentWithFactorAdd(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := fx.Store.MarkAudited("root-acme", base.Add(time.Duration(i)*time.Second)); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		v, err := fx.Store.Open("root-acme")
		if err != nil {
			errs <- err
			return
		}
		err = fx.Keyring.WithIdentityBuffer("root-acme", func(id *memguard.LockedBuffer) error {
			return v.AddFactor(context.Background(), id, vault.FactorSpec{Kind: vault.FactorPassphrase, Name: "second", Passphrase: lb(t, pass), ScryptLogN: 10}, nil)
		})
		if err != nil {
			errs <- err
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	v, err := fx.Store.Open("root-acme")
	if err != nil {
		t.Fatal(err)
	}
	if want := base.Add(19 * time.Second); !v.Meta.LastAudit.Equal(want) {
		t.Errorf("last_audit %v, want the newest %v", v.Meta.LastAudit, want)
	}
	found := false
	for _, f := range v.Meta.Factors {
		found = found || f.Name == "second"
	}
	if !found {
		t.Error("the factor added concurrently was lost")
	}
}

func TestMarkRecoveryVerified(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	at := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	if err := fx.Store.MarkRecoveryVerified(at); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{vault.GlobalID, "root-acme"} {
		v, err := fx.Store.Open(id)
		if err != nil || !v.Meta.RecoveryVerifiedAt.Equal(at) {
			t.Errorf("%s: recovery_verified_at %v %v", id, v.Meta.RecoveryVerifiedAt, err)
		}
	}
	if err := fx.Store.MarkRecoveryVerified(time.Now().Add(time.Hour)); err == nil {
		t.Error("a future recovery_verified_at was accepted")
	}
	if err := fx.Store.MarkRecoveryVerified(at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if v, _ := fx.Store.Open("root-acme"); !v.Meta.RecoveryVerifiedAt.Equal(at) {
		t.Errorf("recovery_verified_at moved backwards to %v", v.Meta.RecoveryVerifiedAt)
	}
}

// A wrong passphrase or recovery key is ErrBadSecret, never a tamper error.
func TestBadSecret(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	v, err := fx.Store.Open("root-acme")
	if err != nil {
		t.Fatal(err)
	}
	for name, factor := range map[string]string{"passphrase": "passphrase", "recovery": "recovery"} {
		_, err := v.Unwrap(context.Background(), factor, uiWith("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ wrong").AsUI())
		if !errors.Is(err, vault.ErrBadSecret) || errors.Is(err, vault.ErrWrongIdentity) || errors.Is(err, vault.ErrMACMismatch) {
			t.Errorf("%s: wrong secret = %v, want ErrBadSecret", name, err)
		}
	}
}

func TestWithIdentityBuffer(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	var kept *memguard.LockedBuffer
	var recipient string
	err := fx.Keyring.WithIdentityBuffer("root-acme", func(id *memguard.LockedBuffer) error {
		kept = id
		if !bytes.HasPrefix(id.Bytes(), []byte("AGE-SECRET-KEY-1")) {
			return errors.New("not an identity")
		}
		recipient = fx.Identity.Recipient().String()
		return nil
	})
	if err != nil || recipient == "" {
		t.Fatalf("WithIdentityBuffer: %v", err)
	}
	if kept.IsAlive() {
		t.Fatal("the identity buffer outlived fn")
	}
	sentinel := errors.New("fn failed")
	if err := fx.Keyring.WithIdentityBuffer("root-acme", func(*memguard.LockedBuffer) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("fn error = %v", err)
	}
	fx.Keyring.Drop("root-acme")
	called := false
	if err := fx.Keyring.WithIdentityBuffer("root-acme", func(*memguard.LockedBuffer) error { called = true; return nil }); !errors.Is(err, vault.ErrLocked) || called {
		t.Fatalf("locked vault: %v (fn called %v)", err, called)
	}
}

func TestPluginPresencePolicyContract(t *testing.T) {
	path := vault.InstallPluginForTest(t, "test")
	for name, c := range map[string]struct {
		mut func(*vault.FactorSpec)
		ok  bool
	}{
		"policy":          {func(s *vault.FactorSpec) {}, true},
		"no policy":       {func(s *vault.FactorSpec) { s.PresencePolicy = "" }, false},
		"acknowledged":    {func(s *vault.FactorSpec) { s.PresencePolicy, s.NoPresenceAck = "", true }, true},
		"unknown policy":  {func(s *vault.FactorSpec) { s.PresencePolicy = "bogus" }, false},
		"se access field": {func(s *vault.FactorSpec) { s.PresencePolicy, s.SEAccessControl = "", "touch-always" }, false},
	} {
		s, _ := newStore(t)
		spec := testPluginSpec(t, path, "ok")
		c.mut(&spec)
		rec, err := s.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{spec}})
		if (err == nil) != c.ok {
			t.Errorf("%s: Init = %v, want ok=%v", name, err, c.ok)
			continue
		}
		if err != nil {
			continue
		}
		rec.Destroy()
		g, _ := s.Open(vault.GlobalID)
		if got := g.Meta.Factors[0].PresencePolicy; name == "policy" && got != "touch-always" {
			t.Errorf("%s: recorded %q", name, got)
		}
	}
	// The se factor keeps SEAccessControl and refuses a plugin policy.
	s, _ := newStore(t)
	se := seSpec(t, vault.InstallPluginForTest(t, "se"), "ok")
	se.PresencePolicy = "touch-always"
	if _, err := s.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{se}}); err == nil {
		t.Error("se factor with a plugin presence policy accepted")
	}
}

func TestRepinPlugin(t *testing.T) {
	path := vault.InstallPluginForTest(t, "test")
	s, g := initWith(t, testPluginSpec(t, path, "ok"), uiWith().AsUI())
	root, err := s.Create(context.Background(), "root-acme", "", uiWith(pass).AsUI())
	if err != nil {
		t.Fatal(err)
	}
	root.Destroy()
	oldPin := g.Meta.Factors[0].PluginSHA256
	// The binary changes (an upgrade): unwrap refuses until re-pinned.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("\n# upgraded\n")
	f.Close()
	if _, err := g.Unwrap(context.Background(), "test", uiWith().AsUI()); !errors.Is(err, vault.ErrPluginPin) {
		t.Fatalf("unwrap with a changed binary = %v, want ErrPluginPin", err)
	}
	oldSHA, newSHA, err := s.RepinPlugin("test")
	if err != nil {
		t.Fatal(err)
	}
	if oldSHA != oldPin || newSHA == oldSHA || len(newSHA) != 64 {
		t.Fatalf("RepinPlugin = %s → %s (pinned %s)", oldSHA, newSHA, oldPin)
	}
	for _, id := range []string{vault.GlobalID, "root-acme"} {
		v, err := s.Open(id)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range v.Meta.Factors {
			if f.Name == "test" && f.PluginSHA256 != newSHA {
				t.Errorf("%s: pin %s, want %s", id, f.PluginSHA256, newSHA)
			}
		}
	}
	g2, _ := s.Open(vault.GlobalID)
	unwrapOK(t, g2, "test", uiWith().AsUI())
	if _, _, err := s.RepinPlugin("no-such-factor"); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("unknown factor: %v", err)
	}
	if _, _, err := s.RepinPlugin("passphrase"); err == nil {
		t.Error("re-pinned a passphrase factor")
	}
	// A group-writable binary is refused, and so is a symlink.
	if err := os.Chmod(path, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RepinPlugin("test"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("group-writable binary: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	moved := path + ".real"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RepinPlugin("test"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("symlinked binary: %v", err)
	}
}

// The embedded Diceware list: 7776 distinct lowercase words of 3–9
// letters (OD-01 keeps it swappable).
func TestWordlistShape(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("wordlist.txt"))
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(string(data))
	if len(words) != 7776 {
		t.Fatalf("%d words, want 7776", len(words))
	}
	seen := map[string]bool{}
	for _, w := range words {
		if seen[w] {
			t.Fatalf("duplicate word %q", w)
		}
		seen[w] = true
		if len(w) < 3 || len(w) > 9 {
			t.Fatalf("word %q outside 3–9 letters", w)
		}
		for _, c := range w {
			if c < 'a' || c > 'z' {
				t.Fatalf("word %q is not lowercase ASCII letters", w)
			}
		}
	}
}
