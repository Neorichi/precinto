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

	"filippo.io/age"
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

// A last_audit or recovery_verified_at later than now (forged, or written
// under a skewed clock) counts as zero: the next mark replaces it even
// though it is older.
func TestMarksReplaceAFutureValue(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	path := filepath.Join(fx.Store.VaultsDir, "root-acme", "vault.toml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	forged := strings.Replace(string(b), "last_audit = 0001-01-01T00:00:00Z", "last_audit = "+future, 1)
	forged = strings.Replace(forged, "recovery_verified_at = 0001-01-01T00:00:00Z", "recovery_verified_at = "+future, 1)
	if forged == string(b) || strings.Count(forged, future) != 2 {
		t.Fatalf("vault.toml layout changed:\n%s", b)
	}
	if err := os.WriteFile(path, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	if err := fx.Store.MarkAudited("root-acme", at); err != nil {
		t.Fatal(err)
	}
	if err := fx.Store.MarkRecoveryVerified(at); err != nil {
		t.Fatal(err)
	}
	v, err := fx.Store.Open("root-acme")
	if err != nil {
		t.Fatal(err)
	}
	if !v.Meta.LastAudit.Equal(at) || !v.Meta.RecoveryVerifiedAt.Equal(at) {
		t.Fatalf("last_audit %v, recovery_verified_at %v: the future values were kept (want %v)", v.Meta.LastAudit, v.Meta.RecoveryVerifiedAt, at)
	}
	if _, _, err := fx.Store.Recipients("root-acme"); err != nil {
		t.Fatalf("Recipients after the rewrite: %v", err)
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
	foreign, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	isBadSecret := func(err error) bool {
		return errors.Is(err, vault.ErrBadSecret) && !errors.Is(err, vault.ErrWrongIdentity) && !errors.Is(err, vault.ErrMACMismatch)
	}
	for name, c := range map[string]struct{ factor, secret string }{
		"wrong passphrase":            {"passphrase", "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ wrong"},
		"malformed recovery key":      {"recovery", "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ wrong"},
		"another valid recovery key":  {"recovery", foreign.String()},
		"the vault key, not recovery": {"recovery", fx.Identity.String()},
	} {
		if _, err := v.Unwrap(context.Background(), c.factor, uiWith(c.secret).AsUI()); !isBadSecret(err) {
			t.Errorf("%s: %v, want ErrBadSecret", name, err)
		}
	}
	if _, err := vault.ParseRecoveryKey(lb(t, "not a key")); !isBadSecret(err) {
		t.Errorf("ParseRecoveryKey of garbage = %v, want ErrBadSecret", err)
	}
	// Create confirms the install passphrase against the global vault: a
	// wrong one is a bad secret too, an empty answer a cancel.
	if _, err := fx.Store.Create(context.Background(), "root-beta", "", uiWith("not the passphrase of this install").AsUI()); !isBadSecret(err) {
		t.Errorf("Create with a wrong passphrase = %v, want ErrBadSecret", err)
	}
	if _, err := fx.Store.Create(context.Background(), "root-beta", "", uiWith("").AsUI()); !errors.Is(err, vault.ErrCancelled) {
		t.Errorf("Create with an empty passphrase = %v, want ErrCancelled", err)
	}
	if _, err := fx.Store.Open("root-beta"); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("a refused Create left a vault: %v", err)
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

// D80: a factor enrolled through a link (Homebrew's /opt/homebrew/bin) pins
// the binary it resolves to and records the link; after an upgrade moved
// the link to a new Cellar version and removed the old one, RepinPlugin
// resolves the link again and pins the new binary in every vault. A link
// swapped to a binary of another name is refused.
func TestRepinFollowsTheEnrolledLink(t *testing.T) {
	src := vault.InstallPluginForTest(t, "test")
	prefix := mustRealTemp(t)
	install := func(version, extra string) string {
		t.Helper()
		p := filepath.Join(prefix, "Cellar", "age-plugin-test", version, "bin", "age-plugin-test")
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, append(b, extra...), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := filepath.Join(prefix, "bin", "age-plugin-test")
	relink := func(to string) {
		t.Helper()
		_ = os.Remove(link)
		if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(to, link); err != nil {
			t.Fatal(err)
		}
	}
	v1 := install("1.0", "")
	relink(v1)
	s, g := initWith(t, testPluginSpec(t, link, "ok"), uiWith().AsUI())
	root, err := s.Create(context.Background(), "root-acme", "", uiWith(pass).AsUI())
	if err != nil {
		t.Fatal(err)
	}
	root.Destroy()
	f := g.Meta.Factors[0]
	if f.PluginPath != v1 || f.PluginLink != link {
		t.Fatalf("enrolled through the link: plugin_path %s, plugin_link %s; want %s and %s", f.PluginPath, f.PluginLink, v1, link)
	}

	// brew upgrade: a new version, the link moved, the old version gone.
	v2 := install("2.0", "\n# 2.0\n")
	relink(v2)
	if err := os.RemoveAll(filepath.Join(prefix, "Cellar", "age-plugin-test", "1.0")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Unwrap(context.Background(), "test", uiWith().AsUI()); err == nil {
		t.Fatal("unwrap ran a binary that is not the pinned one")
	}
	if got, err := vault.PluginTarget(f); err != nil || got != v2 {
		t.Fatalf("PluginTarget = %s %v, want %s", got, err, v2)
	}
	oldSHA, newSHA, err := s.RepinPlugin("test")
	if err != nil {
		t.Fatal(err)
	}
	if oldSHA != f.PluginSHA256 || newSHA == oldSHA || len(newSHA) != 64 {
		t.Fatalf("RepinPlugin = %s → %s (pinned %s)", oldSHA, newSHA, f.PluginSHA256)
	}
	for _, id := range []string{vault.GlobalID, "root-acme"} {
		v, err := s.Open(id)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range v.Meta.Factors {
			if x.Name == "test" && (x.PluginPath != v2 || x.PluginLink != link || x.PluginSHA256 != newSHA) {
				t.Errorf("%s: factor %+v, want %s pinned at %s through %s", id, x, newSHA, v2, link)
			}
		}
	}
	g2, _ := s.Open(vault.GlobalID)
	unwrapOK(t, g2, "test", uiWith().AsUI()).Destroy()

	// The link swapped to a binary named otherwise: refused, nothing pinned.
	other := filepath.Join(prefix, "evil", "age-plugin-other")
	if err := os.MkdirAll(filepath.Dir(other), 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(v2)
	if err := os.WriteFile(other, b, 0o755); err != nil {
		t.Fatal(err)
	}
	relink(other)
	if _, _, err := s.RepinPlugin("test"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("link to age-plugin-other: %v, want ErrUnsafe", err)
	}
	if v, _ := s.Open(vault.GlobalID); v.Meta.Factors[0].PluginPath != v2 {
		t.Errorf("a refused repin moved the pin to %s", v.Meta.Factors[0].PluginPath)
	}
}

// D80: a repin that fails in one vault (here root-acme's directory is not
// writable) re-pins the others and reports that vault; a later repin then
// brings it to the same binary, although the vaults pin different binaries
// in between (the enrolled path is the same).
func TestRepinCompletesAfterAPartialFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into read-only directories")
	}
	src := vault.InstallPluginForTest(t, "test")
	prefix := mustRealTemp(t)
	install := func(version, extra string) string {
		t.Helper()
		p := filepath.Join(prefix, "Cellar", "age-plugin-test", version, "bin", "age-plugin-test")
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, append(b, extra...), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := filepath.Join(prefix, "bin", "age-plugin-test")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	v1 := install("1.0", "")
	if err := os.Symlink(v1, link); err != nil {
		t.Fatal(err)
	}
	s, _ := initWith(t, testPluginSpec(t, link, "ok"), uiWith().AsUI())
	root, err := s.Create(context.Background(), "root-acme", "", uiWith(pass).AsUI())
	if err != nil {
		t.Fatal(err)
	}
	root.Destroy()
	v2 := install("2.0", "\n# 2.0\n")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(v2, link); err != nil {
		t.Fatal(err)
	}
	pinnedAt := func(id string) string {
		t.Helper()
		v, err := s.Open(id)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range v.Meta.Factors {
			if f.Name == "test" {
				return f.PluginPath
			}
		}
		t.Fatalf("%s has no factor test", id)
		return ""
	}
	dir := filepath.Join(s.VaultsDir, "root-acme")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, _, err := s.RepinPlugin("test"); err == nil || !strings.Contains(err.Error(), "root-acme") {
		t.Fatalf("repin with root-acme unwritable = %v, want its failure reported", err)
	}
	if g, r := pinnedAt(vault.GlobalID), pinnedAt("root-acme"); g != v2 || r != v1 {
		t.Fatalf("after the failed repin: global pins %s, root-acme %s; want %s and %s", g, r, v2, v1)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RepinPlugin("test"); err != nil {
		t.Fatalf("repin after the failure: %v", err)
	}
	if g, r := pinnedAt(vault.GlobalID), pinnedAt("root-acme"); g != v2 || r != v2 {
		t.Fatalf("after the second repin: global pins %s, root-acme %s; want %s in both", g, r, v2)
	}
}

// D96 (SEC-F3): an enrolled link or a resolved binary whose path holds C0,
// C1, DEL or Unicode format characters is refused: repin shows these paths
// to the human who decides the pin.
func TestPluginTargetRefusesControlCharacters(t *testing.T) {
	for _, bad := range []string{"\x1b[2K", "a\rb", "a\nb", "a\u202eb", "a\u200bb", "a\x7fb", "a\u0085b"} {
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(base, bad, "bin")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(dir, "age-plugin-test")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "age-plugin-test")
		if err := os.Symlink(bin, link); err != nil {
			t.Fatal(err)
		}
		f := vault.Factor{Name: "test", Kind: vault.FactorPlugin, PluginLink: link, PluginPath: filepath.Join(base, "old", "age-plugin-test")}
		if _, err := vault.PluginTarget(f); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("%q: PluginTarget = %v, want ErrUnsafe", bad, err)
		}
		f.PluginLink = filepath.Join(dir, "age-plugin-test")
		if _, err := vault.PluginTarget(f); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("%q in the enrolled path: PluginTarget = %v, want ErrUnsafe", bad, err)
		}
	}
}
