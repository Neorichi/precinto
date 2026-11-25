package vault_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/vault"
	"github.com/Neorichi/precinto/internal/vault/vaulttest"
)

// The fake plugins (testdata/fakeplugin) stand in for age-plugin-se and a
// hardware-token plugin: the real ones are never run by these tests.

func testPluginSpec(t *testing.T, path, mode string) vault.FactorSpec {
	t.Helper()
	return vault.FactorSpec{
		Kind: vault.FactorPlugin, Recipient: vault.KeygenForTest(t, path),
		IdentityStub: plugin.EncodeIdentity("test", []byte(mode)), PluginPath: path, PresencePolicy: "touch-always",
	}
}

func seSpec(t *testing.T, path, mode string) vault.FactorSpec {
	t.Helper()
	return vault.FactorSpec{Kind: vault.FactorSE, Recipient: vault.KeygenForTest(t, path), IdentityStub: plugin.EncodeIdentity("se", []byte(mode)), PluginPath: path}
}

// initWith initializes a store with the given factor plus a passphrase.
func initWith(t *testing.T, spec vault.FactorSpec, ui vault.UI) (*vault.Store, *vault.Vault) {
	t.Helper()
	s, _ := newStore(t)
	rec, err := s.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{spec, passSpec(t)}, UI: ui, Now: func() time.Time { return epoch }})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	rec.Destroy()
	g, err := s.Open(vault.GlobalID)
	if err != nil {
		t.Fatal(err)
	}
	return s, g
}

func unwrapOK(t *testing.T, v *vault.Vault, factor string, ui vault.UI) *memguard.LockedBuffer {
	t.Helper()
	id, err := v.Unwrap(context.Background(), factor, ui)
	if err != nil {
		t.Fatalf("Unwrap(%s): %v", factor, err)
	}
	t.Cleanup(id.Destroy)
	if r, _ := age.ParseX25519Identity(id.String()); r == nil || r.Recipient().String() != v.Meta.Recipient {
		t.Fatal("unwrapped identity does not match the vault")
	}
	return id
}

func TestX25519TestPlugin(t *testing.T) {
	path := vault.InstallPluginForTest(t, "test")
	s, g := initWith(t, testPluginSpec(t, path, "ok"), uiWith().AsUI())
	f := g.Meta.Factors[0]
	if f.Name != "test" || f.Kind != vault.FactorPlugin || f.PluginPath != path || len(f.PluginSHA256) != 64 || f.PresencePolicy != "touch-always" || f.GUI {
		t.Fatalf("factor %+v", f)
	}
	unwrapOK(t, g, "test", uiWith().AsUI())
	// Create wraps the new root vault through the plugin too.
	root, err := s.Create(context.Background(), "root-acme", "", uiWith(pass).AsUI())
	if err != nil {
		t.Fatal(err)
	}
	root.Destroy()
	v, _ := s.Open("root-acme")
	unwrapOK(t, v, "test", uiWith().AsUI())
}

func TestPluginUIRelay(t *testing.T) {
	path := vault.InstallPluginForTest(t, "test")
	_, g := initWith(t, testPluginSpec(t, path, "ok"), uiWith().AsUI())
	identity := unwrapOK(t, g, "test", uiWith().AsUI())
	add := func(name, mode string) {
		t.Helper()
		spec := testPluginSpec(t, path, mode)
		spec.Name = name
		if err := g.AddFactor(context.Background(), identity, spec, uiWith().AsUI()); err != nil {
			t.Fatalf("AddFactor(%s): %v", name, err)
		}
	}
	for _, m := range []string{"msg", "pin", "confirm", "error", "envcheck", "hang"} {
		add("test-"+m, m)
	}

	ui := uiWith()
	unwrapOK(t, g, "test-msg", ui.AsUI())
	if len(ui.Displayed) != 1 || ui.Displayed[0] != "touch the fake key" {
		t.Errorf("displayed %q", ui.Displayed)
	}
	unwrapOK(t, g, "test-pin", uiWith("123456").AsUI())
	if _, err := g.Unwrap(context.Background(), "test-pin", uiWith("000000").AsUI()); err == nil {
		t.Error("wrong PIN accepted")
	}
	if _, err := g.Unwrap(context.Background(), "test-pin", uiWith().AsUI()); !errors.Is(err, vault.ErrCancelled) {
		t.Errorf("cancelled PIN = %v", err)
	}
	if _, err := g.Unwrap(context.Background(), "test-pin", (&vaulttest.UI{GUIOK: true}).AsUI()); !errors.Is(err, vault.ErrNoUI) {
		t.Errorf("PIN without a prompt = %v", err)
	}
	unwrapOK(t, g, "test-confirm", (&vaulttest.UI{Interactive: true, Confirms: []bool{true}}).AsUI())
	if _, err := g.Unwrap(context.Background(), "test-confirm", (&vaulttest.UI{Interactive: true, Confirms: []bool{false}}).AsUI()); err == nil {
		t.Error("declined confirmation accepted")
	}
	if _, err := g.Unwrap(context.Background(), "test-error", uiWith().AsUI()); err == nil || !strings.Contains(err.Error(), "fake plugin failure") {
		t.Errorf("plugin error = %v", err)
	}
	// S2: the plugin runs with an environment of exactly PATH=<its dir>.
	unwrapOK(t, g, "test-envcheck", uiWith().AsUI())
	// A plugin that never answers is stopped by the context.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := g.Unwrap(ctx, "test-hang", uiWith().AsUI()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("hanging plugin = %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("cancellation took %v", d)
	}
}

func TestPluginPresencePolicy(t *testing.T) {
	path := vault.InstallPluginForTest(t, "test")
	s, _ := newStore(t)
	spec := testPluginSpec(t, path, "ok")
	spec.PresencePolicy = ""
	if _, err := s.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{spec}}); err == nil {
		t.Fatal("plugin factor without a known presence policy accepted (S10)")
	}
	spec.NoPresenceAck = true
	rec, err := s.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{spec}})
	if err != nil {
		t.Fatal(err)
	}
	rec.Destroy()
	g, _ := s.Open(vault.GlobalID)
	if p := g.Meta.Factors[0].PresencePolicy; p == "" || p == "touch-always" {
		t.Errorf("acknowledged policy recorded as %q", p)
	}
	// A plain X25519 recipient is never a factor (S10).
	x, _ := age.GenerateX25519Identity()
	bad := testPluginSpec(t, path, "ok")
	bad.Recipient = x.Recipient().String()
	s2, _ := newStore(t)
	if _, err := s2.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{bad}}); err == nil {
		t.Fatal("X25519 recipient accepted as a plugin factor")
	}
	// The plugin path must name age-plugin-<name>.
	bad = testPluginSpec(t, path, "ok")
	other := filepath.Join(filepath.Dir(path), "age-plugin-other")
	if err := os.Link(path, other); err != nil {
		t.Fatal(err)
	}
	bad.PluginPath = other
	if _, err := s2.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{bad}}); err == nil {
		t.Fatal("plugin path of another plugin accepted")
	}
}

func TestSecureEnclaveFactor(t *testing.T) {
	path := vault.InstallPluginForTest(t, "se")
	spec := seSpec(t, path, "ok")
	if !strings.HasPrefix(spec.Recipient, "age1tag1") {
		t.Fatalf("fake keygen recipient %q", spec.Recipient)
	}
	s, g := initWith(t, spec, uiWith().AsUI())
	f := g.Meta.Factors[0]
	if f.Name != "se" || f.Kind != vault.FactorSE || f.PresencePolicy != "any-biometry-or-passcode" || !f.GUI || f.PluginPath != path {
		t.Fatalf("se factor %+v", f)
	}
	// Wrapped natively to the tag recipient: no plugin needed to seal.
	ct, _ := os.ReadFile(filepath.Join(g.Dir, "identity.se.age"))
	if !bytes.Contains(ct, []byte("-> p256tag ")) {
		t.Fatal("identity.se.age is not wrapped to the P-256 tag recipient")
	}
	stub, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(g.Dir)), "factors", "se.identity"))
	if err != nil || strings.TrimSpace(string(stub)) != spec.IdentityStub {
		t.Fatalf("factors/se.identity: %v", err)
	}
	// Without a terminal, "" picks the Secure Enclave (D27).
	unwrapOK(t, g, "", (&vaulttest.UI{GUIOK: true}).AsUI())
	if got := g.UsableFactors(false, true); len(got) != 1 || got[0].Kind != vault.FactorSE {
		t.Fatalf("UsableFactors(gui) = %+v", got)
	}
	if _, err := g.Unwrap(context.Background(), "se", uiWith().AsUI()); !errors.Is(err, vault.ErrNoUI) {
		t.Fatalf("se without a GUI = %v", err)
	}
	root, err := s.Create(context.Background(), "root-acme", "", uiWith(pass).AsUI())
	if err != nil {
		t.Fatal(err)
	}
	root.Destroy()
	v, _ := s.Open("root-acme")
	unwrapOK(t, v, "se", (&vaulttest.UI{GUIOK: true}).AsUI())

	for _, ac := range []string{"none", "any-biometry", "current-biometry", "bogus"} {
		s2, _ := newStore(t)
		bad := seSpec(t, path, "ok")
		bad.SEAccessControl = ac
		if _, err := s2.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{bad}}); err == nil {
			t.Errorf("access control %q accepted", ac)
		}
	}
	s3, _ := newStore(t)
	wrongStub := seSpec(t, path, "ok")
	wrongStub.IdentityStub = plugin.EncodeIdentity("yubikey", []byte("x"))
	if _, err := s3.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{wrongStub}}); err == nil {
		t.Error("se factor with a non-se stub accepted")
	}
}

// TestPluginPinMismatch: every plugin-backed factor, se included, refuses
// a binary whose hash no longer matches its pin, or that became a symlink.
func TestPluginPinMismatch(t *testing.T) {
	for _, kind := range []string{"se", "test"} {
		t.Run(kind, func(t *testing.T) {
			path := vault.InstallPluginForTest(t, kind)
			spec := seSpec(t, path, "ok")
			ui := (&vaulttest.UI{Interactive: true, GUIOK: true}).AsUI()
			if kind == "test" {
				spec = testPluginSpec(t, path, "ok")
			}
			_, g := initWith(t, spec, ui)
			unwrapOK(t, g, kind, ui)
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			f.Write([]byte{0})
			f.Close()
			if _, err := g.Unwrap(context.Background(), kind, ui); !errors.Is(err, vault.ErrPluginPin) {
				t.Fatalf("modified binary = %v", err)
			}
			// A symlink to a genuine copy is refused as well.
			genuine := vault.InstallPluginForTest(t, kind)
			os.Remove(path)
			if err := os.Symlink(genuine, path); err != nil {
				t.Fatal(err)
			}
			if _, err := g.Unwrap(context.Background(), kind, ui); !errors.Is(err, vault.ErrPluginPin) {
				t.Fatalf("symlinked binary = %v", err)
			}
			os.Remove(path)
			if _, err := g.Unwrap(context.Background(), kind, ui); !errors.Is(err, vault.ErrPluginPin) {
				t.Fatalf("missing binary = %v", err)
			}
		})
	}
}

// TestPluginPATHHijack is the vault part of SEC-12: a fake age-plugin-se
// first on the process PATH is never run; only the pinned binary is.
func TestPluginPATHHijack(t *testing.T) {
	path := vault.InstallPluginForTest(t, "se")
	_, g := initWith(t, seSpec(t, path, "ok"), uiWith().AsUI())
	evil := vault.InstallPluginForTest(t, "se")
	evilDir := filepath.Dir(evil)
	if err := os.WriteFile(filepath.Join(evilDir, "EVIL"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", evilDir+string(os.PathListSeparator)+filepath.Dir(path))
	unwrapOK(t, g, "se", (&vaulttest.UI{GUIOK: true}).AsUI())
	if _, err := os.Lstat(filepath.Join(evilDir, "RAN")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the plugin found on PATH ran")
	}
}

// TestRealPluginClientInterop drives the real filippo.io/age/plugin client
// against the fake plugin, both ways: files wrapped by vault's pinned
// client open with the stock client, and files wrapped by the stock client
// open through vault (the protocol implementations agree).
func TestRealPluginClientInterop(t *testing.T) {
	path := vault.InstallPluginForTest(t, "test")
	spec := testPluginSpec(t, path, "ok")
	_, g := initWith(t, spec, uiWith().AsUI())
	identity := unwrapOK(t, g, "test", uiWith().AsUI())
	t.Setenv("PATH", filepath.Dir(path)) // the stock client resolves plugins through PATH

	stockUI := &plugin.ClientUI{
		DisplayMessage: func(string, string) error { return nil },
		RequestValue:   func(string, string, bool) (string, error) { return "", errors.New("no") },
		Confirm:        func(string, string, string, string) (bool, error) { return false, errors.New("no") },
	}
	sid, err := plugin.NewIdentity(spec.IdentityStub, stockUI)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := os.ReadFile(filepath.Join(g.Dir, "identity.test.age"))
	r, err := age.Decrypt(bytes.NewReader(ct), sid)
	if err != nil {
		t.Fatalf("stock client on a vault-wrapped file: %v", err)
	}
	plain, _ := io.ReadAll(r)
	if strings.TrimSpace(string(plain)) != identity.String() {
		t.Fatal("stock client read another identity")
	}

	srcp, err := plugin.NewRecipient(spec.Recipient, stockUI)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	w, err := age.Encrypt(&b, srcp)
	if err != nil {
		t.Fatalf("stock client wrap: %v", err)
	}
	w.Write([]byte(identity.String() + "\n"))
	w.Close()
	if err := os.WriteFile(filepath.Join(g.Dir, "identity.test.age"), b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	got := unwrapOK(t, g, "test", uiWith().AsUI())
	if !bytes.Equal(got.Bytes(), identity.Bytes()) {
		t.Fatal("vault read another identity from a stock-wrapped file")
	}
}

// TestE2ESecureEnclave is the opt-in end-to-end test with the real
// age-plugin-se (it shows the Secure Enclave dialog). It runs only with
// PRECINTO_E2E=1 and PRECINTO_E2E_SE=1, against a throwaway store.
func TestE2ESecureEnclave(t *testing.T) {
	if os.Getenv("PRECINTO_E2E") != "1" || os.Getenv("PRECINTO_E2E_SE") != "1" {
		t.Skip("opt-in: PRECINTO_E2E=1 PRECINTO_E2E_SE=1 (shows the Secure Enclave dialog)")
	}
	// From `age-plugin-se keygen --access-control any-biometry-or-passcode`.
	rcpt, stub, path := os.Getenv("PRECINTO_E2E_SE_RECIPIENT"), os.Getenv("PRECINTO_E2E_SE_STUB"), os.Getenv("PRECINTO_E2E_SE_PATH")
	if rcpt == "" || stub == "" || !filepath.IsAbs(path) {
		t.Skip("set PRECINTO_E2E_SE_RECIPIENT, PRECINTO_E2E_SE_STUB and PRECINTO_E2E_SE_PATH (absolute path of age-plugin-se)")
	}
	s, _ := newStore(t)
	rec, err := s.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{{Kind: vault.FactorSE, Recipient: rcpt, IdentityStub: stub, PluginPath: path}}})
	if err != nil {
		t.Fatal(err)
	}
	rec.Destroy()
	g, err := s.Open(vault.GlobalID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	id, err := g.Unwrap(ctx, "se", (&vaulttest.UI{GUIOK: true}).AsUI())
	if err != nil {
		t.Fatal(err)
	}
	defer id.Destroy()
	if err := s.Verify(g, id); err != nil {
		t.Fatal(err)
	}
}
