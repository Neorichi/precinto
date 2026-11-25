package vaulttest_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/Neorichi/precinto/internal/vault"
	"github.com/Neorichi/precinto/internal/vault/vaulttest"
)

func TestFixture(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fx := vaulttest.New(t, dir, "root-acme")
	if fx.RootID != "root-acme" || fx.Store.VaultsDir != filepath.Join(dir, "vaults") ||
		fx.Store.VerifiedDir != filepath.Join(dir, "state", "verified") || fx.Store.FactorsDir != filepath.Join(dir, "factors") {
		t.Fatalf("fixture %+v", fx)
	}
	if !fx.Keyring.Has("root-acme") || !fx.Keyring.Has(vault.GlobalID) {
		t.Fatalf("keyring %v", fx.Keyring.IDs())
	}
	v, err := fx.Store.Open("root-acme")
	if err != nil {
		t.Fatal(err)
	}
	if v.Meta.Recipient != fx.Identity.Recipient().String() || v.Meta.RecoveryRecipient != fx.Recovery.Recipient().String() {
		t.Fatal("fixture identities do not match the vault")
	}
	rs, _, err := fx.Store.Recipients("root-acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fx.Store.Recipients(vault.GlobalID); err != nil {
		t.Fatal(err)
	}
	// A header sealed to the root's recipients opens through the keyring
	// and with the test identities.
	eph, _ := age.GenerateX25519Identity()
	var b bytes.Buffer
	w, _ := age.Encrypt(&b, append(rs, eph.Recipient())...)
	w.Write([]byte("x"))
	w.Close()
	hdr, _ := age.ExtractHeader(bytes.NewReader(b.Bytes()))
	k, err := fx.Keyring.FileKey("root-acme", hdr)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Destroy()
	for _, id := range []*age.X25519Identity{fx.Identity, fx.Recovery} {
		if fk, err := age.DecryptHeader(hdr, id); err != nil || !bytes.Equal(fk, k.Bytes()) {
			t.Fatalf("test identity: %v", err)
		}
	}
	// The passphrase factor unwraps with the fixture passphrase (logN 10).
	if v.Meta.Factors[0].Kind != vault.FactorPassphrase || v.Meta.Factors[0].ScryptLogN != 10 {
		t.Fatalf("factors %+v", v.Meta.Factors)
	}
	// Two fixtures in one test are independent.
	other := vaulttest.New(t, t.TempDir(), "root-acme")
	if other.Identity.Recipient().String() == fx.Identity.Recipient().String() {
		t.Fatal("fixtures share an identity")
	}
}

func TestScriptedUI(t *testing.T) {
	u := &vaulttest.UI{Secrets: []string{"one"}, Confirms: []bool{true}, Interactive: true, GUIOK: true}
	ui := u.AsUI()
	if !ui.Interactive() || !ui.GUI() {
		t.Fatal("capabilities")
	}
	s, err := ui.Secret("p")
	if err != nil || s.String() != "one" {
		t.Fatalf("Secret: %v", err)
	}
	s.Destroy()
	if _, err := ui.Secret("p"); !errors.Is(err, vault.ErrCancelled) {
		t.Fatalf("exhausted Secret = %v", err)
	}
	if ok, err := ui.Confirm("q", "y", "n"); !ok || err != nil {
		t.Fatalf("Confirm: %v %v", ok, err)
	}
	if _, err := ui.Confirm("q", "y", "n"); !errors.Is(err, vault.ErrCancelled) {
		t.Fatalf("exhausted Confirm = %v", err)
	}
	ui.Display("hello")
	if len(u.Displayed) != 1 || u.Displayed[0] != "hello" || len(u.Secrets) != 0 {
		t.Fatalf("state %+v", u)
	}
	quiet := (&vaulttest.UI{Secrets: []string{"x"}}).AsUI()
	if _, err := quiet.Secret("p"); !errors.Is(err, vault.ErrNoUI) {
		t.Fatalf("non-interactive Secret = %v", err)
	}
	if _, err := quiet.Confirm("p", "y", "n"); !errors.Is(err, vault.ErrNoUI) {
		t.Fatalf("non-interactive Confirm = %v", err)
	}
	b := vaulttest.LockedBuffer(t, "secret")
	if b.String() != "secret" || !b.IsAlive() {
		t.Fatal("LockedBuffer")
	}
}

// TamperRecipient trips the D5 checks the way a one-shot writer would.
func TestTamperRecipient(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		fx := vaulttest.New(t, dir, "root-acme")
		got := fx.TamperRecipient(t, "root-acme", recovery)
		v, err := fx.Store.Open("root-acme")
		if err != nil {
			t.Fatal(err)
		}
		field := v.Meta.Recipient
		if recovery {
			field = v.Meta.RecoveryRecipient
		}
		if field != got || got == fx.Identity.Recipient().String() || got == fx.Recovery.Recipient().String() {
			t.Fatalf("recovery=%v: field %s, returned %s", recovery, field, got)
		}
		for _, fct := range v.Meta.Factors {
			if fct.Recipient == got {
				t.Fatal("a factor recipient was edited")
			}
		}
		if _, _, err := fx.Store.Recipients("root-acme"); !errors.Is(err, vault.ErrRecipientsChanged) {
			t.Errorf("recovery=%v: Recipients = %v, want ErrRecipientsChanged", recovery, err)
		}
		if err := fx.Store.Verify(v, vaulttest.LockedBuffer(t, fx.Identity.String())); err == nil {
			t.Errorf("recovery=%v: Verify accepted a tampered vault", recovery)
		}
	}
}
