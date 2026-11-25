package capsule_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/internal/vault"
	"github.com/Neorichi/precinto/internal/vault/vaulttest"
)

// sealWithVault seals one synthetic session file of a testkit home to the
// root vault of a vaulttest fixture, as the sealer does: recipients and
// fingerprint from the store (D5 tripwire), unit key from the salt (D45),
// capsule in the unit directory of the layout.
type sealed struct {
	home    *testkit.Home
	fx      *vaulttest.Fixture
	out     *fsx.Dir
	s       *capsule.Sealed
	content []byte
	marker  string
}

func sealWithVault(t *testing.T) sealed {
	t.Helper()
	h := testkit.NewHome(t)
	if err := h.Layout.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	fx := vaulttest.New(t, h.Base, "root-acme")
	salt, err := capsule.LoadSalt(h.Layout.NameSalt)
	if err != nil {
		t.Fatal(err)
	}
	sid := "00000000-0000-4000-8000-000000000042"
	key, err := harness.UnitKeyFor(salt, capsule.KindClaudeSession, "claude-code", "0123456789abcdef", "root-acme", sid)
	if err != nil {
		t.Fatal(err)
	}
	rel := "projects/-u-work-acme/" + sid + ".jsonl"
	marker := testkit.Marker(t)
	content := []byte(`{"type":"user","message":"` + marker + `"}` + "\n")
	p := filepath.Join(h.ClaudeConfig, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	base, err := fsx.OpenBase(mustReal(t, h.ClaudeConfig))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })
	unitDir := h.Layout.UnitCapsuleDir("claude-code", key)
	if err := fsx.MkdirPrivate(unitDir); err != nil {
		t.Fatal(err)
	}
	out, err := fsx.OpenBase(mustReal(t, unitDir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	rs, fpr, err := fx.Store.Recipients("root-acme")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := base.Lstat(rel)
	m := manifest("vault integration")
	m.UnitKey, m.UnitID, m.RecipientsFpr = key, sid, fpr
	s, err := capsule.Seal(context.Background(), capsule.SealRequest{
		Manifest: m, Inputs: []capsule.Input{{Base: capsule.BaseClaudeConfig, Dir: base, Rel: rel, Path: p, Snap: st, Append: true}},
		Recipients: rs, Out: out, Name: capsule.GenName(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	return sealed{home: h, fx: fx, out: out, s: s, content: content, marker: marker}
}

func mustReal(t *testing.T, p string) string {
	t.Helper()
	r, err := fsx.Realpath(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSealToVaultAndRestoreThroughKeyring(t *testing.T) {
	x := sealWithVault(t)
	hdr, hsum, err := capsule.ReadHeader(x.out, x.s.Name)
	if err != nil || hsum != x.s.HeaderSHA256 {
		t.Fatalf("ReadHeader: %v", err)
	}
	if err := capsule.CheckHeader(bytes.NewReader(hdr), capsule.HeaderStanzas); err != nil {
		t.Fatal(err)
	}
	fk, err := x.fx.Keyring.FileKey("root-acme", hdr)
	if err != nil {
		t.Fatal(err)
	}
	defer fk.Destroy()
	if _, err := x.fx.Keyring.FileKey(vault.GlobalID, hdr); !errors.Is(err, vault.ErrWrongIdentity) {
		t.Fatalf("global vault opened a root capsule: %v (D1)", err)
	}
	st, err := fsx.NewStaging(x.home.Layout.StagingDir, mustReal(t, x.home.ClaudeConfig), "op-restore")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Remove()
	f, _, err := x.out.Open(x.s.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, staged, err := capsule.Extract(context.Background(), f, capsule.ExtractOptions{
		FileKey: fk.Bytes(), Staging: st, Limits: capsule.Limits{MaxTotal: 1 << 20},
		Check: func(e capsule.Entry) error {
			if e.Base != capsule.BaseClaudeConfig || !strings.HasPrefix(e.Rel, "projects/") {
				return errors.New("outside the session's targets")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.UnitKey != x.s.Manifest.UnitKey || m.VaultID != "root-acme" || len(staged) != 1 {
		t.Fatalf("manifest %+v", m)
	}
	b, _ := os.ReadFile(filepath.Join(st.Path, staged[0].StagedRel))
	if !bytes.Equal(b, x.content) {
		t.Fatal("restored bytes differ")
	}
	// The recovery key alone opens it too (recover --verify, D7).
	if err := vault.VerifyRecovery(vaulttest.LockedBuffer(t, x.fx.Recovery.String()), hdr); err != nil {
		t.Fatal(err)
	}
	// Leak check: the marker is only inside the ciphertext and the plaintext
	// that was sealed (which the sweep deletes later, not capsule).
	hits := testkit.GrepTree(t, x.home.Base, x.marker, "capsules", "staging")
	if len(hits) != 0 {
		t.Fatalf("marker found in %v", hits)
	}
}

// TestSealerTripwire (SEC-9, sealer side): after vault.toml is edited the
// store refuses the recipients, so nothing can be sealed to a foreign key.
func TestSealerTripwire(t *testing.T) {
	x := sealWithVault(t)
	v, err := x.fx.Store.Open("root-acme")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(v.Dir, "vault.toml")
	b, _ := os.ReadFile(p)
	other := newKeys(t)
	b = []byte(strings.Replace(string(b), v.Meta.RecoveryRecipient, other.recovery.Recipient().String(), 1))
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := x.fx.Store.Recipients("root-acme"); !errors.Is(err, vault.ErrRecipientsChanged) {
		t.Fatalf("Recipients after an edit = %v", err)
	}
}
