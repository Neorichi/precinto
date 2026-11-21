package vault_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

// pass is a test passphrase that satisfies the D3 policy.
const pass = "Q8#zN4!pW7^rT2&mK-vault-test"

var epoch = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

func newStore(t *testing.T) (*vault.Store, string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return vault.OpenStore(filepath.Join(dir, "vaults"), filepath.Join(dir, "state", "verified"), filepath.Join(dir, "factors")), dir
}

func lb(t *testing.T, s string) *memguard.LockedBuffer { return vaulttest.LockedBuffer(t, s) }

func uiWith(secrets ...string) *vaulttest.UI {
	return &vaulttest.UI{Secrets: secrets, Interactive: true}
}

func passSpec(t *testing.T) vault.FactorSpec {
	return vault.FactorSpec{Kind: vault.FactorPassphrase, Passphrase: lb(t, pass), ScryptLogN: 10}
}

func initPass(t *testing.T, s *vault.Store) *memguard.LockedBuffer {
	t.Helper()
	rec, err := s.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{passSpec(t)}, UI: uiWith().AsUI(), Now: func() time.Time { return epoch }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rec.Destroy)
	return rec
}

func identityOf(t *testing.T, b *memguard.LockedBuffer) *age.X25519Identity {
	t.Helper()
	id, err := age.ParseX25519Identity(b.String())
	if err != nil {
		t.Fatal("not an X25519 identity")
	}
	return id
}

func mode(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

func TestPassphraseFactorWrapUnwrap(t *testing.T) {
	s, dir := newStore(t)
	if ok, err := s.Initialized(); ok || err != nil {
		t.Fatalf("Initialized before Init = %v %v", ok, err)
	}
	rec := initPass(t, s)
	recID := identityOf(t, rec)
	if ok, err := s.Initialized(); !ok || err != nil {
		t.Fatalf("Initialized = %v %v", ok, err)
	}
	if _, err := s.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{passSpec(t)}}); !errors.Is(err, fs.ErrExist) {
		t.Errorf("second Init = %v", err)
	}
	g, err := s.Open(vault.GlobalID)
	if err != nil {
		t.Fatal(err)
	}
	m := g.Meta
	if m.Format != vault.FormatVersion || m.ID != vault.GlobalID || m.Family != vault.Family || !m.CreatedAt.Equal(epoch) ||
		m.RecoveryRecipient != recID.Recipient().String() || m.Recipient == "" || len(m.RecipientsMAC) != 64 {
		t.Fatalf("meta %+v", m)
	}
	if len(m.Factors) != 2 || m.Factors[0].Name != "passphrase" || m.Factors[0].ScryptLogN != 10 || m.Factors[1].Kind != vault.FactorRecovery {
		t.Fatalf("factors %+v", m.Factors)
	}
	for _, f := range []string{"vault.toml", "identity.passphrase.age", "identity.recovery.age"} {
		if got := mode(t, filepath.Join(g.Dir, f)); got != 0o600 {
			t.Errorf("%s mode %v", f, got)
		}
	}
	for _, d := range []string{"vaults", "vaults/global", "state/verified", "factors"} {
		if got := mode(t, filepath.Join(dir, d)); got != fs.ModeDir|0o700 {
			t.Errorf("%s mode %v", d, got)
		}
	}

	ui := uiWith(pass)
	id, err := g.Unwrap(context.Background(), "passphrase", ui.AsUI())
	if err != nil {
		t.Fatal(err)
	}
	defer id.Destroy()
	if identityOf(t, id).Recipient().String() != m.Recipient {
		t.Fatal("unwrapped identity does not match the vault recipient")
	}
	if err := s.Verify(g, id); err != nil {
		t.Fatal(err)
	}
	rs, fpr, err := s.Recipients(vault.GlobalID)
	if err != nil || len(rs) != 2 {
		t.Fatalf("Recipients = %v %v", rs, err)
	}
	set := []string{m.Recipient, m.RecoveryRecipient}
	if set[0] > set[1] {
		set[0], set[1] = set[1], set[0]
	}
	sum := sha256.Sum256([]byte("x25519\n" + set[0] + "\n" + set[1]))
	if fpr != hex.EncodeToString(sum[:]) {
		t.Errorf("fingerprint %s", fpr)
	}
	if _, ok := rs[0].(*age.X25519Recipient); !ok {
		t.Errorf("recipient type %T", rs[0])
	}

	// The recovery key unwraps the same identity (D7), typed grouped.
	shown, err := vault.FormatRecoveryKey(rec)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := g.Unwrap(context.Background(), "recovery", uiWith(strings.ToLower(shown.String())).AsUI())
	shown.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id2.Bytes(), id.Bytes()) {
		t.Fatal("recovery unwrap gave another identity")
	}
	id2.Destroy()

	// Wrong passphrase, cancelled prompt, no UI.
	if _, err := g.Unwrap(context.Background(), "passphrase", uiWith("not the passphrase at all").AsUI()); !errors.Is(err, vault.ErrBadSecret) || errors.Is(err, vault.ErrWrongIdentity) {
		t.Errorf("wrong passphrase = %v, want ErrBadSecret (never ErrWrongIdentity)", err)
	}
	if _, err := g.Unwrap(context.Background(), "passphrase", uiWith().AsUI()); !errors.Is(err, vault.ErrCancelled) {
		t.Errorf("cancelled = %v", err)
	}
	if _, err := g.Unwrap(context.Background(), "", (&vaulttest.UI{}).AsUI()); !errors.Is(err, vault.ErrNoUI) {
		t.Errorf("no interactive factor = %v", err)
	}
	if _, err := g.Unwrap(context.Background(), "", nil); !errors.Is(err, vault.ErrNoUI) {
		t.Errorf("nil UI = %v", err)
	}
	if _, err := g.Unwrap(context.Background(), "missing", uiWith(pass).AsUI()); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("unknown factor = %v", err)
	}
	// "" picks the passphrase (recovery is never picked implicitly).
	id3, err := g.Unwrap(context.Background(), "", uiWith(pass).AsUI())
	if err != nil {
		t.Fatal(err)
	}
	id3.Destroy()
}

func TestCreateRootVaults(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Create(context.Background(), "root-acme", "/u/work/acme", uiWith(pass).AsUI()); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("Create before Init = %v", err)
	}
	rec := initPass(t, s)
	root, err := s.Create(context.Background(), "root-acme", "/u/work/acme", uiWith(pass).AsUI())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Destroy()
	v, err := s.Open("root-acme")
	if err != nil {
		t.Fatal(err)
	}
	g, _ := s.Open(vault.GlobalID)
	if v.Meta.RootPath != "/u/work/acme" || v.Meta.RecoveryRecipient != g.Meta.RecoveryRecipient || v.Meta.Recipient == g.Meta.Recipient {
		t.Fatalf("root vault %+v", v.Meta)
	}
	if identityOf(t, root).Recipient().String() != v.Meta.Recipient {
		t.Fatal("Create returned another identity")
	}
	if err := s.Verify(v, root); err != nil {
		t.Fatal(err)
	}
	// D1: the root's passphrase file opens only the root identity.
	got, err := v.Unwrap(context.Background(), "passphrase", uiWith(pass).AsUI())
	if err != nil || !bytes.Equal(got.Bytes(), root.Bytes()) {
		t.Fatalf("root unwrap: %v", err)
	}
	got.Destroy()
	// The recovery identity also opens it.
	recID := identityOf(t, rec)
	ct, err := os.ReadFile(filepath.Join(v.Dir, "identity.recovery.age"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(ct), recID)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(r)
	if strings.TrimSpace(string(plain)) != root.String() {
		t.Fatal("identity.recovery.age does not hold the root identity")
	}

	if _, err := s.Create(context.Background(), "root-acme", "", uiWith(pass).AsUI()); !errors.Is(err, fs.ErrExist) {
		t.Errorf("duplicate Create = %v", err)
	}
	if _, err := s.Create(context.Background(), "root-b", "", uiWith("wrong passphrase entirely").AsUI()); !errors.Is(err, vault.ErrBadSecret) {
		t.Errorf("Create with a wrong passphrase = %v, want ErrBadSecret", err)
	}
	if _, err := s.Create(context.Background(), "root-b", "", (&vaulttest.UI{}).AsUI()); !errors.Is(err, vault.ErrNoUI) {
		t.Errorf("Create without UI = %v", err)
	}
	for _, bad := range []string{vault.GlobalID, "", "../x", ".hidden", "a/b"} {
		if _, err := s.Create(context.Background(), bad, "", uiWith(pass).AsUI()); err == nil {
			t.Errorf("Create(%q) accepted", bad)
		}
	}
	ids, err := s.List()
	if err != nil || !reflect.DeepEqual(ids, []string{"global", "root-acme"}) {
		t.Fatalf("List = %v %v", ids, err)
	}
}

// editMeta rewrites one key of vault.toml, as a one-shot writer would.
func editMeta(t *testing.T, v *vault.Vault, key, value string) {
	t.Helper()
	p := filepath.Join(v.Dir, "vault.toml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	done := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, key+" = ") && !done {
			line = key + " = \"" + value + "\""
			done = true
		}
		out = append(out, line)
	}
	if !done {
		t.Fatalf("no %s in vault.toml", key)
	}
	if err := os.WriteFile(p, []byte(strings.Join(out, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newRecipient(t *testing.T) string {
	id, _ := age.GenerateX25519Identity()
	return id.Recipient().String()
}

// TestTripwireAndMAC covers SEC-9 for vault: a recovery recipient swapped in
// vault.toml trips the sealer's tripwire; with the tripwire copy edited too,
// the next unlock finds the MAC mismatch; a vault replaced consistently is
// refused because only Repair may move the tripwire.
func TestTripwireAndMAC(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	s := fx.Store
	v, _ := s.Open("root-acme")
	identity := lb(t, fx.Identity.String())

	editMeta(t, v, "recovery_recipient", newRecipient(t))
	if _, _, err := s.Recipients("root-acme"); !errors.Is(err, vault.ErrRecipientsChanged) {
		t.Fatalf("tripwire = %v", err)
	}
	v, _ = s.Open("root-acme")
	// Bypass the tripwire by editing the verified copy as well.
	vc := filepath.Join(filepath.Dir(filepath.Dir(v.Dir)), "state", "verified", "root-acme.recipients")
	b, _ := os.ReadFile(vc)
	b = []byte(strings.Replace(string(b), fx.Recovery.Recipient().String(), v.Meta.RecoveryRecipient, 1))
	os.WriteFile(vc, b, 0o600)
	if _, _, err := s.Recipients("root-acme"); err != nil {
		t.Fatalf("tripwire bypassed: %v", err)
	}
	if err := s.Verify(v, identity); !errors.Is(err, vault.ErrMACMismatch) {
		t.Fatalf("Verify after the swap = %v", err)
	}

	// The vault recipient swapped: the unlocked identity no longer matches.
	fx2 := vaulttest.New(t, mustRealTemp(t), "root-acme")
	v2, _ := fx2.Store.Open("root-acme")
	editMeta(t, v2, "recipient", newRecipient(t))
	v2, _ = fx2.Store.Open("root-acme")
	if err := fx2.Store.Verify(v2, lb(t, fx2.Identity.String())); !errors.Is(err, vault.ErrWrongIdentity) {
		t.Fatalf("Verify after a recipient swap = %v", err)
	}
	if _, _, err := fx2.Store.Recipients("root-acme"); !errors.Is(err, vault.ErrRecipientsChanged) {
		t.Fatalf("tripwire after a recipient swap = %v", err)
	}

	// Fully replaced, self-consistent vault (new identity, valid MAC): the
	// verified copy differs, so unlock refuses.
	fx3 := vaulttest.New(t, mustRealTemp(t), "root-acme")
	other := vaulttest.New(t, mustRealTemp(t), "root-acme")
	ov, _ := other.Store.Open("root-acme")
	tv, _ := fx3.Store.Open("root-acme")
	for _, f := range []string{"vault.toml", "identity.passphrase.age", "identity.recovery.age"} {
		b, _ := os.ReadFile(filepath.Join(ov.Dir, f))
		os.WriteFile(filepath.Join(tv.Dir, f), b, 0o600)
	}
	tv, _ = fx3.Store.Open("root-acme")
	if err := fx3.Store.Verify(tv, lb(t, other.Identity.String())); !errors.Is(err, vault.ErrRecipientsChanged) {
		t.Fatalf("Verify of a replaced vault = %v", err)
	}
}

func mustRealTemp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestVerifiedCopyLifecycle(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	s := fx.Store
	v, _ := s.Open("root-acme")
	vc := filepath.Join(filepath.Dir(filepath.Dir(v.Dir)), "state", "verified", "root-acme.recipients")
	if mode(t, vc) != 0o600 {
		t.Errorf("verified copy mode %v", mode(t, vc))
	}
	if err := os.Remove(vc); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Recipients("root-acme"); !errors.Is(err, vault.ErrRecipientsChanged) {
		t.Fatalf("missing verified copy = %v (the sealer must refuse)", err)
	}
	if err := s.Verify(v, lb(t, fx.Identity.String())); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Recipients("root-acme"); err != nil {
		t.Fatalf("after Verify: %v", err)
	}
}

// TestRepair covers SEC-26 for vault: the recipient rewrite, the kept or
// re-derived recovery recipient (ErrNeedRecovery), the verified copy and
// last_audit, and identity files left untouched.
func TestRepair(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	s := fx.Store
	v, _ := s.Open("root-acme")
	before := v.Meta.LastAudit
	hashes := identityHashes(t, v.Dir)
	editMeta(t, v, "recipient", newRecipient(t))
	v, _ = s.Open("root-acme")
	now := epoch.Add(time.Hour)
	res, err := s.Repair(v, vault.RepairOptions{Identity: lb(t, fx.Identity.String()), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !res.RecipientChanged || res.RecoveryChanged || !res.LastAudit.Equal(before) {
		t.Fatalf("result %+v", res)
	}
	if v.Meta.Recipient != fx.Identity.Recipient().String() || !v.Meta.LastAudit.Equal(now) {
		t.Fatalf("meta after repair %+v", v.Meta)
	}
	if _, _, err := s.Recipients("root-acme"); err != nil {
		t.Fatalf("sealing after repair: %v", err)
	}
	re, _ := s.Open("root-acme")
	if err := s.Verify(re, lb(t, fx.Identity.String())); err != nil {
		t.Fatalf("unlock after repair: %v", err)
	}
	if !reflect.DeepEqual(hashes, identityHashes(t, v.Dir)) {
		t.Fatal("Repair touched identity files")
	}

	// Recovery recipient changed: without the recovery key, refuse.
	editMeta(t, re, "recovery_recipient", newRecipient(t))
	re, _ = s.Open("root-acme")
	if _, err := s.Repair(re, vault.RepairOptions{Identity: lb(t, fx.Identity.String())}); !errors.Is(err, vault.ErrNeedRecovery) {
		t.Fatalf("Repair without --recovery = %v", err)
	}
	res, err = s.Repair(re, vault.RepairOptions{Identity: lb(t, fx.Identity.String()), Recovery: lb(t, fx.Recovery.String())})
	if err != nil || !res.RecoveryChanged || res.RecipientChanged {
		t.Fatalf("Repair --recovery = %+v %v", res, err)
	}
	if re.Meta.RecoveryRecipient != fx.Recovery.Recipient().String() {
		t.Fatal("recovery recipient not re-derived")
	}
	if _, _, err := s.Recipients("root-acme"); err != nil {
		t.Fatalf("sealing after repair --recovery: %v", err)
	}
	if _, err := s.Repair(re, vault.RepairOptions{Identity: lb(t, "not an identity")}); err == nil {
		t.Fatal("garbage identity accepted")
	}
}

func identityHashes(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "identity.") {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			s := sha256.Sum256(b)
			out[e.Name()] = hex.EncodeToString(s[:])
		}
	}
	return out
}

func sealedHeader(t *testing.T, rs ...age.Recipient) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := age.Encrypt(&b, rs...)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("payload"))
	w.Close()
	hdr, err := age.ExtractHeader(bytes.NewReader(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return hdr
}

func TestKeyring(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	kr := fx.Keyring
	if !kr.Has("root-acme") || !kr.Has(vault.GlobalID) || !reflect.DeepEqual(kr.IDs(), []string{"global", "root-acme"}) {
		t.Fatalf("IDs %v", kr.IDs())
	}
	rs, _, err := fx.Store.Recipients("root-acme")
	if err != nil {
		t.Fatal(err)
	}
	eph, _ := age.GenerateX25519Identity()
	hdr := sealedHeader(t, rs[0], rs[1], eph.Recipient())
	fk, err := kr.FileKey("root-acme", hdr)
	if err != nil || fk.Size() != 16 {
		t.Fatalf("FileKey: %v", err)
	}
	want, _ := age.DecryptHeader(hdr, fx.Identity)
	if !bytes.Equal(want, fk.Bytes()) {
		t.Fatal("file key differs")
	}
	fk.Destroy()
	// D1: the global identity does not open root-acme's capsules.
	if _, err := kr.FileKey(vault.GlobalID, sealedHeader(t, rs[0], eph.Recipient())); !errors.Is(err, vault.ErrWrongIdentity) {
		t.Errorf("FileKey with the wrong vault = %v", err)
	}

	m1, err := kr.MAC("root-acme", vault.InfoRecipients, []byte("data"))
	m2, _ := kr.MAC("root-acme", vault.InfoPolicy, []byte("data"))
	m3, _ := kr.MAC("root-acme", vault.InfoRecipients, []byte("data"))
	mg, _ := kr.MAC(vault.GlobalID, vault.InfoRecipients, []byte("data"))
	if err != nil || len(m1) != 64 || m1 == m2 || m1 != m3 || m1 == mg {
		t.Fatalf("MAC per info string: %s %s %s %v", m1, m2, mg, err)
	}
	// The recipients MAC in vault.toml is Keyring.MAC over the canonical set.
	v, _ := fx.Store.Open("root-acme")
	set := []string{v.Meta.Recipient, v.Meta.RecoveryRecipient}
	if set[0] > set[1] {
		set[0], set[1] = set[1], set[0]
	}
	if got, _ := kr.MAC("root-acme", vault.InfoRecipients, []byte("x25519\n"+set[0]+"\n"+set[1])); got != v.Meta.RecipientsMAC {
		t.Fatal("recipients_mac is not Keyring.MAC(InfoRecipients, canonical set)")
	}
	if _, err := kr.MAC("root-acme", "precinto/other/v1", nil); err == nil {
		t.Error("unknown MAC purpose accepted")
	}
	var seen string
	if err := kr.WithIdentity("root-acme", func(id age.Identity, b *memguard.LockedBuffer) error {
		seen = id.(*age.X25519Identity).Recipient().String()
		return nil
	}); err != nil || seen != v.Meta.Recipient {
		t.Fatalf("WithIdentity: %v", err)
	}

	kr.Drop("root-acme")
	if kr.Has("root-acme") {
		t.Fatal("Drop kept the identity")
	}
	if _, err := kr.FileKey("root-acme", hdr); !errors.Is(err, vault.ErrLocked) {
		t.Errorf("FileKey after Drop = %v", err)
	}
	if _, err := kr.MAC("root-acme", vault.InfoPolicy, nil); !errors.Is(err, vault.ErrLocked) {
		t.Errorf("MAC after Drop = %v", err)
	}
	kr.DropAll()
	if len(kr.IDs()) != 0 {
		t.Fatal("DropAll kept identities")
	}
	b := lb(t, fx.Identity.String()+"\n")
	if err := kr.Put("root-acme", b); err != nil || b.IsAlive() {
		t.Fatalf("Put: %v (alive %v)", err, b.IsAlive())
	}
	bad := lb(t, "AGE-SECRET-KEY-1NOTAKEY")
	if err := kr.Put("x", bad); err == nil || bad.IsAlive() {
		t.Fatalf("Put of garbage: %v (alive %v)", err, bad.IsAlive())
	}
	if err := kr.Put("../x", lb(t, fx.Identity.String())); err == nil {
		t.Fatal("bad id accepted")
	}

	// Concurrent use (run with -race).
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				if k, err := kr.FileKey("root-acme", hdr); err == nil {
					k.Destroy()
				}
			} else {
				_, _ = kr.MAC("root-acme", vault.InfoPolicy, []byte{byte(i)})
				_ = kr.IDs()
			}
		}(i)
	}
	wg.Wait()
}

func TestFactorsAddRemove(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	v, _ := fx.Store.Open("root-acme")
	identity := lb(t, fx.Identity.String())
	if err := v.RemoveFactor("passphrase"); !errors.Is(err, vault.ErrLastFactor) {
		t.Fatalf("removing the last interactive factor = %v", err)
	}
	if err := v.RemoveFactor("recovery"); !errors.Is(err, vault.ErrLastFactor) {
		t.Fatalf("removing recovery = %v", err)
	}
	if err := v.RemoveFactor("nope"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("removing an unknown factor = %v", err)
	}
	other, _ := age.GenerateX25519Identity()
	if err := v.AddFactor(context.Background(), lb(t, other.String()), vault.FactorSpec{Kind: vault.FactorPassphrase, Name: "second", Passphrase: lb(t, pass), ScryptLogN: 10}, nil); !errors.Is(err, vault.ErrWrongIdentity) {
		t.Fatalf("AddFactor with another identity = %v", err)
	}
	weak := lb(t, "short")
	if err := v.AddFactor(context.Background(), identity, vault.FactorSpec{Kind: vault.FactorPassphrase, Name: "second", Passphrase: weak, ScryptLogN: 10}, nil); !errors.Is(err, vault.ErrWeakPassphrase) || weak.IsAlive() {
		t.Fatalf("weak passphrase = %v (consumed %v)", err, !weak.IsAlive())
	}
	if err := v.AddFactor(context.Background(), identity, vault.FactorSpec{Kind: vault.FactorPassphrase, Passphrase: lb(t, pass), ScryptLogN: 10}, nil); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("duplicate factor name = %v", err)
	}
	second := "another strong passphrase: 9@Lq!"
	sp := lb(t, second)
	if err := v.AddFactor(context.Background(), identity, vault.FactorSpec{Kind: vault.FactorPassphrase, Name: "second", Passphrase: sp, ScryptLogN: 10}, nil); err != nil {
		t.Fatal(err)
	}
	if sp.IsAlive() {
		t.Error("passphrase not consumed")
	}
	re, _ := fx.Store.Open("root-acme")
	if len(re.Meta.Factors) != 3 {
		t.Fatalf("factors %+v", re.Meta.Factors)
	}
	got, err := re.Unwrap(context.Background(), "second", uiWith(second).AsUI())
	if err != nil || !bytes.Equal(got.Bytes(), identity.Bytes()) {
		t.Fatalf("unwrap with the new factor: %v", err)
	}
	got.Destroy()
	if err := re.RemoveFactor("passphrase"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(re.Dir, "identity.passphrase.age")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("identity file left after RemoveFactor")
	}
	if err := re.RemoveFactor("second"); !errors.Is(err, vault.ErrLastFactor) {
		t.Fatalf("now the last factor = %v", err)
	}
	if _, _, err := fx.Store.Recipients("root-acme"); err != nil {
		t.Fatalf("factor changes must not trip the recipients tripwire: %v", err)
	}
}

func TestUsableFactors(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	v, _ := fx.Store.Open("root-acme")
	names := func(fs []vault.Factor) []string {
		var out []string
		for _, f := range fs {
			out = append(out, f.Name)
		}
		return out
	}
	if got := names(v.UsableFactors(true, false)); !reflect.DeepEqual(got, []string{"passphrase", "recovery"}) {
		t.Errorf("tty: %v", got)
	}
	if got := names(v.UsableFactors(false, true)); len(got) != 0 {
		t.Errorf("gui only: %v (a passphrase needs a prompt)", got)
	}
}

func TestUnwrapRefusesTamperedFiles(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	v, _ := fx.Store.Open("root-acme")
	p := filepath.Join(v.Dir, "identity.passphrase.age")
	orig, _ := os.ReadFile(p)

	// A passphrase file with another work factor is refused before any
	// prompt (no secret is consumed).
	r, _ := age.NewScryptRecipient(pass)
	r.SetWorkFactor(11)
	var b bytes.Buffer
	w, _ := age.Encrypt(&b, r)
	io.WriteString(w, fx.Identity.String()+"\n")
	w.Close()
	os.WriteFile(p, b.Bytes(), 0o600)
	ui := uiWith(pass)
	if _, err := v.Unwrap(context.Background(), "passphrase", ui.AsUI()); !errors.Is(err, vault.ErrWrongIdentity) {
		t.Fatalf("other work factor = %v", err)
	}
	if len(ui.Secrets) != 1 {
		t.Fatal("prompted before checking the file")
	}
	// A flipped byte fails authentication.
	bad := append([]byte(nil), orig...)
	bad[len(bad)-3] ^= 1
	os.WriteFile(p, bad, 0o600)
	if _, err := v.Unwrap(context.Background(), "passphrase", uiWith(pass).AsUI()); err == nil {
		t.Fatal("tampered identity file accepted")
	}
	os.Remove(p)
	if _, err := v.Unwrap(context.Background(), "passphrase", uiWith(pass).AsUI()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing identity file = %v", err)
	}
}

func TestStrictMeta(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	v, _ := fx.Store.Open("root-acme")
	p := filepath.Join(v.Dir, "vault.toml")
	orig, _ := os.ReadFile(p)
	for name, content := range map[string]string{
		"unknown key": string(orig) + "\nsurprise = true\n",
		"format 2":    strings.Replace(string(orig), "format = 1", "format = 2", 1),
		"other id":    strings.Replace(string(orig), `id = "root-acme"`, `id = "root-other"`, 1),
	} {
		os.WriteFile(p, []byte(content), 0o600)
		if _, err := fx.Store.Open("root-acme"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	os.WriteFile(p, orig, 0o600)
	if _, err := fx.Store.Open("missing"); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Open(missing) = %v", err)
	}
}

func TestRemoveVault(t *testing.T) {
	fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
	s := fx.Store
	v, _ := s.Open("root-acme")
	if err := s.Remove(vault.GlobalID); err == nil {
		t.Fatal("the global vault was removed")
	}
	if err := s.Remove("missing"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("Remove(missing) = %v", err)
	}
	extra := filepath.Join(v.Dir, "notes.txt")
	os.WriteFile(extra, []byte("x"), 0o600)
	if err := s.Remove("root-acme"); err == nil {
		t.Fatal("removed a vault holding an unexpected file")
	}
	if _, err := os.Lstat(filepath.Join(v.Dir, "vault.toml")); err != nil {
		t.Fatal("refused removal deleted files")
	}
	os.Remove(extra)
	if err := s.Remove("root-acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(v.Dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("vault directory left")
	}
	if ids, _ := s.List(); !reflect.DeepEqual(ids, []string{"global"}) {
		t.Fatalf("List = %v", ids)
	}
	if _, _, err := s.Recipients("root-acme"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("Recipients after Remove = %v", err)
	}
}

func TestRecoveryKeyFormatParseVerify(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	key := lb(t, id.String())
	shown, err := vault.FormatRecoveryKey(key)
	if err != nil {
		t.Fatal(err)
	}
	groups := strings.Fields(shown.String())
	if groups[0] != "AGE-SECRET-KEY-1" || len(groups) != 11 || len(groups[10]) != 4 {
		t.Fatalf("format: %d groups", len(groups))
	}
	for _, g := range groups[1:10] {
		if len(g) != 6 {
			t.Fatalf("group of %d", len(g))
		}
	}
	for _, typed := range []string{shown.String(), strings.ToLower(shown.String()), strings.ReplaceAll(shown.String(), " ", "-"), id.String() + "\n", "  " + strings.ReplaceAll(shown.String(), " ", "\n") + "  "} {
		got, err := vault.ParseRecoveryKey(lb(t, typed))
		if err != nil || got.(*age.X25519Identity).Recipient().String() != id.Recipient().String() {
			t.Fatalf("ParseRecoveryKey: %v", err)
		}
	}
	s := id.String()
	flipped := s[:20] + string("qpzry9x8gf2tvdw0s3jn54khce6mua7l"[strings.IndexByte("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L", s[20])^1]) + s[21:]
	// Typed keys are case-insensitive, even mixed.
	if _, err := vault.ParseRecoveryKey(lb(t, strings.ToUpper(s[:30])+strings.ToLower(s[30:]))); err != nil {
		t.Errorf("mixed-case recovery key refused: %v", err)
	}
	for _, bad := range []string{"", "AGE-SECRET-KEY-1", "hello world", flipped, s + "Q", s[:len(s)-1]} {
		if _, err := vault.ParseRecoveryKey(lb(t, bad)); err == nil {
			t.Errorf("ParseRecoveryKey accepted %d bytes of garbage", len(bad))
		}
	}
	other, _ := age.GenerateX25519Identity()
	hdr := sealedHeader(t, other.Recipient(), id.Recipient())
	if err := vault.VerifyRecovery(key, hdr); err != nil {
		t.Fatal(err)
	}
	// A wrong recovery key is a bad secret (exit 3, CC-08), never a tamper
	// error; so is a malformed one.
	for name, wrong := range map[string]string{"another key": other.String(), "malformed": "AGE-SECRET-KEY-1 nonsense"} {
		err := vault.VerifyRecovery(lb(t, wrong), sealedHeader(t, id.Recipient()))
		if !errors.Is(err, vault.ErrBadSecret) || errors.Is(err, vault.ErrWrongIdentity) {
			t.Fatalf("VerifyRecovery with %s = %v, want ErrBadSecret", name, err)
		}
	}
	// A header whose MAC fails once the right key opened its stanza was
	// tampered with: that is not the user's mistake.
	hdr = sealedHeader(t, id.Recipient())
	mac := bytes.LastIndex(hdr, []byte("--- ")) + len("--- ")
	if hdr[mac] == 'A' { // another valid base64 character: the MAC, not the syntax, fails
		hdr[mac] = 'B'
	} else {
		hdr[mac] = 'A'
	}
	if err := vault.VerifyRecovery(key, hdr); !errors.Is(err, vault.ErrWrongIdentity) || errors.Is(err, vault.ErrBadSecret) {
		t.Fatalf("VerifyRecovery of a tampered header = %v, want ErrWrongIdentity", err)
	}
}

func TestPassphrasePolicy(t *testing.T) {
	for _, c := range []struct {
		p       string
		atLeast float64
		below   float64
	}{
		{"password", 0, 50},
		{"aaaaaaaaaaaaaaaaaaaa", 0, 40},
		{"12345678901234567890", 0, 40},
		{"abcdefghijklmnopqrst", 0, 40},
		{"Q8#zN4!pW7^rT2&mK-vault-test", 80, 1000},
		{"", 0, 1},
	} {
		got := vault.EstimateBits(lb(t, c.p))
		if got < c.atLeast || got >= c.below {
			t.Errorf("EstimateBits(%d chars) = %.1f, want [%v, %v)", len(c.p), got, c.atLeast, c.below)
		}
	}
	if vault.EstimateBits(nil) != 0 {
		t.Error("nil buffer")
	}
	d, err := vault.Diceware(7)
	if err != nil {
		t.Fatal(err)
	}
	ws := strings.Split(strings.Clone(d.String()), "-")
	if len(ws) != 7 {
		t.Fatalf("Diceware(7) gave %d words", len(ws))
	}
	bits := vault.EstimateBits(d)
	if bits < 88 || bits > 100 {
		t.Fatalf("7 Diceware words estimated at %.1f bits", bits)
	}
	// A Diceware passphrase is judged by its words, not its length.
	four := strings.Join(ws[:4], "-")
	if b := vault.EstimateBits(lb(t, four)); b > 60 {
		t.Errorf("4 list words estimated at %.1f bits", b)
	}
	d.Destroy()
	if _, err := vault.Diceware(0); err == nil {
		t.Error("Diceware(0) accepted")
	}
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		d, _ := vault.Diceware(2)
		seen[d.String()] = true
		d.Destroy()
	}
	if len(seen) < 45 {
		t.Errorf("Diceware repeats itself: %d distinct of 50", len(seen))
	}
	// Policy at enrollment: ≥ 12 characters and ≥ 80 bits (D3).
	s, _ := newStore(t)
	for _, weak := range []string{"short", "aaaaaaaaaaaaaaaaaaaaaaaaaaa", strings.Join(ws[:3], "-")} {
		_, err := s.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{{Kind: vault.FactorPassphrase, Passphrase: lb(t, weak), ScryptLogN: 10}}})
		if !errors.Is(err, vault.ErrWeakPassphrase) {
			t.Errorf("Init with a weak passphrase = %v", err)
		}
	}
	if _, err := s.Init(context.Background(), vault.InitOptions{}); !errors.Is(err, vault.ErrLastFactor) {
		t.Errorf("Init without factors = %v", err)
	}
	if _, err := s.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{{Kind: vault.FactorPassphrase, Passphrase: lb(t, pass), ScryptLogN: 23}}}); !errors.Is(err, vault.ErrWeakPassphrase) {
		t.Errorf("work factor above the ceiling = %v", err)
	}
	if ok, _ := s.Initialized(); ok {
		t.Fatal("a refused Init initialized the store")
	}
}

func TestCalibrateScrypt(t *testing.T) {
	for _, target := range []time.Duration{time.Second, time.Millisecond, time.Hour, 0} {
		if n := vault.CalibrateScrypt(target); n < 19 || n > 22 {
			t.Errorf("CalibrateScrypt(%v) = %d", target, n)
		}
	}
}

// TestNoSecretsOnDisk: identities and passphrases never appear in clear in
// the store (I7).
func TestNoSecretsOnDisk(t *testing.T) {
	dir := mustRealTemp(t)
	fx := vaulttest.New(t, dir, "root-acme")
	secrets := []string{fx.Identity.String(), fx.Recovery.String(), "vaulttest:Q8#zN4!pW7^rT2&mK"}
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || !fi.Mode().IsRegular() {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) || bytes.Contains(bytes.ToLower(b), []byte(strings.ToLower(s))) {
				t.Errorf("%s holds a secret in clear", p)
			}
		}
		return nil
	})
}

// TestConcurrentCreate: two creators of one vault id race; exactly one
// wins, and the tripwire copy matches the winner's vault (a loser never
// overwrites it).
func TestConcurrentCreate(t *testing.T) {
	s, _ := newStore(t)
	initPass(t, s)
	type result struct {
		id  *memguard.LockedBuffer
		err error
	}
	out := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			id, err := s.Create(context.Background(), "root-race", "", uiWith(pass).AsUI())
			out <- result{id, err}
		}()
	}
	var won *memguard.LockedBuffer
	for i := 0; i < 2; i++ {
		r := <-out
		switch {
		case r.err == nil:
			if won != nil {
				t.Fatal("two creators won")
			}
			won = r.id
		case !errors.Is(r.err, fs.ErrExist):
			t.Fatalf("loser: %v", r.err)
		}
	}
	if won == nil {
		t.Fatal("no creator won")
	}
	defer won.Destroy()
	v, err := s.Open("root-race")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Recipients("root-race"); err != nil {
		t.Fatalf("tripwire after a race: %v", err)
	}
	if err := s.Verify(v, won); err != nil {
		t.Fatalf("winner's identity: %v", err)
	}
	ents, _ := os.ReadDir(s.VaultsDir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("temporary vault directory left: %s", e.Name())
		}
	}
}

// TestTestdataHygiene: the fake plugin's sources carry no key material,
// real paths or tokens (S13); its keys are derived at run time.
func TestTestdataHygiene(t *testing.T) {
	testkit.Hygiene(t, "testdata")
}

// UX-07: Init hands the new recovery identity to Confirm before it writes
// anything: the user sees and confirms the key first, and when Confirm
// fails (the user stopped before typing it back) nothing is created, so
// init can run again with a new key.
func TestInitConfirmsTheRecoveryKeyFirst(t *testing.T) {
	s, dir := newStore(t)
	stop := errors.New("not confirmed")
	var seen string
	_, err := s.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{passSpec(t)}, UI: uiWith().AsUI(),
		Confirm: func(rec *memguard.LockedBuffer) error {
			seen = string(append([]byte(nil), rec.Bytes()...)) // a copy: the buffer is destroyed on failure
			if _, err := os.Lstat(filepath.Join(dir, "vaults", vault.GlobalID)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the global vault exists before the key was confirmed: %v", err)
			}
			return stop
		}})
	if !errors.Is(err, stop) {
		t.Fatalf("Init = %v, want the Confirm error", err)
	}
	if !strings.HasPrefix(seen, "AGE-SECRET-KEY-1") {
		t.Fatal("Confirm did not get the recovery identity")
	}
	if ok, err := s.Initialized(); ok || err != nil {
		t.Fatalf("Initialized after a refused confirmation = %v %v", ok, err)
	}
	for _, d := range []string{"vaults", filepath.Join("state", "verified"), "factors"} {
		if es, _ := os.ReadDir(filepath.Join(dir, d)); len(es) != 0 {
			t.Errorf("%s holds %d entries after a refused confirmation", d, len(es))
		}
	}
	// Confirmed: the identity Confirm saw is the one Init returns.
	rec, err := s.Init(context.Background(), vault.InitOptions{Factors: []vault.FactorSpec{passSpec(t)}, UI: uiWith().AsUI(),
		Confirm: func(r *memguard.LockedBuffer) error { seen = string(append([]byte(nil), r.Bytes()...)); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Destroy()
	if string(rec.Bytes()) != seen {
		t.Fatal("Init returned another identity than the one confirmed")
	}
	if ok, err := s.Initialized(); !ok || err != nil {
		t.Fatalf("Initialized = %v %v", ok, err)
	}
}
