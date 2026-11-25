package vaulttest

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/vault"
)

// Fixture is an initialized store with one root vault.
type Fixture struct {
	Store    *vault.Store
	RootID   string
	Identity *age.X25519Identity // the root vault identity (test only)
	Recovery *age.X25519Identity // the recovery identity (test only)
	Keyring  *vault.Keyring      // already holding RootID and vault.GlobalID
}

// fixturePassphrase is the passphrase of every fixture's passphrase factor.
// It is a test constant, strong enough for the D3 policy.
const fixturePassphrase = "vaulttest:Q8#zN4!pW7^rT2&mK"

// fixtureLogN is the scrypt work factor of fixtures (test binaries only).
const fixtureLogN = 10

// fixtureTime is the creation time recorded in fixture vaults.
var fixtureTime = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

// New creates a store under dir (vaults/, state/verified/, factors/) with a
// passphrase-only factor (scrypt logN 10 for speed), the global vault and a
// root vault rootID, all unlocked in Keyring.
func New(t testing.TB, dir, rootID string) *Fixture {
	t.Helper()
	if rootID == vault.GlobalID {
		t.Fatalf("vaulttest.New: root id %q is reserved", rootID)
	}
	ctx := context.Background()
	store := vault.OpenStore(filepath.Join(dir, "vaults"), filepath.Join(dir, "state", "verified"), filepath.Join(dir, "factors"))
	// Two answers: Create confirms the passphrase, then the global vault
	// is unwrapped with it.
	ui := &UI{Secrets: []string{fixturePassphrase, fixturePassphrase}, Interactive: true}
	recovery, err := store.Init(ctx, vault.InitOptions{
		Factors: []vault.FactorSpec{{Kind: vault.FactorPassphrase, Passphrase: LockedBuffer(t, fixturePassphrase), ScryptLogN: fixtureLogN}},
		UI:      ui.AsUI(),
		Now:     func() time.Time { return fixtureTime },
	})
	if err != nil {
		t.Fatalf("vaulttest.New: Init: %v", err)
	}
	recoveryID := parse(t, recovery)
	recovery.Destroy()

	root, err := store.Create(ctx, rootID, "", ui.AsUI())
	if err != nil {
		t.Fatalf("vaulttest.New: Create(%s): %v", rootID, err)
	}
	rootIdentity := parse(t, root)
	kr := vault.NewKeyring()
	t.Cleanup(kr.DropAll)
	if err := kr.Put(rootID, root); err != nil {
		t.Fatalf("vaulttest.New: %v", err)
	}
	g, err := store.Open(vault.GlobalID)
	if err != nil {
		t.Fatalf("vaulttest.New: %v", err)
	}
	global, err := g.Unwrap(ctx, string(vault.FactorPassphrase), ui.AsUI())
	if err != nil {
		t.Fatalf("vaulttest.New: unwrap the global vault: %v", err)
	}
	if err := store.Verify(g, global); err != nil {
		global.Destroy()
		t.Fatalf("vaulttest.New: verify the global vault: %v", err)
	}
	if err := kr.Put(vault.GlobalID, global); err != nil {
		t.Fatalf("vaulttest.New: %v", err)
	}
	return &Fixture{Store: store, RootID: rootID, Identity: rootIdentity, Recovery: recoveryID, Keyring: kr}
}

// TamperRecipient replaces the vault recipient of vaultID in its vault.toml
// (or, with recovery, the recovery recipient) with a fresh foreign X25519
// recipient, as a one-shot writer would (SEC-9, SEC-26), and returns it.
// Only the top-level key is edited, byte for byte, so the recipients MAC
// and the verified copy no longer match.
func (f *Fixture) TamperRecipient(t testing.TB, vaultID string, recovery bool) string {
	t.Helper()
	foreign, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("vaulttest: %v", err)
	}
	key := "recipient"
	if recovery {
		key = "recovery_recipient"
	}
	path := filepath.Join(f.Store.VaultsDir, vaultID, "vault.toml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("vaulttest: TamperRecipient: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	replaced := false
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "[") {
			break // factors and other tables follow the top-level keys
		}
		name, _, ok := strings.Cut(trimmed, "=")
		if ok && strings.TrimSpace(name) == key {
			lines[i] = key + " = " + strconv.Quote(foreign.Recipient().String())
			replaced = true
			break
		}
	}
	if !replaced {
		t.Fatalf("vaulttest: TamperRecipient: %s has no top-level %s", path, key)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatalf("vaulttest: TamperRecipient: %v", err)
	}
	return foreign.Recipient().String()
}

func parse(t testing.TB, b *memguard.LockedBuffer) *age.X25519Identity {
	t.Helper()
	id, err := age.ParseX25519Identity(b.String())
	if err != nil {
		t.Fatalf("vaulttest: identity does not parse")
	}
	return id
}

// LockedBuffer copies s into a locked buffer (test convenience).
func LockedBuffer(t testing.TB, s string) *memguard.LockedBuffer {
	t.Helper()
	b := memguard.NewBufferFromBytes([]byte(s))
	t.Cleanup(b.Destroy)
	return b
}

// UI is a scripted vault.UI.
type UI struct {
	Secrets     []string // answers to Secret, in order
	Confirms    []bool   // answers to Confirm, in order
	Displayed   []string // recorded Display messages
	Interactive bool
	GUIOK       bool
}

// AsUI returns u as a vault.UI.
func (u *UI) AsUI() vault.UI { return scripted{u} }

// uiMu guards every scripted UI: a vault.UI may be driven from a plugin
// session and the caller at once.
var uiMu sync.Mutex

// scripted answers from the UI's slices: Secret and Confirm consume one
// answer each; without one left they report a cancel, and a
// non-interactive UI reports vault.ErrNoUI.
type scripted struct{ u *UI }

func (s scripted) Display(msg string) error {
	uiMu.Lock()
	defer uiMu.Unlock()
	s.u.Displayed = append(s.u.Displayed, msg)
	return nil
}

func (s scripted) Secret(prompt string) (*memguard.LockedBuffer, error) {
	uiMu.Lock()
	defer uiMu.Unlock()
	if !s.u.Interactive {
		return nil, vault.ErrNoUI
	}
	if len(s.u.Secrets) == 0 {
		return nil, vault.ErrCancelled
	}
	v := s.u.Secrets[0]
	s.u.Secrets = s.u.Secrets[1:]
	return memguard.NewBufferFromBytes([]byte(v)), nil
}

func (s scripted) Confirm(prompt, yes, no string) (bool, error) {
	uiMu.Lock()
	defer uiMu.Unlock()
	if !s.u.Interactive {
		return false, vault.ErrNoUI
	}
	if len(s.u.Confirms) == 0 {
		return false, vault.ErrCancelled
	}
	v := s.u.Confirms[0]
	s.u.Confirms = s.u.Confirms[1:]
	return v, nil
}

func (s scripted) Interactive() bool {
	uiMu.Lock()
	defer uiMu.Unlock()
	return s.u.Interactive
}

func (s scripted) GUI() bool {
	uiMu.Lock()
	defer uiMu.Unlock()
	return s.u.GUIOK
}
