package vaulttest

import (
	"testing"

	"filippo.io/age"
	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/vault"
)

// Fixture is an initialized store with one root vault.
type Fixture struct {
	Store    *vault.Store
	RootID   string
	Identity *age.X25519Identity // the root vault identity (test only)
	Recovery *age.X25519Identity // the recovery identity (test only)
	Keyring  *vault.Keyring      // already holding RootID and vault.GlobalID
}

// New creates a store under dir (vaults/, state/verified/, factors/) with a
// passphrase-only factor (scrypt logN 10 for speed), the global vault and a
// root vault rootID, all unlocked in Keyring.
func New(t testing.TB, dir, rootID string) *Fixture { panic("unimplemented: vaulttest.New") }

// LockedBuffer copies s into a locked buffer (test convenience).
func LockedBuffer(t testing.TB, s string) *memguard.LockedBuffer {
	panic("unimplemented: vaulttest.LockedBuffer")
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
func (u *UI) AsUI() vault.UI { panic("unimplemented: vaulttest.UI.AsUI") }
