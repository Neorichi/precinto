package main

import (
	"testing"

	"filippo.io/age"

	"github.com/precinto/precinto/internal/vault"
)

// SPEC §4.7, CC-07: a successful recover --verify is recorded in every
// vault (vault.Store.MarkRecoveryVerified), so status stops saying "never
// tested"; a key that does not match records nothing.
func TestRecoverVerifyRecordsTheTest(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	setup := func(t *testing.T, key string) *env {
		e := newEnv(t)
		e.tty = nil // the key comes from stdin
		m := e.vaults.metas[vault.GlobalID]
		m.RecoveryRecipient = id.Recipient().String()
		e.vaults.metas[vault.GlobalID] = m
		e.in.WriteString(key + "\n")
		return e
	}

	e := setup(t, id.String())
	if code := e.run("recover", "--verify"); code != exitOK {
		t.Fatalf("exit %d (stderr %q)", code, e.stderr())
	}
	if len(e.vaults.verifiedAt) != 1 || !e.vaults.verifiedAt[0].Equal(e.h.Clock.Now()) {
		t.Fatalf("MarkRecoveryVerified calls %v, want one at %v", e.vaults.verifiedAt, e.h.Clock.Now())
	}
	for vid, m := range e.vaults.metas {
		if !m.RecoveryVerifiedAt.Equal(e.h.Clock.Now()) {
			t.Errorf("vault %s not recorded: %v", vid, m.RecoveryVerifiedAt)
		}
	}

	e = setup(t, other.String())
	if code := e.run("recover", "--verify"); code == exitOK {
		t.Fatal("a wrong key verified")
	}
	if len(e.vaults.verifiedAt) != 0 {
		t.Fatalf("a failed verify was recorded: %v", e.vaults.verifiedAt)
	}
}
