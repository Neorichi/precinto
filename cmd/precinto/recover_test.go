package main

import (
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/precinto/precinto/internal/ui"
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

// CC-08: a key that is the install's recovery key (it opens a fresh header
// to the recovery recipient) but does not open the newest logged capsule
// means that capsule was sealed to another recovery recipient: exit 5 (a
// verification failure), never the wrong-key exit 3, and nothing recorded.
func TestRecoverVerifyNewestCapsuleSealedElsewhere(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	e.tty = nil
	m := e.vaults.metas[vault.GlobalID]
	m.RecoveryRecipient = id.Recipient().String()
	e.vaults.metas[vault.GlobalID] = m
	h, err := freshHeader(other.Recipient().String()) // the newest capsule: sealed to another recovery key
	if err != nil {
		t.Fatal(err)
	}
	e.eng.header = h
	e.in.WriteString(id.String() + "\n")
	if code := e.run("recover", "--verify"); code != exitVerify {
		t.Fatalf("exit %d, want %d (stderr %q)", code, exitVerify, e.stderr())
	}
	if !strings.Contains(e.stderr(), textRecoveryNotNewest) {
		t.Errorf("stderr %q lacks the newest-capsule warning", e.stderr())
	}
	if len(e.vaults.verifiedAt) != 0 {
		t.Fatalf("a failed verify was recorded: %v", e.vaults.verifiedAt)
	}
}

// UX-18: a wrong key at recover says so in recover's own words: no folder
// is being unlocked, so it never says "the folder stays locked".
func TestRecoverWrongKeyMessage(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	e.tty = nil
	m := e.vaults.metas[vault.GlobalID]
	m.RecoveryRecipient = id.Recipient().String()
	e.vaults.metas[vault.GlobalID] = m
	e.in.WriteString(other.String() + "\n")
	if code := e.run("recover", "--verify"); code != exitLocked {
		t.Fatalf("exit %d (stderr %q)", code, e.stderr())
	}
	if got, want := e.stderr(), ui.Format(ui.MsgRecoveryWrongKey, ui.Vars{})+"\n"; got != want {
		t.Fatalf("stderr %q, want %q", got, want)
	}
}
