package doctor_test

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/doctor"
	"github.com/Neorichi/precinto/internal/sweep/capslog"
	"github.com/Neorichi/precinto/internal/vault"
)

func TestVaultTampered(t *testing.T) {
	f := newFixture(t)
	want(t, f.run(), doctor.CheckVaultTampered, doctor.OK)

	// The tripwire (D5): vault.toml differs from its verified copy.
	f.d.VaultRecipients = func(id string) (string, error) {
		if id == "root-acme" {
			return "", fmt.Errorf("check: %w", vault.ErrRecipientsChanged)
		}
		return "fpr-good", nil
	}
	got := want(t, f.run(), doctor.CheckVaultTampered, doctor.Fail, f.tilde(f.h.Root)+"'s vault file was changed outside precinto")
	if got.Fix != "precinto vault repair --root "+f.tilde(f.h.Root) {
		t.Errorf("fix %q", got.Fix)
	}

	// The global vault names its own repair command.
	f.d.VaultRecipients = func(id string) (string, error) {
		if id == vault.GlobalID {
			return "", vault.ErrRecipientsChanged
		}
		return "fpr-good", nil
	}
	got = want(t, f.run(), doctor.CheckVaultTampered, doctor.Fail, "global vault")
	if got.Fix != "precinto vault repair --global" {
		t.Errorf("global fix %q", got.Fix)
	}

	// A folder without a vault cannot be sealed.
	f.d.VaultRecipients = func(string) (string, error) { return "fpr-good", nil }
	f.d.OpenVault = func(id string) (*vault.Vault, error) {
		if id == "root-acme" {
			return nil, vault.ErrNotFound
		}
		return &vault.Vault{Meta: vault.Meta{ID: id, RecoveryVerifiedAt: now}}, nil
	}
	want(t, f.run(), doctor.CheckVaultTampered, doctor.Fail, f.tilde(f.h.Root)+" has no vault")
	f.d.OpenVault = func(string) (*vault.Vault, error) { return nil, fs.ErrPermission }
	want(t, f.run(), doctor.CheckVaultTampered, doctor.Warn, "permission denied")

	// Not set up at all.
	g := newFixture(t)
	g.d.VaultInitialized = func() (bool, error) { return false, nil }
	got = want(t, g.run(), doctor.CheckVaultTampered, doctor.Fail, "not set up")
	if got.Fix != "precinto init" {
		t.Errorf("fix %q", got.Fix)
	}
	g.o.Cfg.Roots = nil
	want(t, g.run(), doctor.CheckVaultTampered, doctor.Info, "not set up yet")
	none(t, g.run(), doctor.CheckRecoveryTested)
}

func TestExposedCapsules(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.h.Layout.CapsuleLog, "", 0o600)
	entries := []capslog.Entry{
		{Path: "claude-code/u1/g000001.pcap", VaultID: "root-acme", RecipientsFpr: "fpr-good"},
		{Path: "claude-code/u2/g000001.pcap", VaultID: "root-acme", RecipientsFpr: "fpr-attacker"},
		{Path: "claude-code/u3/g000001.pcap", VaultID: "root-acme", RecipientsFpr: "fpr-attacker"},
		{Path: "claude-code/u4/g000001.pcap", VaultID: vault.GlobalID, RecipientsFpr: "fpr-good"},
	}
	f.d.CapsuleLog = func() ([]capslog.Entry, error) { return entries, nil }
	want(t, f.run(), doctor.CheckExposed, doctor.Fail, "2 capsules of "+f.tilde(f.h.Root)+" were sealed to a different set of keys")

	// A tampered vault is not audited against its own (untrusted) file.
	f.d.VaultRecipients = func(id string) (string, error) {
		if id == "root-acme" {
			return "", vault.ErrRecipientsChanged
		}
		return "fpr-good", nil
	}
	none(t, f.run(), doctor.CheckExposed, doctor.Fail)

	f.d.CapsuleLog = func() ([]capslog.Entry, error) { return nil, errors.New("torn") }
	want(t, f.run(), doctor.CheckExposed, doctor.Info, "could not read the capsule log")
}

func TestRecoveryTested(t *testing.T) {
	f := newFixture(t)
	want(t, f.run(), doctor.CheckRecoveryTested, doctor.OK, "last tested on")
	f.d.OpenVault = func(id string) (*vault.Vault, error) { return &vault.Vault{Meta: vault.Meta{ID: id}}, nil }
	got := want(t, f.run(), doctor.CheckRecoveryTested, doctor.Warn, "never been tested")
	if got.Fix != "precinto recover --verify" {
		t.Errorf("fix %q", got.Fix)
	}
	// Tested on one vault is tested: the recovery key is install-wide.
	f.d.OpenVault = func(id string) (*vault.Vault, error) {
		m := vault.Meta{ID: id}
		if id == vault.GlobalID {
			m.RecoveryVerifiedAt = now.Add(-48 * time.Hour)
		}
		return &vault.Vault{Meta: m}, nil
	}
	want(t, f.run(), doctor.CheckRecoveryTested, doctor.OK)
}

func TestPassphraseFactor(t *testing.T) {
	f := newFixture(t)
	want(t, f.run(), doctor.CheckPassphraseFactor, doctor.OK)
	f.d.OpenVault = func(id string) (*vault.Vault, error) {
		fs := []vault.Factor{{Name: "se", Kind: vault.FactorSE}}
		if id == "root-acme" {
			fs = append(fs, vault.Factor{Name: "passphrase", Kind: vault.FactorPassphrase, ScryptLogN: 20})
		}
		if id == vault.GlobalID {
			fs = append(fs, vault.Factor{Name: "passphrase", Kind: vault.FactorPassphrase, ScryptLogN: 15})
		}
		return &vault.Vault{Meta: vault.Meta{ID: id, RecoveryVerifiedAt: now, Factors: fs}}, nil
	}
	fs := f.run()
	want(t, fs, doctor.CheckPassphraseFactor, doctor.Warn, "a passphrase unlocks", f.tilde(f.h.Root), "guess it offline")
	want(t, fs, doctor.CheckPassphraseFactor, doctor.Warn, "work factor below the minimum")
}
