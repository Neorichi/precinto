package doctor_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/doctor"
	"github.com/Neorichi/precinto/internal/vault"
)

// plugin-pin (D75): a pinned plugin that changed fails and names factor
// repin; a matching one is OK; no plugin factor reports nothing.
func TestPluginPin(t *testing.T) {
	f := newFixture(t)
	none(t, f.run(), doctor.CheckPluginPin)
	content := "#!/bin/sh\nexit 0\n"
	plug := writeFile(t, filepath.Join(f.h.Dir, "bin", "age-plugin-yubikey"), content, 0o700)
	sum := sha256.Sum256([]byte(content))
	pin := hex.EncodeToString(sum[:])
	f.d.OpenVault = func(id string) (*vault.Vault, error) {
		return &vault.Vault{Meta: vault.Meta{ID: id, Factors: []vault.Factor{
			{Name: "yubikey", Kind: vault.FactorPlugin, PluginPath: plug, PluginSHA256: pin},
		}}}, nil
	}
	want(t, f.run(), doctor.CheckPluginPin, doctor.OK)
	writeFile(t, plug, content+"# upgraded\n", 0o700)
	got := want(t, f.run(), doctor.CheckPluginPin, doctor.Fail, "yubikey", "changed since it was pinned")
	if got.Fix != "precinto factor repin yubikey" {
		t.Errorf("fix %q", got.Fix)
	}

	// One vault re-pinned, a later one not: each distinct pin is checked.
	newSum := sha256.Sum256([]byte(content + "# upgraded\n"))
	f.d.OpenVault = func(id string) (*vault.Vault, error) {
		sha := hex.EncodeToString(newSum[:])
		if id == vault.GlobalID {
			sha = pin // still the old pin
		}
		return &vault.Vault{Meta: vault.Meta{ID: id, Factors: []vault.Factor{
			{Name: "yubikey", Kind: vault.FactorPlugin, PluginPath: plug, PluginSHA256: sha},
		}}}, nil
	}
	want(t, f.run(), doctor.CheckPluginPin, doctor.Fail, "yubikey", "changed since it was pinned")

	// A symlink at the pinned path is never run (the vault refuses it).
	f.d.OpenVault = func(id string) (*vault.Vault, error) {
		return &vault.Vault{Meta: vault.Meta{ID: id, Factors: []vault.Factor{
			{Name: "yubikey", Kind: vault.FactorPlugin, PluginPath: plug, PluginSHA256: hex.EncodeToString(newSum[:])},
		}}}, nil
	}
	want(t, f.run(), doctor.CheckPluginPin, doctor.OK)
	real := writeFile(t, filepath.Join(f.h.Dir, "real", "age-plugin-yubikey"), content+"# upgraded\n", 0o700)
	if err := os.Remove(plug); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, plug); err != nil {
		t.Fatal(err)
	}
	got = want(t, f.run(), doctor.CheckPluginPin, doctor.Fail, "is no longer a regular file")
	if !strings.HasSuffix(got.Fix, "precinto factor repin yubikey") {
		t.Errorf("fix %q", got.Fix)
	}

	// Missing, and without a recorded hash.
	if err := os.Remove(plug); err != nil {
		t.Fatal(err)
	}
	got = want(t, f.run(), doctor.CheckPluginPin, doctor.Fail, "is missing")
	if !strings.HasSuffix(got.Fix, "precinto factor repin yubikey") {
		t.Errorf("fix %q", got.Fix)
	}
	f.d.OpenVault = func(id string) (*vault.Vault, error) {
		return &vault.Vault{Meta: vault.Meta{ID: id, Factors: []vault.Factor{
			{Name: "se", Kind: vault.FactorSE, PluginPath: real},
		}}}, nil
	}
	got = want(t, f.run(), doctor.CheckPluginPin, doctor.Fail, "the se unlock method's plugin", "has no pinned hash")
	if got.Fix != "precinto factor repin se" {
		t.Errorf("fix %q", got.Fix)
	}
}
