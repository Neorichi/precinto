package doctor_test

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/vault"
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
}
