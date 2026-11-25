package agent

import (
	"os"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/vault"
)

// recordedRoots returns the folders the root vaults record (vault.toml
// root_path), with the default folder settings: every protected folder
// has one (D121). While the policy is tampered they join what the daemon
// enforces (recomputeLocked, D145), so a folder that a forged pin and
// config.toml both leave out stays protected — locked, gated, sealed by
// its lock worker and listed in roots.list — and its removal shows in the
// review until the user confirms settings at a terminal unlock. Paths are
// never trusted as a configuration: config.WithRoots drops any that could
// not be saved. Read once at start (loadPolicy), outside d.mu.
func (d *daemon) recordedRoots() []config.Root {
	ents, err := os.ReadDir(d.l.VaultsDir)
	if err != nil {
		return nil
	}
	var out []config.Root
	for _, e := range ents {
		id := e.Name()
		if id == vault.GlobalID || !validName(id) || !d.vaultExists(id) {
			continue
		}
		if m, err := d.deps.vaults.meta(id); err == nil && m.RootPath != "" {
			out = append(out, config.Root{ID: id, Path: m.RootPath})
		}
	}
	return out
}
