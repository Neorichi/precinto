package generic

import (
	"io/fs"

	"github.com/Neorichi/precinto/internal/harness"
)

// New returns an adapter for one inventory.
func New(inv harness.Inventory) harness.Adapter { return newAdapter(inv) }

// Adapters loads every inventory from fsys that is not built in
// (claude-code, codex) and returns adapters; experimental inventories are
// returned only when experimental is true.
func Adapters(fsys fs.FS, experimental bool) ([]harness.Adapter, error) {
	return adapters(fsys, experimental)
}
