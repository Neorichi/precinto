package generic

import (
	"io/fs"

	"github.com/precinto/precinto/internal/harness"
)

// New returns an adapter for one inventory.
func New(inv harness.Inventory) harness.Adapter { panic("unimplemented: generic.New") }

// Adapters loads every inventory from fsys that is not built in
// (claude-code, codex) and returns adapters; experimental inventories are
// returned only when experimental is true.
func Adapters(fsys fs.FS, experimental bool) ([]harness.Adapter, error) {
	panic("unimplemented: generic.Adapters")
}
