package inventories

import "embed"

// FS holds every *.toml inventory.
//
//go:embed *.toml
var FS embed.FS
