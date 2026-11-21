package vault

// Pinned dependencies of this package (keeps go.mod/go.sum complete from day
// 0 so parallel implementers never edit them).
import (
	_ "filippo.io/age/plugin"
	_ "filippo.io/age/tag"
	_ "github.com/BurntSushi/toml"
)
