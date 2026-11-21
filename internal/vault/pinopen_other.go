//go:build !darwin && !linux

package vault

import "os"

// pinOpenFlags: other platforms are unsupported (D34); the package still
// compiles so that `go vet` works everywhere.
const pinOpenFlags = os.O_RDONLY
