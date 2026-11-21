//go:build !darwin && !linux

package codextest

import (
	"errors"
	"os"
)

// Other platforms are unsupported (D34); the package still compiles so that
// `go vet` works everywhere, and HoldWriterLock fails the test there.
var errNoFlock = errors.New("codextest: flock(2) is not available on this OS (D34)")

func tryFlock(f *os.File) (busy bool, err error) { return false, errNoFlock }
