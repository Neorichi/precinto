//go:build !darwin && !linux

package testkit

import (
	"errors"
	"io/fs"
	"os"
)

// Other platforms are unsupported (D34); the package still compiles.
const oNoFollow = 0

func tryLock(*os.File) error {
	return errors.New("testkit: file locks are unsupported on this OS (D34)")
}

func ownedByMe(fs.FileInfo) bool { return false }
