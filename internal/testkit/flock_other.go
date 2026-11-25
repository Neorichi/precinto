//go:build !darwin && !linux

package testkit

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// Other platforms are unsupported (D34); the package still compiles.
const oNoFollow = 0

func tryLock(*os.File) error {
	return errors.New("testkit: file locks are unsupported on this OS (D34)")
}

func ownedByMe(fs.FileInfo) bool { return false }

func mkfifo(string, uint32) error {
	return errors.New("testkit: FIFOs are unsupported on this OS (D34)")
}

// newSession: no setsid here; the child keeps the test's console.
func newSession() *syscall.SysProcAttr { return nil }
