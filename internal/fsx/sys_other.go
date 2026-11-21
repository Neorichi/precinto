//go:build !darwin && !linux

package fsx

import (
	"errors"
	"os"
)

// Other platforms are unsupported in v0.1 (D34); the package still compiles so
// that `go vet` works everywhere.
const osName = "unsupported"

const (
	oNoFollow = 0
	oNonblock = 0
)

var errUnsupported = errors.New("fsx: unsupported OS (D34)")

func lstatPath(path string) (Stat, error)           { return Stat{}, errUnsupported }
func fstatFile(f *os.File) (Stat, error)            { return Stat{}, errUnsupported }
func fullSync(f *os.File) error                     { return errUnsupported }
func openDirNoFollow(path string) (*os.File, error) { return nil, errUnsupported }
func flockNB(f *os.File, shared bool) error         { return errUnsupported }
func unlockFile(f *os.File) error                   { return errUnsupported }
