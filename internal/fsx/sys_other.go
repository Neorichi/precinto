//go:build !darwin && !linux

package fsx

import (
	"errors"
	"io/fs"
	"os"
	"time"
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

func openBase(path string) (*Dir, error)                         { return nil, errUnsupported }
func (d *Dir) close() error                                      { return errUnsupported }
func (d *Dir) openDir(rel string, create bool) (*Dir, error)     { return nil, errUnsupported }
func (d *Dir) openFile(rel string) (*os.File, Stat, error)       { return nil, Stat{}, errUnsupported }
func (d *Dir) lstat(rel string) (Stat, error)                    { return Stat{}, errUnsupported }
func (d *Dir) readDir(rel string) ([]Entry, error)               { return nil, errUnsupported }
func (d *Dir) walk(rel string, fn func(WalkEntry) error) error   { return errUnsupported }
func (d *Dir) link(oldRel, newRel string) error                  { return errUnsupported }
func (d *Dir) unlinkIfUnchanged(rel string, expect Stat) error   { return errUnsupported }
func (d *Dir) remove(rel string) error                           { return errUnsupported }
func (d *Dir) removeEmptyDirs(rel, stopAt string) error          { return errUnsupported }
func (d *Dir) chtimes(rel string, mtime time.Time) error         { return errUnsupported }
func (d *Dir) chmod(rel string, perm fs.FileMode) error          { return errUnsupported }
func (d *Dir) sync() error                                       { return errUnsupported }
func (d *Dir) device() (uint64, error)                           { return 0, errUnsupported }
func statPath(path string) (Stat, error)                         { return Stat{}, errUnsupported }
func mkdirOne(path string) error                                 { return errUnsupported }
func fixDirMode(path string) error                               { return errUnsupported }
func removeStaging(s *Staging) error                             { return errUnsupported }
func probeHeld(path string) (bool, error)                        { return true, errUnsupported }
func space(path string) (avail, total uint64, err error)         { return 0, 0, errUnsupported }
func classifyErrno(err error) Class                              { return ClassOther }
func (d *Dir) appendLine(rel string, line []byte, max int) error { return errUnsupported }
func (d *Dir) createTemp(dirRel, pattern string) (*os.File, string, error) {
	return nil, "", errUnsupported
}
func (d *Dir) renameTo(oldRel string, dst *Dir, newRel string, mode RenameMode) error {
	return errUnsupported
}
