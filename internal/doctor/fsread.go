package doctor

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/inventories"
)

// Every file access of doctor goes through these helpers: reads only, at a
// bounded size, never blocking on a FIFO or a device planted at a path
// (O_NONBLOCK, then a regular-file check on the open descriptor).

var (
	errNotRegular = errors.New("doctor: not a regular file")
	errTooLarge   = errors.New("doctor: file too large to check")
)

// Size bounds of the files doctor parses.
const (
	maxSettingsBytes = 4 << 20  // Claude settings files
	maxStateBytes    = 64 << 20 // ~/.claude.json and its backups
	maxSmallFile     = 1 << 20  // package.json, plists and other small files
	saltSize         = 32       // state/name.salt (D45)
	maxDirEntries    = 100_000  // entries listed per directory walk
)

// openRegular opens path for reading (following symlinks: harness files are
// often links into a dotfiles repository) and requires a regular file.
// O_NONBLOCK keeps a FIFO from blocking the open, O_NOCTTY keeps a terminal
// device from becoming the controlling terminal.
func openRegular(path string) (*os.File, fs.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%w: %s", errNotRegular, path)
	}
	return f, fi, nil
}

// sha256File hashes the regular file at path (plugin pins, D75); it never
// follows a FIFO open and reads nothing else.
func (e *env) sha256File(path string) (string, error) {
	f, _, err := openRegular(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readRegular reads a whole regular file of at most max bytes.
func readRegular(path string, max int64) ([]byte, error) {
	f, fi, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Size() > max {
		return nil, errTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errTooLarge
	}
	return b, nil
}

// readFirstLine returns the first line of a regular file (without its
// newline), reading at most max bytes; complete is false when no newline
// came within them (the line may continue).
func readFirstLine(path string, max int) (line []byte, complete bool, err error) {
	f, _, err := openRegular(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(io.LimitReader(f, int64(max)), 4096)
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		switch {
		case err == nil:
			return line[:len(line)-1], true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return line, false, nil
		default:
			return nil, false, err
		}
	}
}

// exists reports whether something (of any type, a dangling symlink
// included) is at path.
func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// isDir reports whether path is a directory, following symlinks.
func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// readSalt reads state/name.salt without creating it (capsule.ReadSalt;
// capsule.LoadSalt would create it): nil when it does not exist yet.
func readSalt(path string) ([]byte, error) {
	salt, ok, err := capsule.ReadSalt(path)
	if err != nil || !ok {
		return nil, err
	}
	return salt, nil
}

// listDir returns the entries of dir sorted by name (at most
// maxDirEntries); a missing directory has none.
func listDir(dir string) ([]fs.DirEntry, error) {
	f, err := os.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	es, err := f.ReadDir(maxDirEntries)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	sort.Slice(es, func(i, j int) bool { return es[i].Name() < es[j].Name() })
	return es, nil
}

// errClass renders an error as a short class for a message: never the OS
// text, which carries paths and, for some readers, content.
func errClass(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, fs.ErrNotExist):
		return "missing"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, errTooLarge):
		return "too large"
	case errors.Is(err, errNotRegular):
		return "not a regular file"
	case errors.Is(err, errInvalidJSON):
		return "invalid JSON"
	case errors.Is(err, fsx.ErrUnsafe):
		return "unsafe path"
	}
	return "unreadable"
}

// embeddedInventories lists the inventory files compiled into the binary.
func embeddedInventories() []string {
	es, err := fs.ReadDir(inventories.FS, ".")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range es {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".toml" {
			out = append(out, e.Name())
		}
	}
	return out
}
