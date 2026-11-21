//go:build darwin || linux

package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestEnsureDirsUmask: a umask that clears owner bits must not leave 0500
// directories behind (nor make nested ones uncreatable). The umask is
// process-wide, so this test is never parallel.
func TestEnsureDirsUmask(t *testing.T) {
	root := shortTestDir(t)
	l, err := LayoutAt(filepath.Join(root, "x", "base"), filepath.Join(root, "y", "run"))
	if err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o277)
	err = l.EnsureDirs()
	syscall.Umask(old)
	if err != nil {
		t.Fatalf("EnsureDirs under umask 0277: %v", err)
	}
	for _, d := range []string{filepath.Join(root, "x"), l.Base, l.StateDir, l.LocksDir, filepath.Join(root, "y"), l.RunDir} {
		fi, err := os.Lstat(d)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, fi.Mode(), err)
		}
	}
}

// TestEnsureDirsCreateError: a parent that cannot be written to is an I/O
// error, not a silent success.
func TestEnsureDirsCreateError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	root := shortTestDir(t)
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	l, err := LayoutAt(filepath.Join(locked, "base"), filepath.Join(root, "run"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.EnsureDirs(); err == nil || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("EnsureDirs below a 0500 directory = %v, want a permission error", err)
	}
}

func shortTestDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "pt-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err == nil && e.IsDir() {
				_ = os.Chmod(p, 0o700)
			}
			return nil
		})
		if err := os.RemoveAll(d); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	real, err := filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	return real
}
