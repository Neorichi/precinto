//go:build darwin || linux

package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
)

// guard runs f and fails if it takes longer than 2 s (a FIFO must never
// block a reader).
func guard(t *testing.T, name string, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatalf("%s blocked", name)
		return nil
	}
}

// readers are the three configuration readers, as error-returning calls.
func readers(path string) map[string]func() error {
	return map[string]func() error{
		"Load":          func() error { _, err := config.Load(path); return err },
		"LoadPinned":    func() error { _, _, err := config.LoadPinned(path); return err },
		"ReadRootsList": func() error { _, err := config.ReadRootsList(path); return err },
	}
}

// CC-47: a FIFO, symlink, directory or oversized file at a configuration
// path is refused at once with fsx.ErrUnsafe.
func TestConfigReadersRefuseUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("version = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "dir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte(strings.Repeat("#", config.MaxFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	for kind, path := range map[string]string{"FIFO": fifo, "symlink": link, "directory": sub, "oversized": big} {
		for name, read := range readers(path) {
			if err := guard(t, name+" "+kind, read); !errors.Is(err, fsx.ErrUnsafe) {
				t.Errorf("%s of a %s: %v, want fsx.ErrUnsafe", name, kind, err)
			}
		}
	}
	// Missing files are still "none", not an error.
	missing := filepath.Join(dir, "missing")
	if c, err := config.Load(missing); err != nil || c.Version != config.Default().Version {
		t.Errorf("Load(missing) = %v", err)
	}
	if _, ok, err := config.LoadPinned(missing); ok || err != nil {
		t.Errorf("LoadPinned(missing) = %v %v", ok, err)
	}
	if roots, err := config.ReadRootsList(missing); roots != nil || err != nil {
		t.Errorf("ReadRootsList(missing) = %v %v", roots, err)
	}
}

// A file owned by another user is refused (needs root to create one).
func TestConfigReadersRefuseForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating a file owned by another user needs root")
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("version = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Skipf("chown: %v", err)
	}
	for name, read := range readers(path) {
		if err := guard(t, name, read); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("%s of a foreign file: %v, want fsx.ErrUnsafe", name, err)
		}
	}
}
