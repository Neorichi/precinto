//go:build darwin || linux

package vault_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/vault"
	"github.com/Neorichi/precinto/internal/vault/vaulttest"
)

// plantFIFO replaces path with a FIFO (nobody ever opens its other end).
func plantFIFO(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// guarded runs op with a 2 s guard: a reader that opened the FIFO without
// O_NONBLOCK would wait for a writer forever.
func guarded(t *testing.T, what string, op func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- op() }()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: blocked on a FIFO", what)
		return nil
	}
}

// failsFast is guarded for an op that must refuse the FIFO.
func failsFast(t *testing.T, what string, op func() error) error {
	t.Helper()
	err := guarded(t, what, op)
	if err == nil {
		t.Errorf("%s: accepted a FIFO", what)
	}
	return err
}

func isFIFO(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("%s was replaced or removed (%v, %v)", filepath.Base(path), fi, err)
	}
}

// TestPlantedFIFOsFailFast (FX-G1-14): every file the vault package reads,
// vault.toml, identity.<factor>.age, state/verified/<id>.recipients, the
// vault's lock file and a pinned plugin binary, is opened
// O_RDONLY|O_NOFOLLOW|O_NONBLOCK as a regular file of bounded size, so a
// FIFO planted at any of them fails at once and is never replaced.
func TestPlantedFIFOsFailFast(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name  string
		path  func(fx *vaulttest.Fixture) string
		check func(t *testing.T, fx *vaulttest.Fixture) error
		want  error // nil: any error
	}{
		{"vault.toml at Open", vaultFile("root-acme", "vault.toml"), func(t *testing.T, fx *vaulttest.Fixture) error {
			_, err := fx.Store.Open("root-acme")
			return err
		}, fsx.ErrUnsafe},
		{"vault.toml at Recipients", vaultFile("root-acme", "vault.toml"), func(t *testing.T, fx *vaulttest.Fixture) error {
			_, _, err := fx.Store.Recipients("root-acme")
			return err
		}, fsx.ErrUnsafe},
		{"vault.toml at MarkAudited", vaultFile("root-acme", "vault.toml"), func(t *testing.T, fx *vaulttest.Fixture) error {
			return fx.Store.MarkAudited("root-acme", time.Now().Add(-time.Minute))
		}, fsx.ErrUnsafe},
		{"global vault.toml at Initialized", vaultFile(vault.GlobalID, "vault.toml"), func(t *testing.T, fx *vaulttest.Fixture) error {
			_, err := fx.Store.Initialized()
			return err
		}, fsx.ErrUnsafe},
		{"identity file at Unwrap", vaultFile("root-acme", "identity.passphrase.age"), func(t *testing.T, fx *vaulttest.Fixture) error {
			v, err := fx.Store.Open("root-acme")
			if err != nil {
				t.Fatal(err)
			}
			_, err = v.Unwrap(ctx, "passphrase", uiWith("never asked").AsUI())
			return err
		}, fsx.ErrUnsafe},
		{"recovery identity file at Unwrap", vaultFile("root-acme", "identity.recovery.age"), func(t *testing.T, fx *vaulttest.Fixture) error {
			v, err := fx.Store.Open("root-acme")
			if err != nil {
				t.Fatal(err)
			}
			_, err = v.Unwrap(ctx, "recovery", uiWith(fx.Recovery.String()).AsUI())
			return err
		}, fsx.ErrUnsafe},
		{"global identity file at Create", vaultFile(vault.GlobalID, "identity.passphrase.age"), func(t *testing.T, fx *vaulttest.Fixture) error {
			_, err := fx.Store.Create(ctx, "root-beta", "", uiWith("never asked").AsUI())
			return err
		}, fsx.ErrUnsafe},
		{"verified copy at Recipients", verifiedFile("root-acme"), func(t *testing.T, fx *vaulttest.Fixture) error {
			_, _, err := fx.Store.Recipients("root-acme")
			return err
		}, vault.ErrRecipientsChanged},
		{"verified copy at Verify", verifiedFile("root-acme"), func(t *testing.T, fx *vaulttest.Fixture) error {
			v, err := fx.Store.Open("root-acme")
			if err != nil {
				t.Fatal(err)
			}
			return fx.Store.Verify(v, vaulttest.LockedBuffer(t, fx.Identity.String()))
		}, fsx.ErrUnsafe},
		{"global verified copy at Create", verifiedFile(vault.GlobalID), func(t *testing.T, fx *vaulttest.Fixture) error {
			_, err := fx.Store.Create(ctx, "root-beta", "", uiWith("never asked").AsUI())
			return err
		}, vault.ErrRecipientsChanged},
		{"lock file at MarkAudited", func(fx *vaulttest.Fixture) string {
			return filepath.Join(fx.Store.VaultsDir, ".root-acme.lock")
		}, func(t *testing.T, fx *vaulttest.Fixture) error {
			return fx.Store.MarkAudited("root-acme", time.Now().Add(-time.Minute))
		}, fsx.ErrUnsafe},
	} {
		t.Run(c.name, func(t *testing.T) {
			fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
			p := c.path(fx)
			plantFIFO(t, p)
			err := failsFast(t, c.name, func() error { return c.check(t, fx) })
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", c.name, err, c.want)
			}
			isFIFO(t, p)
		})
	}

	t.Run("List skips a vault whose vault.toml is a FIFO", func(t *testing.T) {
		fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
		plantFIFO(t, vaultFile("root-acme", "vault.toml")(fx))
		var ids []string
		err := guarded(t, "List", func() error {
			var err error
			ids, err = fx.Store.List()
			return err
		})
		if err != nil || len(ids) != 1 || ids[0] != vault.GlobalID {
			t.Errorf("List = %v %v, want only the global vault", ids, err)
		}
	})

	t.Run("vault directory", func(t *testing.T) {
		fx := vaulttest.New(t, mustRealTemp(t), "root-acme")
		dir := filepath.Join(fx.Store.VaultsDir, "root-acme")
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		plantFIFO(t, dir)
		failsFast(t, "Open", func() error { _, err := fx.Store.Open("root-acme"); return err })
		failsFast(t, "MarkAudited", func() error { return fx.Store.MarkAudited("root-acme", time.Now().Add(-time.Minute)) })
		var ids []string
		if err := guarded(t, "List", func() error { var err error; ids, err = fx.Store.List(); return err }); err != nil || len(ids) != 1 {
			t.Errorf("List = %v %v, want only the global vault", ids, err)
		}
		isFIFO(t, dir)
	})

	t.Run("plugin binary at Unwrap and RepinPlugin", func(t *testing.T) {
		path := vault.InstallPluginForTest(t, "test")
		s, g := initWith(t, testPluginSpec(t, path, "ok"), uiWith().AsUI())
		plantFIFO(t, path)
		err := failsFast(t, "Unwrap", func() error {
			_, err := g.Unwrap(ctx, "test", uiWith().AsUI())
			return err
		})
		if !errors.Is(err, vault.ErrPluginPin) {
			t.Errorf("Unwrap with a FIFO plugin: %v, want ErrPluginPin", err)
		}
		if err := failsFast(t, "RepinPlugin", func() error { _, _, err := s.RepinPlugin("test"); return err }); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("RepinPlugin of a FIFO: %v, want ErrUnsafe", err)
		}
		isFIFO(t, path)
	})
}

func vaultFile(id, name string) func(*vaulttest.Fixture) string {
	return func(fx *vaulttest.Fixture) string { return filepath.Join(fx.Store.VaultsDir, id, name) }
}

func verifiedFile(id string) func(*vaulttest.Fixture) string {
	return func(fx *vaulttest.Fixture) string { return filepath.Join(fx.Store.VerifiedDir, id+".recipients") }
}
