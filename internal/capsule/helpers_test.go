package capsule_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/testkit"
)

// keys are a throwaway vault and recovery identity.
type keys struct {
	vault, recovery *age.X25519Identity
}

func newKeys(t testing.TB) keys {
	t.Helper()
	v, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return keys{v, r}
}

func (k keys) recipients() []age.Recipient {
	return []age.Recipient{k.vault.Recipient(), k.recovery.Recipient()}
}

// unit is a synthetic unit: a base directory with files, and a capsule
// output directory.
type unit struct {
	t     testing.TB
	root  string // base directory holding the plaintext
	base  *fsx.Dir
	out   *fsx.Dir
	outP  string
	files map[string][]byte
}

func newUnit(t testing.TB) *unit {
	t.Helper()
	dir, err := fsx.Realpath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	u := &unit{t: t, root: filepath.Join(dir, "claude"), outP: filepath.Join(dir, "capsules", "claude-code", "0123456789abcdef0123456789abcdef"), files: map[string][]byte{}}
	for _, d := range []string{u.root, u.outP} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if u.base, err = fsx.OpenBase(u.root); err != nil {
		t.Fatal(err)
	}
	if u.out, err = fsx.OpenBase(u.outP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.base.Close(); u.out.Close() })
	return u
}

func (u *unit) write(rel string, data []byte) {
	u.t.Helper()
	p := filepath.Join(u.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		u.t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		u.t.Fatal(err)
	}
	u.files[rel] = append([]byte(nil), data...)
}

// input returns the capsule input for rel with a fresh snapshot.
func (u *unit) input(rel string) capsule.Input {
	u.t.Helper()
	st, err := u.base.Lstat(rel)
	if err != nil {
		u.t.Fatal(err)
	}
	return capsule.Input{Base: capsule.BaseClaudeConfig, Dir: u.base, Rel: rel, Path: filepath.Join(u.root, rel), Snap: st}
}

func (u *unit) inputs(rels ...string) []capsule.Input {
	var in []capsule.Input
	for _, r := range rels {
		in = append(in, u.input(r))
	}
	return in
}

// assertPlaintext checks that every plaintext file still has its content.
func (u *unit) assertPlaintext() {
	u.t.Helper()
	for rel, want := range u.files {
		got, err := os.ReadFile(filepath.Join(u.root, rel))
		if err != nil || !bytes.Equal(got, want) {
			u.t.Fatalf("plaintext %s changed or lost: %v", rel, err)
		}
	}
}

// outNames lists the capsule directory.
func (u *unit) outNames() []string {
	u.t.Helper()
	ents, err := os.ReadDir(u.outP)
	if err != nil {
		u.t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func manifest(marker string) capsule.Manifest {
	return capsule.Manifest{
		Kind: capsule.KindClaudeSession, Harness: "claude-code", UnitKey: "0123456789abcdef0123456789abcdef",
		UnitID: "00000000-0000-4000-8000-000000000001", VaultID: "root-acme", RootIDs: []string{"root-acme"},
		Gen: 1, Lineage: capsule.LineageFresh, CreatedAt: testkit.Epoch, Sealer: "precinto test", Title: marker,
	}
}

func randomBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// fileKey unwraps the capsule header with id.
func fileKey(t testing.TB, dir *fsx.Dir, name string, id age.Identity) []byte {
	t.Helper()
	hdr, _, err := capsule.ReadHeader(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	k, err := age.DecryptHeader(hdr, id)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newStaging(t testing.TB, target string) *fsx.Staging {
	t.Helper()
	pref := filepath.Join(filepath.Dir(target), "staging")
	s, err := fsx.NewStaging(pref, target, "op-"+filepath.Base(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Remove() })
	return s
}

func allowAll(capsule.Entry) error { return nil }

func seal(t testing.TB, u *unit, k keys, name string, in []capsule.Input, dirs []capsule.Entry, on func(capsule.Phase, *capsule.Sealed) error) (*capsule.Sealed, error) {
	t.Helper()
	return capsule.Seal(context.Background(), capsule.SealRequest{
		Manifest: manifest(testkit.Marker(t)), Inputs: in, Dirs: dirs, Recipients: k.recipients(),
		Out: u.out, Name: name, OnPhase: on,
	})
}
