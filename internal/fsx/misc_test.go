//go:build darwin || linux

package fsx_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/precinto/precinto/internal/fsx"
)

func TestStagingSameDevice(t *testing.T) {
	base := tempDir(t)
	preferred := filepath.Join(base, "staging")
	target := filepath.Join(base, "claude", "projects")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := fsx.NewStaging(preferred, target, "op-1")
	if err != nil {
		t.Fatal(err)
	}
	if s.Path != filepath.Join(preferred, "op-1") || s.ID != "op-1" || s.Dir == nil {
		t.Fatalf("staging %+v", s)
	}
	if err := fsx.CheckPrivateDir(s.Path); err != nil {
		t.Fatal(err)
	}
	if ok, err := fsx.SameDevice(s.Path, target); err != nil || !ok {
		t.Fatalf("SameDevice = %v %v", ok, err)
	}
	if _, err := fsx.NewStaging(preferred, target, "op-1"); !errors.Is(err, fsx.ErrExist) {
		t.Errorf("duplicate staging id = %v", err)
	}
	for _, bad := range []string{"", ".", "..", "a/b"} {
		if _, err := fsx.NewStaging(preferred, target, bad); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("NewStaging id %q = %v", bad, err)
		}
	}
	// Fill it with files, nested directories and a symlink to a canary.
	canary := tempDir(t)
	writeFile(t, filepath.Join(canary, "keep"), "canary")
	before := listTree(t, canary)
	f, _, err := s.Dir.CreateTemp("nested/deep", "f-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Symlink(canary, filepath.Join(s.Path, "link")); err != nil {
		t.Fatal(err)
	}
	re, err := fsx.OpenStaging(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if re.ID != "op-1" || re.Path != s.Path {
		t.Fatalf("reopened %+v", re)
	}
	re.Dir.Close()
	if err := s.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(s.Path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("staging not removed")
	}
	if err := s.Remove(); err != nil {
		t.Errorf("second Remove = %v", err)
	}
	if after := listTree(t, canary); !equalLists(before, after) {
		t.Fatal("Remove followed a symlink")
	}
	if _, err := fsx.OpenStaging(s.Path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OpenStaging(removed) = %v", err)
	}
}

func TestFreeSpaceFloor(t *testing.T) {
	dir := tempDir(t)
	avail, total, err := fsx.Space(dir)
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 || avail > total {
		t.Fatalf("Space = %d / %d", avail, total)
	}
	if a2, _, err := fsx.Space(filepath.Join(dir, "not", "yet")); err != nil || a2 == 0 {
		t.Fatalf("Space of a missing path = %d %v", a2, err)
	}
	if err := fsx.CheckSpace(dir, 0, fsx.Floor{}); err != nil {
		t.Fatalf("no floor: %v", err)
	}
	if err := fsx.CheckSpace(dir, int64(avail)+1<<30, fsx.Floor{}); !errors.Is(err, fsx.ErrNoSpace) {
		t.Errorf("more than available = %v", err)
	}
	if err := fsx.CheckSpace(dir, 1, fsx.Floor{MinBytes: int64(avail) + 1<<30}); !errors.Is(err, fsx.ErrNoSpace) {
		t.Errorf("floor above available = %v", err)
	}
	if err := fsx.CheckSpace(dir, 1, fsx.Floor{MinFraction: 1}); !errors.Is(err, fsx.ErrNoSpace) {
		t.Errorf("floor of the whole volume = %v", err)
	}
	if err := fsx.CheckSpace(dir, 1, fsx.Floor{MinFraction: 0.000001}); err != nil && avail > total/100 {
		t.Errorf("tiny floor = %v", err)
	}
	if fsx.DefaultFloor.MinBytes != 2<<30 || fsx.DefaultFloor.MinFraction != 0.05 {
		t.Errorf("DefaultFloor %+v", fsx.DefaultFloor)
	}
	if fsx.Classify(fsx.CheckSpace(dir, int64(avail)+1<<30, fsx.Floor{})) != fsx.ClassNoSpace {
		t.Error("ErrNoSpace not classified as nospace")
	}
}

func TestClassifyTable(t *testing.T) {
	wrap := func(e error) error { return &os.PathError{Op: "open", Path: "/x", Err: e} }
	for _, c := range []struct {
		err  error
		want fsx.Class
	}{
		{nil, fsx.ClassNone},
		{wrap(syscall.ENOSPC), fsx.ClassNoSpace},
		{wrap(syscall.EDQUOT), fsx.ClassNoSpace},
		{wrap(syscall.EFBIG), fsx.ClassNoSpace},
		{fsx.ErrNoSpace, fsx.ClassNoSpace},
		{wrap(syscall.EACCES), fsx.ClassAccess},
		{wrap(syscall.EPERM), fsx.ClassAccess},
		{&os.SyscallError{Syscall: "failpoint fsx.readdir", Err: syscall.EPERM}, fsx.ClassAccess},
		{wrap(syscall.ENOENT), fsx.ClassMissing},
		{wrap(syscall.ENOTDIR), fsx.ClassMissing},
		{wrap(syscall.EBUSY), fsx.ClassBusy},
		{wrap(syscall.ETXTBSY), fsx.ClassBusy},
		{wrap(syscall.EDEADLK), fsx.ClassBusy},
		{wrap(syscall.EAGAIN), fsx.ClassBusy},
		{fsx.ErrLocked, fsx.ClassBusy},
		{fmt.Errorf("lock: %w", fsx.ErrLocked), fsx.ClassBusy},
		{fsx.ErrUnsafe, fsx.ClassUnsafe},
		{fsx.ErrHardlink, fsx.ClassUnsafe},
		{wrap(syscall.ELOOP), fsx.ClassUnsafe},
		{wrap(syscall.EMLINK), fsx.ClassUnsafe},
		{wrap(syscall.EROFS), fsx.ClassReadOnly},
		{wrap(syscall.EIO), fsx.ClassIO},
		{wrap(syscall.EINVAL), fsx.ClassIO},
		{fsx.ErrChanged, fsx.ClassOther},
		{fsx.ErrExist, fsx.ClassOther},
		{context.Canceled, fsx.ClassOther},
		{errors.New("plain"), fsx.ClassOther},
	} {
		if got := fsx.Classify(c.err); got != c.want {
			t.Errorf("Classify(%v) = %q, want %q", c.err, got, c.want)
		}
	}
	// EPERM/EACCES are never missing, however they are wrapped.
	if fsx.Classify(fmt.Errorf("readdir: %w", wrap(syscall.EPERM))) == fsx.ClassMissing {
		t.Error("EPERM classified as missing")
	}
}

func TestMkdirPrivateAndCheckPrivateDir(t *testing.T) {
	root := tempDir(t)
	p := filepath.Join(root, "a", "b", "c")
	old := syscall.Umask(0o277) // process-wide: this test is never parallel
	err := fsx.MkdirPrivate(p)
	syscall.Umask(old)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b"), p} {
		if fi, err := os.Lstat(d); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, fi.Mode(), err)
		}
		if err := fsx.CheckPrivateDir(d); err != nil {
			t.Errorf("CheckPrivateDir(%s) = %v", d, err)
		}
	}
	if err := fsx.MkdirPrivate(p); err != nil {
		t.Errorf("idempotent: %v", err)
	}
	open := filepath.Join(root, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fsx.MkdirPrivate(open); err != nil {
		t.Errorf("MkdirPrivate on an existing 0755 directory = %v (only owner and type are checked)", err)
	}
	if err := fsx.CheckPrivateDir(open); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("CheckPrivateDir(0755) = %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if err := fsx.MkdirPrivate(link); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("MkdirPrivate(symlink) = %v", err)
	}
	if err := fsx.CheckPrivateDir(link); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("CheckPrivateDir(symlink) = %v", err)
	}
	file := filepath.Join(root, "file")
	writeFile(t, file, "x")
	if err := fsx.MkdirPrivate(file); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("MkdirPrivate(file) = %v", err)
	}
	if err := fsx.CheckPrivateDir(file); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("CheckPrivateDir(file) = %v", err)
	}
	if err := fsx.CheckPrivateDir(filepath.Join(root, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("CheckPrivateDir(missing) = %v", err)
	}
	if err := fsx.MkdirPrivate("relative"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("MkdirPrivate(relative) = %v", err)
	}
	if err := fsx.CheckPrivateDir("/"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("CheckPrivateDir(/) = %v (root-owned)", err)
	}
}

func TestRealpathContains(t *testing.T) {
	raw := t.TempDir()
	root, err := fsx.Realpath(raw)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" && !strings.HasPrefix(root, "/private/") {
		t.Errorf("Realpath(%s) = %s", raw, root)
	}
	if _, err := fsx.Realpath("rel"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("Realpath(relative) = %v", err)
	}
	if _, err := fsx.Realpath(filepath.Join(root, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Realpath(missing) = %v", err)
	}
	inside := filepath.Join(root, "work", "acme")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p    string
		want bool
	}{
		{inside, true},
		{filepath.Join(inside, "not", "yet", "x.md"), true},
		{filepath.Join(root, "work"), false},
		{filepath.Join(root, "work", "acme2"), false},
		{filepath.Join(root, "work", "acme-x", "y"), false},
	} {
		if got, err := fsx.Contains(inside, c.p); err != nil || got != c.want {
			t.Errorf("Contains(acme, %s) = %v %v, want %v", c.p, got, err, c.want)
		}
	}
	// A symlinked spelling of a path inside the root is inside.
	if err := os.Symlink(inside, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if got, err := fsx.Contains(inside, filepath.Join(root, "alias", "f")); err != nil || !got {
		t.Errorf("Contains through a symlink = %v %v", got, err)
	}
	// Case-insensitive volumes: another spelling names the same directory.
	upper := filepath.Join(root, "WORK", "ACME")
	if _, err := os.Stat(upper); err == nil {
		if got, err := fsx.Contains(inside, filepath.Join(upper, "n.md")); err != nil || !got {
			t.Errorf("Contains(case variant) = %v %v", got, err)
		}
	}
	// A root that does not exist falls back to a component-wise comparison.
	ghost := filepath.Join(root, "ghost")
	if got, _ := fsx.Contains(ghost, filepath.Join(ghost, "a")); !got {
		t.Error("lexical fallback: child not contained")
	}
	if got, _ := fsx.Contains(ghost, filepath.Join(root, "ghostly")); got {
		t.Error("lexical fallback compared by prefix")
	}
	if _, err := fsx.Contains("rel", inside); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("Contains(relative) = %v", err)
	}
}

func TestProbeHeld(t *testing.T) {
	p := filepath.Join(tempDir(t), "unit.lease")
	// Lease and lock files are created before use and never deleted
	// (SPEC §9.3): a missing one was never held.
	if held, err := fsx.ProbeHeld(p); held || err != nil {
		t.Errorf("missing file: held=%v err=%v, want (false, nil)", held, err)
	}
	if held, err := fsx.ProbeHeld(filepath.Join(p+".dir", "x.lease")); held || err != nil {
		t.Errorf("missing parent: held=%v err=%v, want (false, nil)", held, err)
	}
	l, err := fsx.TryLock(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if held, err := fsx.ProbeHeld(p); !held || err != nil {
		t.Errorf("shared lock held: %v %v", held, err)
	}
	l.Unlock()
	if held, err := fsx.ProbeHeld(p); held || err != nil {
		t.Errorf("free lock: %v %v", held, err)
	}
	// The probe itself leaves the lock free.
	l2, err := fsx.TryLock(p, false)
	if err != nil {
		t.Fatalf("lock after probe: %v", err)
	}
	l2.Unlock()
	link := p + ".link"
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if held, err := fsx.ProbeHeld(link); !held || !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("symlink: %v %v", held, err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("lock files are never deleted")
	}
}
