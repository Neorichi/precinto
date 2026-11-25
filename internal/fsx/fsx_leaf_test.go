package fsx_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
)

func TestWriteFileAtomicAndLstat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "meta.json")
	if err := fsx.WriteFileAtomic(p, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fsx.WriteFileAtomic(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	st, err := fsx.Lstat(p)
	if err != nil || string(b) != "two" || !st.IsRegular() || st.Perm() != 0o600 || st.Size != 3 {
		t.Fatalf("got %q %+v %v", b, st, err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temporaries left: %v", ents)
	}
	if err := os.Symlink(p, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if ls, err := fsx.Lstat(filepath.Join(dir, "link")); err != nil || ls.IsRegular() || ls.SameFile(st) {
		t.Fatalf("Lstat followed a symlink: %+v %v", ls, err)
	}
}

func TestAppendLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ledger.jsonl")
	for _, l := range []string{`{"a":1}`, `{"b":2}`} {
		if err := fsx.AppendLine(p, []byte(l)); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	if string(b) != "{\"a\":1}\n{\"b\":2}\n" {
		t.Fatalf("content %q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if err := fsx.AppendLine(p, []byte("two\nlines")); err == nil {
		t.Error("newline accepted")
	}
	if err := os.Symlink(p, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := fsx.AppendLine(filepath.Join(dir, "link"), []byte("x")); err == nil {
		t.Error("appended through a symlink")
	}
}

func TestTryLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sweep.lock")
	l, err := fsx.TryLock(p, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fsx.TryLock(p, false); !errors.Is(err, fsx.ErrLocked) {
		t.Fatalf("second exclusive lock: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := fsx.WaitLock(ctx, p, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitLock while held: %v", err)
	}
	if err := l.Unlock(); err != nil {
		t.Fatal(err)
	}
	a, err := fsx.TryLock(p, true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := fsx.TryLock(p, true)
	if err != nil {
		t.Fatalf("shared locks must coexist: %v", err)
	}
	a.Unlock()
	b.Unlock()
	if _, err := os.Stat(p); err != nil {
		t.Fatal("lock files are never deleted")
	}
}
