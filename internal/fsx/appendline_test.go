//go:build darwin || linux

package fsx_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
)

// TestDirAppendLine covers the handle-relative append (CC-05): creation
// 0600, the newline rule, refusal of symlinks and non-regular files, and
// no parent creation.
func TestDirAppendLine(t *testing.T) {
	d, root := openBase(t)
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{`{"a":1}`, "{\"b\":2}\n", ""} {
		if err := d.AppendLine("sub/history.jsonl", []byte(l)); err != nil {
			t.Fatalf("AppendLine(%q): %v", l, err)
		}
	}
	if got := readFile(t, filepath.Join(root, "sub/history.jsonl")); got != "{\"a\":1}\n{\"b\":2}\n\n" {
		t.Fatalf("content %q", got)
	}
	if fi, err := os.Stat(filepath.Join(root, "sub/history.jsonl")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi.Mode().Perm(), err)
	}
	for _, bad := range []string{"two\nlines", "two\nlines\n", strings.Repeat("x", fsx.MaxLine+1)} {
		if err := d.AppendLine("sub/history.jsonl", []byte(bad)); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("AppendLine(%.20q) = %v, want ErrUnsafe", bad, err)
		}
	}
	if err := d.AppendLine("missing/new.jsonl", []byte("x")); err == nil {
		t.Error("AppendLine created a parent directory")
	}
	if _, err := os.Stat(filepath.Join(root, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("parent created: %v", err)
	}
	// A symlink as the final component or as a parent is refused.
	other := tempDir(t)
	writeFile(t, filepath.Join(other, "target"), "canary\n")
	if err := os.Symlink(filepath.Join(other, "target"), filepath.Join(root, "link.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendLine("link.jsonl", []byte("x")); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("append through a final symlink = %v", err)
	}
	if err := os.Symlink(other, filepath.Join(root, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendLine("dirlink/target", []byte("x")); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("append through a parent symlink = %v", err)
	}
	if got := readFile(t, filepath.Join(other, "target")); got != "canary\n" {
		t.Fatalf("canary written: %q", got)
	}
	// A directory is not a regular file.
	if err := os.Mkdir(filepath.Join(root, "adir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendLine("adir", []byte("x")); err == nil {
		t.Error("appended to a directory")
	}
	// Bad relative paths.
	for _, rel := range []string{"", ".", "../x", "/abs", "a//b"} {
		if err := d.AppendLine(rel, []byte("x")); err == nil {
			t.Errorf("AppendLine(%q) accepted", rel)
		}
	}
}

// A FIFO planted where the file should be is refused at once, whether or
// not a reader is attached (never blocks).
func TestDirAppendLineRefusesFIFO(t *testing.T) {
	d, root := openBase(t)
	fifo := filepath.Join(root, "history.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- d.AppendLine("history.jsonl", []byte("x")) }()
	select {
	case err := <-done:
		if !errors.Is(err, fsx.ErrUnsafe) {
			t.Fatalf("FIFO without a reader: %v, want ErrUnsafe", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AppendLine blocked on a FIFO")
	}
	// With a reader attached the open succeeds but fstat refuses it.
	r, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	go func() { done <- d.AppendLine("history.jsonl", []byte("x")) }()
	select {
	case err := <-done:
		if !errors.Is(err, fsx.ErrUnsafe) {
			t.Fatalf("FIFO with a reader: %v, want ErrUnsafe", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AppendLine blocked on a FIFO with a reader")
	}
	buf := make([]byte, 8)
	if n, _ := r.Read(buf); n != 0 {
		t.Fatalf("%d bytes were written to the FIFO", n)
	}
}

// 50 concurrent appenders (separate descriptors, like separate processes)
// produce whole lines only.
func TestDirAppendLineConcurrentWholeLines(t *testing.T) {
	d, root := openBase(t)
	const writers, perWriter = 50, 20
	var wg sync.WaitGroup
	var failed atomic.Int64
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				line := fmt.Sprintf(`{"w":%d,"i":%d,"pad":"%s"}`, w, i, strings.Repeat("p", 512+w*7))
				if err := d.AppendLine("lines.jsonl", []byte(line)); err != nil {
					failed.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()
	if n := failed.Load(); n != 0 {
		t.Fatalf("%d appends failed", n)
	}
	data, err := os.ReadFile(filepath.Join(root, "lines.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	if len(lines) != writers*perWriter {
		t.Fatalf("%d lines, want %d", len(lines), writers*perWriter)
	}
	seen := map[string]bool{}
	for _, l := range lines {
		var w, i int
		var pad string
		if _, err := fmt.Sscanf(string(l), `{"w":%d,"i":%d,"pad":%q}`, &w, &i, &pad); err != nil || len(pad) != 512+w*7 {
			t.Fatalf("torn or interleaved line %.60q: %v", l, err)
		}
		key := fmt.Sprintf("%d/%d", w, i)
		if seen[key] {
			t.Fatalf("line %s appended twice", key)
		}
		seen[key] = true
	}
}

// SEC-6 style: while the parent directory is flipped between a real
// directory and a symlink to a canary, AppendLine never writes the canary.
func TestDirAppendLineSymlinkFlipRace(t *testing.T) {
	flips := 5000
	if testing.Short() {
		flips = 500
	}
	d, root := openBase(t)
	canary := tempDir(t)
	writeFile(t, filepath.Join(canary, "history.jsonl"), "canary-content\n")
	before := listTree(t, canary)
	unit := filepath.Join(root, "p")
	writeFile(t, filepath.Join(unit, "history.jsonl"), "")
	link := filepath.Join(root, "p.link")
	if err := os.Symlink(canary, link); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	var appended, refused atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			err := d.AppendLine("p/history.jsonl", []byte(`{"line":"mine"}`))
			switch {
			case err == nil:
				appended.Add(1)
			case errors.Is(err, fsx.ErrUnsafe):
				refused.Add(1)
			}
		}
	}()
	for i := 0; i < flips; i++ {
		if err := swapPaths(unit, link); err != nil {
			t.Fatal(err)
		}
		if err := swapPaths(unit, link); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if after := listTree(t, canary); !equalLists(before, after) {
		t.Fatalf("canary changed:\nbefore %v\nafter  %v", before, after)
	}
	if got := readFile(t, filepath.Join(canary, "history.jsonl")); got != "canary-content\n" {
		t.Fatalf("canary written: %q", got)
	}
	t.Logf("%d flips, %d appends, %d refused as unsafe", flips, appended.Load(), refused.Load())
}
