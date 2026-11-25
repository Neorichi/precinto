//go:build darwin || linux

package fsx_test

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/testkit"
)

// TestWalkHazards (TESTPLAN SEC-7, fsx part): a symlinked directory pointing
// at a canary, a FIFO, a socket and a hard-linked file are reported as
// hazards, never followed or opened, and the walk does not hang.
func TestWalkHazards(t *testing.T) {
	// Short path: the socket must fit in sun_path.
	root, err := fsx.Realpath(testkit.ShortTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	d, err := fsx.OpenBase(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	canary := tempDir(t)
	writeFile(t, filepath.Join(canary, "secret"), "canary")
	before := listTree(t, canary)

	u := filepath.Join(root, "unit")
	writeFile(t, filepath.Join(u, "a.jsonl"), "a")
	writeFile(t, filepath.Join(u, "sub", "b.txt"), "b")
	writeFile(t, filepath.Join(u, "hard"), "h")
	if err := os.Link(filepath.Join(u, "hard"), filepath.Join(root, "hard-elsewhere")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, filepath.Join(u, "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(u, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", filepath.Join(u, "sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.MkdirAll(filepath.Join(u, "shared", "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(u, "shared"), 0o777); err != nil {
		t.Fatal(err)
	}

	got := map[string]fsx.WalkEntry{}
	var order []string
	done := make(chan error, 1)
	go func() {
		done <- d.Walk("unit", func(e fsx.WalkEntry) error {
			got[e.Rel] = e
			order = append(order, e.Rel)
			return nil
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Walk blocked")
	}
	want := []string{"unit/a.jsonl", "unit/fifo", "unit/hard", "unit/linkdir", "unit/shared", "unit/sock", "unit/sub", "unit/sub/b.txt"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("order %v\nwant  %v", order, want)
	}
	for rel, wantH := range map[string]fsx.Hazard{
		"unit/a.jsonl": fsx.HazardNone, "unit/fifo": fsx.HazardSpecial, "unit/hard": fsx.HazardHardlink,
		"unit/linkdir": fsx.HazardSymlink, "unit/shared": fsx.HazardForeign, "unit/sock": fsx.HazardSpecial,
		"unit/sub": fsx.HazardNone, "unit/sub/b.txt": fsx.HazardNone,
	} {
		if got[rel].Hazard != wantH {
			t.Errorf("%s: hazard %q, want %q", rel, got[rel].Hazard, wantH)
		}
	}
	if got["unit/linkdir"].Type != fsx.TypeSymlink || got["unit/fifo"].Type != fsx.TypeOther || got["unit/sub"].Type != fsx.TypeDir {
		t.Errorf("types: %+v", got)
	}
	if got["unit/a.jsonl"].Stat.Size != 1 || !got["unit/a.jsonl"].Stat.IsRegular() {
		t.Errorf("stat %+v", got["unit/a.jsonl"].Stat)
	}
	// The hard-linked file is never unlinked.
	if err := d.UnlinkIfUnchanged("unit/hard", got["unit/hard"].Stat); !errors.Is(err, fsx.ErrHardlink) {
		t.Errorf("UnlinkIfUnchanged(hard link) = %v", err)
	}
	if after := listTree(t, canary); !equalLists(before, after) {
		t.Fatalf("canary changed")
	}
	os.Chmod(filepath.Join(u, "shared"), 0o700)
}

func TestWalkSkipDirAndSkipAll(t *testing.T) {
	d, root := openBase(t)
	for _, p := range []string{"a/1", "a/2", "b/1", "c"} {
		writeFile(t, filepath.Join(root, "w", p), "x")
	}
	var seen []string
	err := d.Walk("w", func(e fsx.WalkEntry) error {
		seen = append(seen, e.Rel)
		if e.Rel == "w/a" {
			return fs.SkipDir
		}
		return nil
	})
	if err != nil || strings.Join(seen, ",") != "w/a,w/b,w/b/1,w/c" {
		t.Fatalf("SkipDir: %v %v", seen, err)
	}
	seen = nil
	err = d.Walk("w", func(e fsx.WalkEntry) error {
		seen = append(seen, e.Rel)
		if e.Rel == "w/b/1" {
			return fs.SkipAll
		}
		return nil
	})
	if err != nil || strings.Join(seen, ",") != "w/a,w/a/1,w/a/2,w/b,w/b/1" {
		t.Fatalf("SkipAll: %v %v", seen, err)
	}
	// SkipDir on a file skips the rest of its directory.
	seen = nil
	err = d.Walk("w/a", func(e fsx.WalkEntry) error {
		seen = append(seen, e.Rel)
		return fs.SkipDir
	})
	if err != nil || strings.Join(seen, ",") != "w/a/1" {
		t.Fatalf("SkipDir on a file: %v %v", seen, err)
	}
	stop := errors.New("stop")
	if err := d.Walk("w", func(fsx.WalkEntry) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("callback error = %v", err)
	}
	seen = nil
	if err := d.Walk("", func(e fsx.WalkEntry) error { seen = append(seen, e.Rel); return nil }); err != nil || seen[0] != "w" {
		t.Fatalf("Walk of the base: %v %v", seen, err)
	}
	if err := d.Walk("missing", func(fsx.WalkEntry) error { return nil }); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Walk(missing) = %v", err)
	}
}

func TestWalkUnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	d, root := openBase(t)
	writeFile(t, filepath.Join(root, "u", "locked", "f"), "x")
	writeFile(t, filepath.Join(root, "u", "z"), "x")
	if err := os.Chmod(filepath.Join(root, "u", "locked"), 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Join(root, "u", "locked"), 0o700)
	got := map[string]fsx.Hazard{}
	if err := d.Walk("u", func(e fsx.WalkEntry) error { got[e.Rel] = e.Hazard; return nil }); err != nil {
		t.Fatal(err)
	}
	if got["u/locked"] != fsx.HazardAccess || got["u/z"] != fsx.HazardNone {
		t.Fatalf("hazards %v", got)
	}
	if _, ok := got["u/locked/f"]; ok {
		t.Fatal("descended into an unreadable directory")
	}
}
