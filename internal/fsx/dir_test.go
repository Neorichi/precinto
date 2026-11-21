//go:build darwin || linux

package fsx_test

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/fsx"
)

func TestOpenBaseRules(t *testing.T) {
	root := tempDir(t)
	for _, bad := range []string{"relative/dir", root + "/../" + filepath.Base(root), root + "/"} {
		if _, err := fsx.OpenBase(bad); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("OpenBase(%q) = %v, want ErrUnsafe", bad, err)
		}
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := fsx.OpenBase(link); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("OpenBase(symlink) = %v, want ErrUnsafe", err)
	}
	if _, err := fsx.OpenBase(filepath.Join(root, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OpenBase(missing) = %v", err)
	}
	d, err := fsx.OpenBase(root)
	if err != nil {
		t.Fatal(err)
	}
	if d.Path() != root {
		t.Errorf("Path = %q", d.Path())
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := d.Lstat("x"); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Lstat on a closed Dir = %v", err)
	}
}

func TestRelativePathValidation(t *testing.T) {
	d, _ := openBase(t)
	for _, bad := range []string{"/abs", "../up", "a/../b", "a//b", "a/./b", "a/", "./a", "a\x00b"} {
		if _, err := d.Lstat(bad); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("Lstat(%q) = %v, want ErrUnsafe", bad, err)
		}
		if _, _, err := d.Open(bad); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("Open(%q) = %v, want ErrUnsafe", bad, err)
		}
	}
}

func TestNoFollowWalking(t *testing.T) {
	d, root := openBase(t)
	canary := tempDir(t)
	writeFile(t, filepath.Join(canary, "b", "file"), "canary")
	writeFile(t, filepath.Join(root, "a", "b", "file"), "mine")
	before := listTree(t, canary)

	f, st, err := d.Open("a/b/file")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "mine" || !st.IsRegular() || st.Size != 4 {
		t.Fatalf("Open: %q %+v", b, st)
	}

	// Replace the intermediate directory with a symlink to the canary.
	if err := os.Rename(filepath.Join(root, "a"), filepath.Join(root, "a.real")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, filepath.Join(root, "a")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Open("a/b/file"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("Open through a symlinked parent = %v, want ErrUnsafe", err)
	}
	if _, err := d.Lstat("a/b/file"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("Lstat through a symlinked parent = %v", err)
	}
	if _, err := d.OpenDir("a/b", false); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("OpenDir through a symlink = %v", err)
	}
	if _, err := d.ReadDir("a"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("ReadDir of a symlink = %v", err)
	}
	if _, _, err := d.CreateTemp("a/b", "x-*"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("CreateTemp through a symlink = %v", err)
	}
	if err := d.Remove("a/b/file"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("Remove through a symlink = %v", err)
	}
	if err := d.UnlinkIfUnchanged("a/b/file", st); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("UnlinkIfUnchanged through a symlink = %v", err)
	}
	if err := d.Walk("a", func(fsx.WalkEntry) error { return nil }); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("Walk of a symlink = %v", err)
	}
	if ls, err := d.Lstat("a"); err != nil || ls.IsDir() || ls.IsRegular() {
		t.Errorf("Lstat(a) followed the link: %+v %v", ls, err)
	}
	// A symlink as the final component is not opened either.
	if err := os.Symlink(filepath.Join(root, "a.real", "b", "file"), filepath.Join(root, "flink")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Open("flink"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("Open(final symlink) = %v", err)
	}
	if after := listTree(t, canary); !equalLists(before, after) {
		t.Fatalf("canary changed: %v → %v", before, after)
	}
}

// TestSwappedComponent: a handle opened before a component is swapped for
// a symlink keeps operating on the directory it opened, never on the
// symlink's target.
func TestSwappedComponent(t *testing.T) {
	d, root := openBase(t)
	canary := tempDir(t)
	writeFile(t, filepath.Join(canary, "keep"), "canary")
	before := listTree(t, canary)
	if err := os.MkdirAll(filepath.Join(root, "unit"), 0o700); err != nil {
		t.Fatal(err)
	}
	sub, err := d.OpenDir("unit", false)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	if err := os.Rename(filepath.Join(root, "unit"), filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, filepath.Join(root, "unit")); err != nil {
		t.Fatal(err)
	}
	f, rel, err := sub.CreateTemp("", "t-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := os.Lstat(filepath.Join(root, "moved", rel)); err != nil {
		t.Errorf("temporary not in the opened directory: %v", err)
	}
	if err := sub.Remove(rel); err != nil {
		t.Fatal(err)
	}
	if after := listTree(t, canary); !equalLists(before, after) {
		t.Fatalf("canary changed: %v → %v", before, after)
	}
}

func TestUnsafeDirectoriesBelowBase(t *testing.T) {
	d, root := openBase(t)
	writeFile(t, filepath.Join(root, "g", "file"), "x")
	if err := os.Chmod(filepath.Join(root, "g"), 0o770); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Open("g/file"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("Open below a group-writable directory = %v, want ErrUnsafe", err)
	}
	if err := os.Chmod(filepath.Join(root, "g"), 0o755); err != nil {
		t.Fatal(err)
	}
	if f, _, err := d.Open("g/file"); err != nil {
		t.Errorf("Open below a 0755 directory = %v", err)
	} else {
		f.Close()
	}
}

func TestOpenRefusesNonRegular(t *testing.T) {
	d, root := openBase(t)
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	go func() {
		_, _, err := d.Open("fifo") // must not block waiting for a writer
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("Open(fifo) = %v, want ErrUnsafe", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Open(fifo) blocked")
	}
	if _, _, err := d.Open("dir"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("Open(dir) = %v, want ErrUnsafe", err)
	}
}

func TestOpenDirCreate(t *testing.T) {
	d, root := openBase(t)
	sub, err := d.OpenDir("x/y/z", true)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	if sub.Path() != filepath.Join(root, "x", "y", "z") {
		t.Errorf("Path = %q", sub.Path())
	}
	for _, p := range []string{"x", "x/y", "x/y/z"} {
		fi, err := os.Lstat(filepath.Join(root, p))
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", p, fi.Mode(), err)
		}
	}
	if _, err := d.OpenDir("missing/dir", false); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OpenDir(missing) = %v", err)
	}
	self, err := d.OpenDir("", false)
	if err != nil {
		t.Fatal(err)
	}
	self.Close()
	if _, err := d.Lstat("x"); err != nil {
		t.Errorf("closing a self handle closed the parent: %v", err)
	}
}

func TestReadDir(t *testing.T) {
	d, root := openBase(t)
	writeFile(t, filepath.Join(root, "dir", "b"), "1")
	writeFile(t, filepath.Join(root, "dir", "a"), "22")
	if err := os.Mkdir(filepath.Join(root, "dir", "c"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(root, "dir", "d")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // twice: the handle's offset is never consumed
		ents, err := d.ReadDir("dir")
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, e := range ents {
			got = append(got, e.Name)
		}
		if strings.Join(got, ",") != "a,b,c,d" {
			t.Fatalf("names %v", got)
		}
		if ents[0].Type != fsx.TypeRegular || ents[0].Stat.Size != 2 || ents[2].Type != fsx.TypeDir || ents[3].Type != fsx.TypeSymlink {
			t.Fatalf("types %+v", ents)
		}
	}
	sub, err := d.OpenDir("dir", false)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	for i := 0; i < 2; i++ {
		if ents, err := sub.ReadDir(""); err != nil || len(ents) != 4 {
			t.Fatalf("ReadDir(\"\") pass %d: %d %v", i, len(ents), err)
		}
	}
}

func TestCreateTemp(t *testing.T) {
	d, root := openBase(t)
	f, rel, err := d.CreateTemp("new/sub", ".tmp-*.part")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rel, "new/sub/.tmp-") || !strings.HasSuffix(rel, ".part") || len(rel) <= len("new/sub/.tmp-.part") {
		t.Errorf("rel %q", rel)
	}
	if _, err := f.WriteString("data"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	fi, err := os.Lstat(filepath.Join(root, rel))
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != 4 {
		t.Fatalf("temporary %v %v", fi, err)
	}
	if fi, _ := os.Lstat(filepath.Join(root, "new")); fi.Mode().Perm() != 0o700 {
		t.Errorf("created directory mode %v", fi.Mode())
	}
	// A pattern without '*' is an exact, exclusive name.
	g, rel2, err := d.CreateTemp("", "exact.tmp")
	if err != nil || rel2 != "exact.tmp" {
		t.Fatalf("exact: %q %v", rel2, err)
	}
	g.Close()
	if _, _, err := d.CreateTemp("", "exact.tmp"); !errors.Is(err, fsx.ErrExist) || !errors.Is(err, fs.ErrExist) {
		t.Errorf("second exact create = %v, want ErrExist", err)
	}
	for _, bad := range []string{"", "a/b", "..", "."} {
		if _, _, err := d.CreateTemp("", bad); !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("CreateTemp pattern %q = %v", bad, err)
		}
	}
}

func TestRenameNoReplace(t *testing.T) {
	d, root := openBase(t)
	writeFile(t, filepath.Join(root, "src"), "new")
	writeFile(t, filepath.Join(root, "dst"), "old")
	err := d.Rename("src", "dst", fsx.NoReplace)
	if !errors.Is(err, fsx.ErrExist) || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("NoReplace over an existing file = %v", err)
	}
	if readFile(t, filepath.Join(root, "dst")) != "old" || readFile(t, filepath.Join(root, "src")) != "new" {
		t.Fatal("NoReplace modified a file")
	}
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.Rename("src", "sub/moved", fsx.NoReplace); err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(root, "sub", "moved")) != "new" {
		t.Fatal("rename lost content")
	}
	if _, err := os.Lstat(filepath.Join(root, "src")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("source still present")
	}
	if err := d.Rename("sub/moved", "dst", fsx.Replace); err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(root, "dst")) != "new" {
		t.Fatal("Replace did not replace")
	}
	if err := d.Rename("dst", "missing-dir/x", fsx.NoReplace); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("rename into a missing directory = %v", err)
	}
}

func TestRenameTo(t *testing.T) {
	d, root := openBase(t)
	writeFile(t, filepath.Join(root, "stage", "f"), "payload")
	stage, err := d.OpenDir("stage", false)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	target, err := d.OpenDir("target", true)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := stage.RenameTo("f", target, "placed", fsx.NoReplace); err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(root, "target", "placed")) != "payload" {
		t.Fatal("content")
	}
	writeFile(t, filepath.Join(root, "stage", "g"), "other")
	if err := stage.RenameTo("g", target, "placed", fsx.NoReplace); !errors.Is(err, fsx.ErrExist) {
		t.Fatalf("RenameTo over an existing file = %v", err)
	}
	if readFile(t, filepath.Join(root, "target", "placed")) != "payload" {
		t.Fatal("clobbered")
	}
}

func TestLink(t *testing.T) {
	d, root := openBase(t)
	writeFile(t, filepath.Join(root, "history.jsonl"), "lines")
	if err := d.Link("history.jsonl", ".hold"); err != nil {
		t.Fatal(err)
	}
	a, _ := d.Lstat("history.jsonl")
	b, _ := d.Lstat(".hold")
	if !a.SameFile(b) || a.Nlink != 2 {
		t.Fatalf("link: %+v %+v", a, b)
	}
	if err := d.Link("history.jsonl", ".hold"); !errors.Is(err, fsx.ErrExist) {
		t.Errorf("Link over an existing name = %v", err)
	}
	if err := os.Symlink("history.jsonl", filepath.Join(root, "sym")); err != nil {
		t.Fatal(err)
	}
	if err := d.Link("sym", "sym2"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("Link of a symlink = %v", err)
	}
}

func TestUnlinkIfUnchanged(t *testing.T) {
	d, root := openBase(t)
	p := filepath.Join(root, "s.jsonl")
	writeFile(t, p, "abc")
	st, err := d.Lstat("s.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	// Inode swap with identical size and mtime: a different file.
	tmp := filepath.Join(root, "swap")
	writeFile(t, tmp, "abc")
	mt := time.Unix(0, st.MtimeNS)
	if err := os.Chtimes(tmp, mt, mt); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatal(err)
	}
	if err := d.UnlinkIfUnchanged("s.jsonl", st); !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("inode swap = %v, want ErrChanged", err)
	}
	if readFile(t, p) != "abc" {
		t.Fatal("swapped file removed")
	}

	// Append: same inode, different size.
	st, _ = d.Lstat("s.jsonl")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("d")
	f.Close()
	if err := d.UnlinkIfUnchanged("s.jsonl", st); !errors.Is(err, fsx.ErrChanged) {
		t.Fatalf("append = %v, want ErrChanged", err)
	}

	// Hard link: never unlinked.
	st, _ = d.Lstat("s.jsonl")
	if err := os.Link(p, filepath.Join(root, "other-link")); err != nil {
		t.Fatal(err)
	}
	st2, _ := d.Lstat("s.jsonl")
	if err := d.UnlinkIfUnchanged("s.jsonl", st2); !errors.Is(err, fsx.ErrHardlink) {
		t.Fatalf("nlink=2 = %v, want ErrHardlink", err)
	}
	if err := os.Remove(filepath.Join(root, "other-link")); err != nil {
		t.Fatal(err)
	}

	// Unchanged (the ctime moved with the link count, so re-snapshot).
	st, _ = d.Lstat("s.jsonl")
	if err := d.UnlinkIfUnchanged("s.jsonl", st); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("not removed")
	}
	if err := d.UnlinkIfUnchanged("s.jsonl", st); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("second unlink = %v", err)
	}
}

func TestRemoveAndRemoveEmptyDirs(t *testing.T) {
	d, root := openBase(t)
	writeFile(t, filepath.Join(root, "p", "s", "sub", "f"), "x")
	writeFile(t, filepath.Join(root, "p", "keep"), "k")
	if err := d.Remove("p/s/sub/f"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveEmptyDirs("p/s/sub", "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "p", "s")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("empty parents left")
	}
	if _, err := os.Lstat(filepath.Join(root, "p", "keep")); err != nil {
		t.Fatal("stopAt not respected")
	}
	if err := d.RemoveEmptyDirs("p", "p"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveEmptyDirs("p", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "p")); err != nil {
		t.Fatal("removed a non-empty directory")
	}
	if err := d.RemoveEmptyDirs("p", "q"); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("rel outside stopAt = %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove("empty"); err != nil {
		t.Errorf("Remove(empty dir) = %v", err)
	}
	if err := d.Remove("p"); err == nil {
		t.Error("Remove of a non-empty directory succeeded")
	}
}

func TestChmodChtimes(t *testing.T) {
	d, root := openBase(t)
	canary := filepath.Join(tempDir(t), "canary")
	writeFile(t, canary, "c")
	if err := os.Chmod(canary, 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "f"), "x")
	for _, c := range []struct {
		in   fs.FileMode
		want fs.FileMode
	}{{0o644, 0o600}, {0o4777 | fs.ModeSetuid, 0o700}, {0o755, 0o700}, {0o400, 0o400}} {
		if err := d.Chmod("f", c.in); err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Lstat(filepath.Join(root, "f"))
		if fi.Mode() != c.want {
			t.Errorf("Chmod(%v) → %v, want %v", c.in, fi.Mode(), c.want)
		}
	}
	mt := time.Date(2020, 1, 2, 3, 4, 5, 6000, time.UTC)
	if err := d.Chtimes("f", mt); err != nil {
		t.Fatal(err)
	}
	if st, _ := d.Lstat("f"); st.MtimeNS != mt.UnixNano() {
		t.Errorf("mtime %d, want %d", st.MtimeNS, mt.UnixNano())
	}
	if err := os.Symlink(canary, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Lstat(canary)
	_ = d.Chmod("link", 0o700) // may succeed on the link itself or fail
	_ = d.Chtimes("link", mt)
	after, _ := os.Lstat(canary)
	if before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("symlink target modified: %v %v → %v %v", before.Mode(), before.ModTime(), after.Mode(), after.ModTime())
	}
	if err := d.Chmod("", 0o700); err != nil {
		t.Errorf("Chmod of the directory itself: %v", err)
	}
}

func TestSyncAndDevice(t *testing.T) {
	d, root := openBase(t)
	if err := d.Sync(); err != nil {
		t.Fatal(err)
	}
	dev, err := d.Device()
	if err != nil {
		t.Fatal(err)
	}
	st, _ := fsx.Lstat(root)
	if dev != st.Dev {
		t.Errorf("Device %d, want %d", dev, st.Dev)
	}
}
