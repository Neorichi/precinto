//go:build failpoints && (darwin || linux)

package fsx_test

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/fsx/failpoint"
)

// Crash-injection rows for fsx (TESTPLAN §4 registry: fsx.write, fsx.fsync,
// fsx.rename, fsx.unlink, fsx.readdir, fsx.link). Every mutating operation
// evaluates its point before the system call, so an injected errno leaves
// the previous state intact, and a SIGKILL at the point leaves either the
// old or the new state, never a partial one.

func arm(t *testing.T, spec string) {
	t.Helper()
	failpoint.Reset()
	failpoint.Set(spec)
	t.Cleanup(failpoint.Reset)
}

func TestErrnoFsxWrite(t *testing.T) {
	d, root := openBase(t)
	arm(t, "fsx.write=errno:ENOSPC")
	if _, _, err := d.CreateTemp("", "t-*"); !errors.Is(err, syscall.ENOSPC) || fsx.Classify(err) != fsx.ClassNoSpace {
		t.Fatalf("CreateTemp = %v", err)
	}
	if ents, _ := os.ReadDir(root); len(ents) != 0 {
		t.Fatalf("CreateTemp left %v", ents)
	}
	arm(t, "fsx.write=errno:EROFS")
	if _, err := d.OpenDir("new", true); fsx.Classify(err) != fsx.ClassReadOnly {
		t.Fatalf("OpenDir(create) = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "new")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("directory created despite the fault")
	}
	writeFile(t, filepath.Join(root, "meta"), "old")
	arm(t, "fsx.write=errno:EIO")
	if err := fsx.WriteFileAtomic(filepath.Join(root, "meta"), []byte("new"), 0o600); fsx.Classify(err) != fsx.ClassIO {
		t.Fatalf("WriteFileAtomic = %v", err)
	}
	if readFile(t, filepath.Join(root, "meta")) != "old" {
		t.Fatal("old content lost")
	}
	if ents, _ := os.ReadDir(root); len(ents) != 1 {
		t.Fatalf("temporary left: %v", ents)
	}
	arm(t, "fsx.write=errno:EPERM")
	if err := d.Chmod("meta", 0o600); fsx.Classify(err) != fsx.ClassAccess {
		t.Fatalf("Chmod = %v", err)
	}
	arm(t, "fsx.write=errno:EPERM")
	if err := d.Chtimes("meta", testEpoch); fsx.Classify(err) != fsx.ClassAccess {
		t.Fatalf("Chtimes = %v", err)
	}
	arm(t, "fsx.write=errno:EPERM")
	if err := fsx.MkdirPrivate(filepath.Join(root, "x", "y")); fsx.Classify(err) != fsx.ClassAccess {
		t.Fatalf("MkdirPrivate = %v", err)
	}
}

func TestErrnoFsxRename(t *testing.T) {
	d, root := openBase(t)
	writeFile(t, filepath.Join(root, "src"), "payload")
	writeFile(t, filepath.Join(root, "meta"), "old")
	arm(t, "fsx.rename=errno:EIO")
	if err := d.Rename("src", "dst", fsx.NoReplace); !errors.Is(err, syscall.EIO) {
		t.Fatalf("Rename = %v", err)
	}
	if readFile(t, filepath.Join(root, "src")) != "payload" {
		t.Fatal("source lost")
	}
	if _, err := os.Lstat(filepath.Join(root, "dst")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("target appeared")
	}
	arm(t, "fsx.rename=errno:ENOSPC")
	if err := fsx.WriteFileAtomic(filepath.Join(root, "meta"), []byte("new"), 0o600); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("WriteFileAtomic = %v", err)
	}
	if readFile(t, filepath.Join(root, "meta")) != "old" {
		t.Fatal("metadata lost")
	}
	if ents, _ := os.ReadDir(root); len(ents) != 2 {
		t.Fatalf("temporary left: %v", ents)
	}
}

func TestErrnoFsxUnlink(t *testing.T) {
	d, root := openBase(t)
	writeFile(t, filepath.Join(root, "plain"), "x")
	st, _ := d.Lstat("plain")
	arm(t, "fsx.unlink=errno:EACCES")
	if err := d.UnlinkIfUnchanged("plain", st); fsx.Classify(err) != fsx.ClassAccess {
		t.Fatalf("UnlinkIfUnchanged = %v", err)
	}
	arm(t, "fsx.unlink=errno:EACCES")
	if err := d.Remove("plain"); fsx.Classify(err) != fsx.ClassAccess {
		t.Fatalf("Remove = %v", err)
	}
	if readFile(t, filepath.Join(root, "plain")) != "x" {
		t.Fatal("file removed despite the fault")
	}
	failpoint.Reset()
	staging := filepath.Join(root, "staging")
	s, err := fsx.NewStaging(staging, root, "op")
	if err != nil {
		t.Fatal(err)
	}
	f, _, err := s.Dir.CreateTemp("", "f-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	arm(t, "fsx.unlink=errno:EIO:2")
	if err := s.Remove(); !errors.Is(err, syscall.EIO) {
		t.Fatalf("Staging.Remove = %v", err)
	}
	failpoint.Reset()
	re, err := fsx.OpenStaging(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := re.Remove(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, err := os.Lstat(s.Path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("staging left after retry")
	}
}

func TestErrnoFsxFsync(t *testing.T) {
	d, root := openBase(t)
	writeFile(t, filepath.Join(root, "src"), "x")
	arm(t, "fsx.fsync=errno:EIO")
	if err := d.Sync(); !errors.Is(err, syscall.EIO) {
		t.Fatalf("Sync = %v", err)
	}
	arm(t, "fsx.fsync=errno:EIO")
	if err := fsx.SyncDir(root); !errors.Is(err, syscall.EIO) {
		t.Fatalf("SyncDir = %v", err)
	}
	arm(t, "fsx.fsync=errno:EIO")
	// The rename itself happened; only its durability is unknown, which
	// the caller must treat as an error (and re-check, as capsule.Seal does).
	if err := d.Rename("src", "dst", fsx.NoReplace); !errors.Is(err, syscall.EIO) {
		t.Fatalf("Rename = %v", err)
	}
	if readFile(t, filepath.Join(root, "dst")) != "x" {
		t.Fatal("rename did not happen before the fsync fault")
	}
}

func TestErrnoFsxReaddir(t *testing.T) {
	d, root := openBase(t)
	writeFile(t, filepath.Join(root, "dir", "f"), "x")
	arm(t, "fsx.readdir=errno:EPERM")
	if _, err := d.ReadDir("dir"); fsx.Classify(err) != fsx.ClassAccess {
		t.Fatalf("ReadDir = %v (REST-9: TCC on readdir is access, never missing)", err)
	}
	arm(t, "fsx.readdir=errno:EPERM")
	if err := d.Walk("dir", func(fsx.WalkEntry) error { return nil }); fsx.Classify(err) != fsx.ClassAccess {
		t.Fatalf("Walk = %v", err)
	}
	// A subdirectory that cannot be listed is a hazard, not an error.
	arm(t, "fsx.readdir=errno:EPERM:2")
	var hz fsx.Hazard
	err := d.Walk("", func(e fsx.WalkEntry) error {
		if e.Rel == "dir" {
			hz = e.Hazard
		}
		return nil
	})
	if err != nil || hz != fsx.HazardAccess {
		t.Fatalf("Walk with an unreadable subdirectory: %v %q", err, hz)
	}
}

func TestErrnoFsxLink(t *testing.T) {
	d, root := openBase(t)
	writeFile(t, filepath.Join(root, "h"), "x")
	arm(t, "fsx.link=errno:EIO")
	if err := d.Link("h", ".hold"); !errors.Is(err, syscall.EIO) {
		t.Fatalf("Link = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".hold")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("link created despite the fault")
	}
}

// Crash children: each scenario runs in a re-executed test binary that
// SIGKILLs itself at the armed point; the parent checks what survived.
const crashEnvScenario, crashEnvDir = "PRECINTO_FSX_CRASH_CHILD", "PRECINTO_FSX_CRASH_DIR"

func TestCrashChild(t *testing.T) {
	scenario := os.Getenv(crashEnvScenario)
	if scenario == "" {
		t.Skip("crash child only")
	}
	dir := os.Getenv(crashEnvDir)
	d, err := fsx.OpenBase(dir)
	if err != nil {
		t.Fatal(err)
	}
	switch scenario {
	case "write-atomic":
		failpoint.Set("fsx.rename")
		_ = fsx.WriteFileAtomic(filepath.Join(dir, "meta"), []byte("new"), 0o600)
	case "rename":
		failpoint.Set("fsx.rename")
		_ = d.Rename("src", "dst", fsx.NoReplace)
	case "unlink":
		failpoint.Set("fsx.unlink")
		st, _ := d.Lstat("plain")
		_ = d.UnlinkIfUnchanged("plain", st)
	case "fsync-after-rename":
		failpoint.Set("fsx.fsync")
		_ = d.Rename("src", "dst", fsx.NoReplace)
	}
	t.Fatal("crash point not reached")
}

func runCrashChild(t *testing.T, scenario, dir string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.count=1")
	cmd.Env = []string{crashEnvScenario + "=" + scenario, crashEnvDir + "=" + dir}
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("child %s: %v", scenario, err)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("child %s ended with %v, want SIGKILL", scenario, ee)
	}
}

func TestCrashLeavesOldOrNewState(t *testing.T) {
	t.Run("WriteFileAtomic", func(t *testing.T) {
		root := tempDir(t)
		writeFile(t, filepath.Join(root, "meta"), "old")
		runCrashChild(t, "write-atomic", root)
		if readFile(t, filepath.Join(root, "meta")) != "old" {
			t.Fatal("metadata torn")
		}
	})
	t.Run("RenameNoReplace", func(t *testing.T) {
		root := tempDir(t)
		writeFile(t, filepath.Join(root, "src"), "payload")
		runCrashChild(t, "rename", root)
		if readFile(t, filepath.Join(root, "src")) != "payload" {
			t.Fatal("source lost")
		}
		if _, err := os.Lstat(filepath.Join(root, "dst")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("target appeared before the rename")
		}
	})
	t.Run("UnlinkIfUnchanged", func(t *testing.T) {
		root := tempDir(t)
		writeFile(t, filepath.Join(root, "plain"), "x")
		runCrashChild(t, "unlink", root)
		if readFile(t, filepath.Join(root, "plain")) != "x" {
			t.Fatal("plaintext lost before the unlink point")
		}
	})
	t.Run("FsyncAfterRename", func(t *testing.T) {
		root := tempDir(t)
		writeFile(t, filepath.Join(root, "src"), "payload")
		runCrashChild(t, "fsync-after-rename", root)
		_, errSrc := os.Lstat(filepath.Join(root, "src"))
		_, errDst := os.Lstat(filepath.Join(root, "dst"))
		if (errSrc == nil) == (errDst == nil) {
			t.Fatalf("exactly one name must exist: src=%v dst=%v", errSrc, errDst)
		}
	})
}
