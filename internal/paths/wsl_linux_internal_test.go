//go:build linux

package paths

import (
	"os"
	"path/filepath"
	"testing"
)

// readWSLFiles reads WSL's markers below a root: a fake tree here (the
// real one is "/").
func TestReadWSLFiles(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if w := wslFrom(readWSLFiles(root)); w != (WSL{}) {
		t.Fatalf("an empty tree is WSL: %+v", w)
	}
	write("proc/sys/kernel/osrelease", wsl2Release)
	write("proc/version", wsl2Version)
	write("proc/sys/fs/binfmt_misc/status", "enabled\n")
	write("proc/sys/fs/binfmt_misc/WSLInterop", interopOn)
	write("etc/wsl.conf", "[automount]\nroot = /\n[interop]\nenabled = true\n")
	f := readWSLFiles(root)
	if len(f.binfmt) != 1 || f.runWSL {
		t.Fatalf("files: %+v", f)
	}
	if w := wslFrom(f); w != (WSL{Version: 2, Interop: true, InteropKnown: true, MountRoot: "/"}) {
		t.Fatalf("WSL 2: %+v", w)
	}
	write("proc/sys/fs/binfmt_misc/WSLInterop", interopOff)
	if w := wslFrom(readWSLFiles(root)); w.Interop || !w.InteropKnown {
		t.Fatalf("interop off: %+v", w)
	}
	write("proc/sys/kernel/osrelease", wsl1Release)
	write("proc/version", wsl1Version)
	if w := wslFrom(readWSLFiles(root)); w.Version != 1 {
		t.Fatalf("WSL 1: %+v", w)
	}
	// /run/WSL counts only when root owns it: one this test creates is
	// the user's, and does not make a plain kernel WSL.
	write("proc/sys/kernel/osrelease", ubuntuRel)
	write("proc/version", ubuntuVer)
	if err := os.MkdirAll(filepath.Join(root, "run", "WSL"), 0o755); err != nil {
		t.Fatal(err)
	}
	if f := readWSLFiles(root); f.runWSL != (os.Getuid() == 0) {
		t.Fatalf("/run/WSL owned by uid %d counted: %v", os.Getuid(), f.runWSL)
	}
}

// DetectWSL is what readWSLFiles finds below "/", read once.
func TestDetectWSLReadsTheSystem(t *testing.T) {
	if got, want := DetectWSL(), wslFrom(readWSLFiles("/")); got.Version != want.Version || got.MountRoot != want.MountRoot {
		t.Fatalf("DetectWSL = %+v, the files say %+v", got, want)
	}
	if DetectWSL().Version == 0 {
		// Outside WSL CheckDrive reads nothing and accepts everything.
		if err := CheckDrive("relative"); err != nil {
			t.Fatalf("CheckDrive outside WSL: %v", err)
		}
		return
	}
	// Under WSL (the weekly CI job) the test's own temp dir is on the
	// distribution's disk.
	if err := CheckDrive(t.TempDir()); err != nil {
		t.Fatalf("CheckDrive(TempDir) under WSL: %v", err)
	}
}
