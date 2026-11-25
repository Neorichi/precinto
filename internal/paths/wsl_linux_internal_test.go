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
	// A plain kernel reads nothing beyond its release strings and
	// /run/WSL (D155): not wsl.conf, not binfmt_misc.
	write("proc/sys/kernel/osrelease", ubuntuRel)
	write("proc/version", ubuntuVer)
	write("etc/wsl.conf", "[automount]\nroot = /\n[interop]\nenabled = false\n")
	if f := readWSLFiles(root); f.wslConf != nil || f.wslConfErr {
		t.Fatalf("plain linux read wsl.conf: %+v", f)
	}
	write("proc/sys/kernel/osrelease", wsl2Release)
	write("proc/version", wsl2Version)
	write("proc/sys/fs/binfmt_misc/WSLInterop", "enabled\ninterpreter /init\nflags: PF\noffset 0\nmagic 4d5a\n")
	f := readWSLFiles(root)
	if f.wslConf == nil || f.wslConfErr || f.runWSL {
		t.Fatalf("files: %+v", f)
	}
	// WSL 2's VM-wide WSLInterop entry does not turn interop on when the
	// distribution's wsl.conf turns it off.
	if w := wslFrom(f); w != (WSL{Version: 2, Interop: false, InteropKnown: true, MountRoot: "/"}) {
		t.Fatalf("WSL 2, interop off: %+v", w)
	}
	write("etc/wsl.conf", "[automount]\nroot = /\n")
	if w := wslFrom(readWSLFiles(root)); !w.Interop || !w.InteropKnown {
		t.Fatalf("interop on by default: %+v", w)
	}
	// A wsl.conf that cannot be read leaves interop unknown.
	if os.Getuid() != 0 {
		if err := os.Chmod(filepath.Join(root, "etc", "wsl.conf"), 0); err != nil {
			t.Fatal(err)
		}
		if w := wslFrom(readWSLFiles(root)); w.InteropKnown || w.Version != 2 {
			t.Fatalf("unreadable wsl.conf: %+v", w)
		}
		if err := os.Chmod(filepath.Join(root, "etc", "wsl.conf"), 0o644); err != nil {
			t.Fatal(err)
		}
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
