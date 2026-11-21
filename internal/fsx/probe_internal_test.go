//go:build darwin || linux

package fsx

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestProbeHeldUnsupportedAndRecreated is the fsx half of TESTPLAN CODX-6:
// a lock file unlinked and recreated during the probe, and a file system
// without flock (ENOTSUP), are both reported as held.
func TestProbeHeldUnsupportedAndRecreated(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.lease")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer func() { flockFn = unix.Flock }()

	flockFn = func(fd, how int) error { return unix.ENOTSUP }
	if held, err := ProbeHeld(p); !held || err == nil || Classify(err) != ClassIO {
		t.Errorf("ENOTSUP: held=%v err=%v", held, err)
	}

	flockFn = func(fd, how int) error {
		if how&unix.LOCK_UN != 0 {
			// Between the probe's lock and its identity check, another
			// process replaces the lock file.
			os.Remove(p)
			os.WriteFile(p, nil, 0o600)
		}
		return unix.Flock(fd, how)
	}
	if held, err := ProbeHeld(p); !held || err != nil {
		t.Errorf("recreated during the probe: held=%v err=%v", held, err)
	}

	flockFn = func(fd, how int) error {
		if how&unix.LOCK_UN != 0 {
			os.Remove(p)
		}
		return unix.Flock(fd, how)
	}
	if held, err := ProbeHeld(p); !held || err != nil {
		t.Errorf("unlinked during the probe: held=%v err=%v", held, err)
	}
}

func TestVolumeRootIsAMountBoundary(t *testing.T) {
	dir := t.TempDir()
	root, err := volumeRoot(filepath.Join(dir, "a", "b"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := statPath(root)
	if err != nil {
		t.Fatal(err)
	}
	if mine, _ := statPath(dir); mine.Dev != st.Dev {
		t.Fatalf("volume root %s is on another device", root)
	}
	if up := filepath.Dir(root); up != root {
		if ust, err := statPath(up); err == nil && ust.Dev == st.Dev {
			t.Fatalf("%s is not the top of its volume", root)
		}
	}
}
