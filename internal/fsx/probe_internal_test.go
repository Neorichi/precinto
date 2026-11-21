//go:build darwin || linux

package fsx

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestProbeHeldUnsupportedAndRecreated is the fsx half of TESTPLAN CODX-6
// (CC-06): a missing lease file was never held (false, nil), while a lock
// file unlinked, recreated or swapped by a rename during the probe, and a
// file system without flock (ENOTSUP), are all reported as held.
func TestProbeHeldUnsupportedAndRecreated(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.lease")
	calls := 0
	flockFn = func(fd, how int) error { calls++; return unix.Flock(fd, how) }
	defer func() { flockFn = unix.Flock }()
	if held, err := ProbeHeld(p); held || err != nil || calls != 0 {
		t.Errorf("missing lease file: held=%v err=%v (%d flock calls), want (false, nil)", held, err, calls)
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}

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

	// Another file renamed over the lease file (an atomic swap of inodes).
	flockFn = func(fd, how int) error {
		if how&unix.LOCK_UN != 0 {
			q := p + ".other"
			os.WriteFile(q, nil, 0o600)
			os.Rename(q, p)
		}
		return unix.Flock(fd, how)
	}
	if held, err := ProbeHeld(p); !held || err != nil {
		t.Errorf("swapped by a rename during the probe: held=%v err=%v", held, err)
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

	// Once gone, the lease file was never held (lease files are created
	// before use and never deleted, SPEC §9.3).
	flockFn = unix.Flock
	if held, err := ProbeHeld(p); held || err != nil {
		t.Errorf("missing after the probe: held=%v err=%v, want (false, nil)", held, err)
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
