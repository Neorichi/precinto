//go:build darwin || linux

package fsx_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/precinto/precinto/internal/fsx"
)

// TestSymlinkFlipRace is TESTPLAN SEC-6 for fsx: while a parent directory
// of the unit is flipped between a real directory and a symlink to a
// canary 10,000 times, seal-side operations (Open, Lstat, UnlinkIfUnchanged,
// Walk) and restore-side operations (CreateTemp, Rename NoReplace, Chmod,
// Chtimes, Remove) run concurrently. The canary is never written, chmod'ed
// or deleted.
func TestSymlinkFlipRace(t *testing.T) {
	flips := 10000
	if testing.Short() {
		flips = 1000
	}
	d, root := openBase(t)
	canary := tempDir(t)
	// The canary mirrors the unit's names, so any followed link would hit
	// a real file there.
	writeFile(t, filepath.Join(canary, "victim"), "canary-content")
	writeFile(t, filepath.Join(canary, "placed"), "canary-content")
	if err := os.Chmod(filepath.Join(canary, "victim"), 0o640); err != nil {
		t.Fatal(err)
	}
	before := listTree(t, canary)

	unit := filepath.Join(root, "p")
	writeFile(t, filepath.Join(unit, "victim"), "mine")
	link := filepath.Join(root, "p.link")
	if err := os.Symlink(canary, link); err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	var opsDone, unsafeSeen atomic.Int64
	worker := func(seal bool) {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			if seal {
				if f, _, err := d.Open("p/victim"); err == nil {
					f.Close()
				} else if errors.Is(err, fsx.ErrUnsafe) {
					unsafeSeen.Add(1)
				}
				if st, err := d.Lstat("p/victim"); err == nil {
					// Re-snapshot each time: only the identity check is
					// exercised, the unit's own file must survive too.
					st.Size++ // never matches: nothing may be deleted
					_ = d.UnlinkIfUnchanged("p/victim", st)
				}
				_ = d.Walk("p", func(fsx.WalkEntry) error { return nil })
			} else {
				f, rel, err := d.CreateTemp("p", ".stage-*")
				if err == nil {
					f.WriteString("restored")
					f.Close()
					_ = d.Chmod(rel, 0o600)
					if err := d.Rename(rel, "p/placed", fsx.NoReplace); err == nil {
						_ = d.Remove("p/placed")
					} else {
						_ = d.Remove(rel)
					}
				}
				_ = d.Chmod("p/victim", 0o600)
				_ = d.Chtimes("p/victim", testEpoch)
			}
			opsDone.Add(1)
		}
	}
	wg.Add(2)
	go worker(true)
	go worker(false)

	for i := 0; i < flips; i++ {
		// Atomically exchange "p" and "p.link" twice: "p" is the symlink to
		// the canary in between, and never missing.
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
	if got := readFile(t, filepath.Join(unit, "victim")); got != "mine" {
		t.Fatalf("unit file changed: %q", got)
	}
	ents, _ := os.ReadDir(unit)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".stage-") || e.Name() == "placed" {
			continue // a worker stopped between create and cleanup
		}
		if e.Name() != "victim" {
			t.Errorf("unexpected entry %s", e.Name())
		}
	}
	t.Logf("%d flips, %d operations, %d refused as unsafe", flips, opsDone.Load(), unsafeSeen.Load())
}
