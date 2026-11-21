package sweep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/fsx/failpoint"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
)

// run is one sweep/seal/restore operation: the environment, its ports and
// the report being built. Results may be added from several goroutines.
type run struct {
	e     Env
	p     ports
	l     paths.Layout
	log   *capslog.Log
	jr    *journal.Journal
	clock platform.Clock

	mu  sync.Mutex
	rep *Report

	// forced maps a note unit to the marker `precinto open` named.
	forced map[string]string
	// markers caches each root's markers by unit key (one scan per run).
	markers map[string]map[string][]string

	// quietMu serializes the D63 quiet-window wait; quietTried makes it
	// happen at most once per run.
	quietMu    sync.Mutex
	quietTried bool
}

// wallClock is used when Env.Clock is nil.
type wallClock struct{ origin time.Time }

func (c wallClock) Now() time.Time      { return time.Now().Round(0) }
func (c wallClock) Mono() time.Duration { return time.Since(c.origin) }

var processStart = time.Now()

func newRun(e Env, p ports) *run {
	l := e.Harness.Layout
	r := &run{e: e, p: p, l: l, log: e.Log, jr: e.Journal, clock: e.Clock}
	if r.log == nil {
		r.log = capslog.Open(l.CapsuleLog)
	}
	if r.jr == nil {
		r.jr = journal.Open(l.JournalDir)
	}
	if r.clock == nil {
		r.clock = wallClock{origin: processStart}
	}
	if e.Sleep != nil {
		r.p.sleep = e.Sleep
	}
	if r.p.sleep == nil {
		r.p.sleep = sleepCtx
	}
	r.rep = &Report{Started: r.now()}
	return r
}

func (r *run) now() time.Time { return r.clock.Now().UTC() }

// add appends one unit result to the report.
func (r *run) add(u UnitResult) {
	r.mu.Lock()
	r.rep.Units = append(r.rep.Units, u)
	r.mu.Unlock()
}

// finish stamps and returns the report.
func (r *run) finish() *Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rep.Finished = r.now()
	return r.rep
}

// hit evaluates a failpoint of sweep's registry (docs/TESTPLAN.md §4); ""
// means no point at this call site.
func hit(name string) error {
	if name == "" {
		return nil
	}
	return failpoint.Hit(name)
}

// validKey reports whether k looks like a unit key (32 lowercase hex
// digits, D45); keys become file names, so nothing else is accepted.
func validKey(k string) bool {
	if len(k) != 32 {
		return false
	}
	for _, c := range k {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// storeOf is the directory under CapsulesDir that holds a unit's capsules:
// "md" for notes (SPEC §6.1), the harness id otherwise.
func storeOf(h harness.ID, k capsule.Kind) string {
	if k == capsule.KindMarkdown {
		return "md"
	}
	return string(h)
}

// logPathOf is a capsule path relative to CapsulesDir, slash-separated.
func logPathOf(store, unit string, rel ...string) string {
	return path.Join(append([]string{store, unit}, rel...)...)
}

// ensurePrivateDir creates dir (0700, with parents) if missing and
// requires a directory owned by the current user, without group/other
// permissions, that is not a symlink (precinto-owned state only).
func ensurePrivateDir(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return fmt.Errorf("sweep: directory %q is not absolute", dir)
	}
	st, err := fsx.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		st, err = fsx.Lstat(dir)
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", fsx.ErrUnsafe, filepath.Base(dir))
	}
	if int(st.UID) != os.Getuid() || st.Mode&0o077 != 0 {
		return fmt.Errorf("%w: %s is not private", fsx.ErrUnsafe, filepath.Base(dir))
	}
	return nil
}

// lockUnit takes the unit lock state/locks/unit-<key>.lock (never deleted).
func (r *run) lockUnit(key string) (*fsx.Lock, error) {
	if !validKey(key) {
		return nil, fmt.Errorf("%w: invalid unit key", harness.ErrUnitKey)
	}
	if err := ensurePrivateDir(r.l.LocksDir); err != nil {
		return nil, err
	}
	return fsx.TryLock(r.l.LockFile("unit-"+key), false)
}

// lockName takes a named lock (sweep, global-claude-code, gens) without
// waiting.
func (r *run) lockName(name string) (*fsx.Lock, error) {
	if err := ensurePrivateDir(r.l.LocksDir); err != nil {
		return nil, err
	}
	return fsx.TryLock(r.l.LockFile(name), false)
}

// waitLockName waits for a named lock.
func (r *run) waitLockName(ctx context.Context, name string) (*fsx.Lock, error) {
	if err := ensurePrivateDir(r.l.LocksDir); err != nil {
		return nil, err
	}
	return fsx.WaitLock(ctx, r.l.LockFile(name), false)
}

// openCapsDir opens (creating) capsules/<store>/<unit>.
func (r *run) openCapsDir(store, unit string, create bool) (dirHandle, dirHandle, error) {
	if !validKey(unit) {
		return nil, nil, fmt.Errorf("%w: invalid unit key", harness.ErrUnitKey)
	}
	if create {
		if err := ensurePrivateDir(r.l.CapsulesDir); err != nil {
			return nil, nil, err
		}
	}
	root, err := r.p.fs.OpenBase(r.l.CapsulesDir)
	if err != nil {
		return nil, nil, err
	}
	d, err := root.OpenDir(path.Join(store, unit), create)
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	return root, d, nil
}

// hashPrefix returns the SHA-256 of the first n bytes of rel in dir, which
// must still have identity want (nil: any) while it is read.
func hashPrefix(dir dirHandle, rel string, n int64, want *fsx.Stat) (string, error) {
	f, st, err := dir.Open(rel)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if want != nil && !st.Unchanged(*want) {
		return "", fsx.ErrChanged
	}
	if st.Size < n {
		return "", fsx.ErrChanged
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, n)); err != nil {
		return "", err
	}
	after, err := fsx.Fstat(f)
	if err != nil {
		return "", err
	}
	if !after.Unchanged(st) {
		return "", fsx.ErrChanged
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashFile returns the SHA-256 and identity of a whole file.
func hashFile(dir dirHandle, rel string) (string, fsx.Stat, error) {
	f, st, err := dir.Open(rel)
	if err != nil {
		return "", fsx.Stat{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fsx.Stat{}, err
	}
	after, err := fsx.Fstat(f)
	if err != nil {
		return "", fsx.Stat{}, err
	}
	if !after.Unchanged(st) {
		return "", fsx.Stat{}, fsx.ErrChanged
	}
	return hex.EncodeToString(h.Sum(nil)), st, nil
}

// readAllBounded reads rel from dir (at most max bytes).
func readAllBounded(dir dirHandle, rel string, max int64) ([]byte, fsx.Stat, error) {
	f, st, err := dir.Open(rel)
	if err != nil {
		return nil, fsx.Stat{}, err
	}
	defer f.Close()
	if st.Size > max {
		return nil, st, capsule.ErrTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, st, err
	}
	if int64(len(b)) > max {
		return nil, st, capsule.ErrTooLarge
	}
	return b, st, nil
}

// removeTmp removes a journaled capsule temporary (Record.Tmp: the
// capsule.TmpName of the final name, relative to the unit directory). Only
// a regular file named like one is removed; anything else is left alone.
func removeTmp(unitDir dirHandle, rel string) error {
	if base := path.Base(rel); !strings.HasPrefix(base, ".") || !strings.HasSuffix(base, ".tmp") {
		return nil
	}
	st, err := unitDir.Lstat(rel)
	if isMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.IsRegular() {
		return nil
	}
	if err := unitDir.Remove(rel); err != nil && !isMissing(err) {
		return err
	}
	return nil
}

// dedupe returns s without repeated values, keeping the first occurrence.
func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// sameSet reports whether a and b hold the same strings.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := sortedCopy(a), sortedCopy(b)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// depth is the number of components of a slash path.
func depth(rel string) int { return strings.Count(rel, "/") + 1 }

// sortByDepthDesc orders slash paths deepest first, then lexically.
func sortByDepthDesc(rels []string) {
	sort.SliceStable(rels, func(a, b int) bool {
		if da, db := depth(rels[a]), depth(rels[b]); da != db {
			return da > db
		}
		return rels[a] < rels[b]
	})
}
