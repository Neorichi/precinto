package live

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/platform"
)

const (
	leaseExt = ".lease"
	// leaseWait bounds how long Acquire waits for a shared lease while a
	// sealer probes the lease (it holds the exclusive lock for a moment).
	leaseWait = 5 * time.Second
	// maxLeaseFile bounds what Probe reads of the descriptions.
	maxLeaseFile = 1 << 20
	// relockRounds bounds retries when a lease file is replaced under us.
	relockRounds = 5
)

var (
	// errLeaseKey: a lease key is not a single safe file name.
	errLeaseKey = errors.New("live: bad lease key")
	// errReleased: the Held set was released.
	errReleased = errors.New("live: leases already released")
	// errLeaseSwapped: the lease path no longer names the probed inode
	// (unlinked and recreated during the probe): treated as held (R17).
	errLeaseSwapped = errors.New("live: lease file replaced during probe")

	leaseKeyRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// Seams for crash and race tests (export_test.go): how lease files are
// locked, and a hook run between the probe's lock and its inode check.
var (
	tryLock   = fsx.TryLock
	waitLock  = fsx.WaitLock
	probeHook func(path string)
)

func leasePath(dir, key string) (string, error) {
	if !leaseKeyRE.MatchString(key) {
		return "", fmt.Errorf("%w: %q", errLeaseKey, key)
	}
	if dir == "" || !filepath.IsAbs(dir) {
		return "", fmt.Errorf("live: the lease directory must be absolute, got %q", dir)
	}
	return filepath.Join(filepath.Clean(dir), key+leaseExt), nil
}

// heldLease is one shared flock this process holds.
type heldLease struct {
	key  string
	path string
	lock *fsx.Lock
}

// acquire implements Acquire.
func acquire(dir string, keys []string, l Lease) (*Held, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("live: the lease directory must be absolute, got %q", dir)
	}
	if err := mkdirPrivate(dir); err != nil {
		return nil, err
	}
	if l.At.IsZero() {
		l.At = time.Now().UTC()
	}
	h := &Held{dir: filepath.Clean(dir), desc: l}
	if err := h.add(keys...); err != nil {
		// Without a complete lease the wrapper must not restore: drop what
		// was taken so a sealer is never blocked by a failed launch.
		_ = h.release()
		return nil, err
	}
	return h, nil
}

// add takes a shared lease on every key not held yet, in order. On error the
// leases taken so far stay held (more liveness, never less) until Release.
func (h *Held) add(keys ...string) error {
	if h == nil {
		return errReleased
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.released {
		return errReleased
	}
	for _, k := range keys {
		path, err := leasePath(h.dir, k)
		if err != nil {
			return err
		}
		if h.holdsLocked(k) {
			continue
		}
		lk, err := takeShared(path)
		if err != nil {
			return fmt.Errorf("live: lease %s: %w", k, err)
		}
		hl := &heldLease{key: k, path: path, lock: lk}
		h.leases = append(h.leases, hl)
		if err := writeDescription(hl, h.desc); err != nil {
			return fmt.Errorf("live: lease %s: %w", k, err)
		}
	}
	return nil
}

func (h *Held) holdsLocked(key string) bool {
	for _, hl := range h.leases {
		if hl.key == key {
			return true
		}
	}
	return false
}

// takeShared returns a shared flock on path that still names the locked
// inode. When nobody holds the lease (an exclusive lock succeeds) the
// descriptions left by earlier holders, which have all exited, are
// truncated first, so lease files stay small although they are never
// deleted (SPEC §9.3). Dropping the exclusive lock before taking the
// shared one is harmless: nothing is restored under this lease yet.
func takeShared(path string) (*fsx.Lock, error) {
	for round := 0; round < relockRounds; round++ {
		if ex, err := tryLock(path, false); err == nil {
			if same, serr := lockNamesPath(ex, path); serr == nil && same {
				if terr := ex.File().Truncate(0); terr != nil {
					ex.Unlock()
					return nil, terr
				}
			}
			ex.Unlock()
		} else if !errors.Is(err, fsx.ErrLocked) {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), leaseWait)
		lk, err := waitLock(ctx, path, true)
		cancel()
		if err != nil {
			return nil, err
		}
		same, err := lockNamesPath(lk, path)
		if err != nil {
			lk.Unlock()
			return nil, err
		}
		if same {
			return lk, nil
		}
		lk.Unlock() // the lease file was replaced: lock the current one
	}
	return nil, fmt.Errorf("live: %s keeps being replaced", filepath.Base(path))
}

// lockNamesPath reports whether path still names the inode lk holds.
func lockNamesPath(lk *fsx.Lock, path string) (bool, error) {
	fst, err := fsx.Fstat(lk.File())
	if err != nil {
		return false, err
	}
	cur, err := fsx.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return fst.SameFile(cur), nil
}

// writeDescription appends {key, proc, root, child, at} to the lease file.
// Each holder appends its own line (several wrappers may hold one lease);
// Probe keeps the last line per process.
func writeDescription(hl *heldLease, d Lease) error {
	d.Key = hl.key
	line, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return fsx.AppendLine(hl.path, line)
}

func (h *Held) setChild(child platform.ProcID) error {
	if h == nil {
		return errReleased
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.released {
		return errReleased
	}
	h.desc.Child = child
	var errs []error
	for _, hl := range h.leases {
		if err := writeDescription(hl, h.desc); err != nil {
			errs = append(errs, fmt.Errorf("live: lease %s: %w", hl.key, err))
		}
	}
	return errors.Join(errs...)
}

func (h *Held) inheritable() []*os.File {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.released {
		return nil
	}
	out := make([]*os.File, 0, len(h.leases))
	for _, hl := range h.leases {
		if f := hl.lock.File(); f != nil {
			out = append(out, f)
		}
	}
	return out
}

func (h *Held) release() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.released {
		return nil
	}
	h.released = true
	var errs []error
	for _, hl := range h.leases {
		if err := hl.lock.Unlock(); err != nil {
			errs = append(errs, fmt.Errorf("live: release lease %s: %w", hl.key, err))
		}
	}
	h.leases = nil
	return errors.Join(errs...)
}

// probe implements Probe (SPEC §9.3, R17): a non-blocking exclusive flock
// that is released at once, then a check that the path still names the
// probed inode. A missing lease file means the unit was never leased; any
// other failure, a held lock or a replaced file reports held=true.
func probe(dir, key string) (bool, []Lease, error) {
	path, err := leasePath(dir, key)
	if err != nil {
		return true, nil, err
	}
	st, err := fsx.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil, nil
	}
	if err != nil {
		return true, nil, err
	}
	if !st.IsRegular() {
		return true, nil, fmt.Errorf("%w: %s is not a regular file", fsx.ErrUnsafe, filepath.Base(path))
	}
	lk, err := tryLock(path, false)
	switch {
	case errors.Is(err, fsx.ErrLocked):
		return true, readDescriptions(path), nil
	case err != nil:
		return true, nil, err // ENOTSUP, EACCES…: treated as held
	}
	fst, ferr := fsx.Fstat(lk.File())
	if probeHook != nil {
		probeHook(path)
	}
	lk.Unlock()
	cur, cerr := fsx.Lstat(path)
	if ferr != nil {
		return true, nil, ferr
	}
	if cerr != nil || !fst.SameFile(st) || !fst.SameFile(cur) {
		return true, nil, errLeaseSwapped
	}
	return false, nil, nil
}

// readDescriptions returns the newest description of each holder process
// found in a lease file (best effort: a torn or foreign line is skipped).
func readDescriptions(path string) []Lease {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxLeaseFile))
	if err != nil {
		return nil
	}
	key := filepath.Base(path)
	key = key[:len(key)-len(leaseExt)]
	byProc := map[platform.ProcID]Lease{}
	var order []platform.ProcID
	for _, line := range bytes.Split(data, []byte("\n")) {
		var l Lease
		if json.Unmarshal(line, &l) != nil || l.Key != key {
			continue
		}
		if _, ok := byProc[l.Proc]; !ok {
			order = append(order, l.Proc)
		}
		byProc[l.Proc] = l
	}
	out := make([]Lease, 0, len(order))
	for _, p := range order {
		out = append(out, byProc[p])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// mkdirPrivate creates dir (0700) and requires a real directory owned by
// the current user.
func mkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := fsx.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", fsx.ErrUnsafe, dir)
	}
	if int(st.UID) != os.Getuid() {
		return fmt.Errorf("%w: %s is not owned by the current user", fsx.ErrUnsafe, dir)
	}
	return nil
}
