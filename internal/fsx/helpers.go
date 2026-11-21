package fsx

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// modeSymlink is the st_mode file type of a symbolic link (identical on
// darwin and linux).
const modeSymlink = 0o120000

func isSymlinkMode(mode uint32) bool { return mode&modeTypeMask == modeSymlink }

func unsafePath(path, reason string) error {
	return fmt.Errorf("%w: %s: %s", ErrUnsafe, path, reason)
}

// mkdirPrivate implements MkdirPrivate: the missing components of path are
// created outermost first with mode 0700 (re-applied when a umask removed
// owner bits, so nested components stay creatable); existing components,
// such as a symlinked trusted ancestor like /tmp on darwin, are left
// untouched. The final directory must be a real directory owned by the
// effective uid.
func mkdirPrivate(path string) error {
	if !filepath.IsAbs(path) {
		return unsafePath(path, "not an absolute path")
	}
	path = filepath.Clean(path)
	var missing []string
	for p := path; ; p = filepath.Dir(p) {
		_, err := lstatPath(p)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		missing = append(missing, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		p := missing[i]
		if err := mkdirOne(p); err != nil {
			if errors.Is(err, ErrExist) {
				continue // created concurrently; judged below
			}
			return err
		}
		if err := fixDirMode(p); err != nil {
			return err
		}
	}
	st, err := lstatPath(path)
	if err != nil {
		return err
	}
	switch {
	case isSymlinkMode(st.Mode):
		return unsafePath(path, "is a symlink")
	case !st.IsDir():
		return unsafePath(path, "not a directory")
	case st.UID != uint32(os.Geteuid()):
		return unsafePath(path, fmt.Sprintf("owned by uid %d", st.UID))
	}
	return nil
}

// checkPrivateDir implements CheckPrivateDir (D6).
func checkPrivateDir(path string) error {
	st, err := lstatPath(path)
	if err != nil {
		return err
	}
	switch {
	case isSymlinkMode(st.Mode):
		return unsafePath(path, "is a symlink")
	case !st.IsDir():
		return unsafePath(path, "not a directory")
	case st.UID != uint32(os.Geteuid()):
		return unsafePath(path, fmt.Sprintf("owned by uid %d", st.UID))
	case st.Mode&0o077 != 0:
		return unsafePath(path, fmt.Sprintf("mode %04o (want no group/other bits)", st.Mode&0o7777))
	}
	return nil
}

func realpath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", unsafePath(path, "not an absolute path")
	}
	r, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	r = filepath.Clean(r)
	if !filepath.IsAbs(r) {
		return "", unsafePath(path, "resolves to a relative path")
	}
	return r, nil
}

// nearestExisting returns the deepest existing ancestor of path (path
// itself when it exists), stat'ed through symlinks.
func nearestExisting(path string) (string, Stat, error) {
	for p := path; ; p = filepath.Dir(p) {
		st, err := statPath(p)
		if err == nil {
			return p, st, nil
		}
		if Classify(err) != ClassMissing {
			return "", Stat{}, err
		}
		if filepath.Dir(p) == p {
			return "", Stat{}, err
		}
	}
}

func contains(root, p string) (bool, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(p) {
		return false, fmt.Errorf("%w: Contains needs absolute paths", ErrUnsafe)
	}
	root, p = filepath.Clean(root), filepath.Clean(p)
	rootSt, rerr := statPath(root)
	if rerr != nil {
		if Classify(rerr) != ClassMissing {
			return false, rerr
		}
		return lexicallyWithin(root, p), nil
	}
	q, _, err := nearestExisting(p)
	if err != nil {
		return false, err
	}
	// Compare the identity of every existing ancestor with root, so case-
	// and normalization-insensitive spellings and symlinked ancestors are
	// judged by the object they name.
	for a := q; ; a = filepath.Dir(a) {
		st, err := statPath(a)
		if err != nil {
			return false, err
		}
		if st.SameFile(rootSt) {
			return true, nil
		}
		if filepath.Dir(a) == a {
			return false, nil
		}
	}
}

// lexicallyWithin compares cleaned absolute paths component by component,
// case-folded on darwin (case-insensitive by default there; folding can
// only make more paths count as contained).
func lexicallyWithin(root, p string) bool {
	rc, pc := components(root), components(p)
	if len(pc) < len(rc) {
		return false
	}
	for i := range rc {
		if rc[i] == pc[i] {
			continue
		}
		if runtime.GOOS == "darwin" && strings.EqualFold(rc[i], pc[i]) {
			continue
		}
		return false
	}
	return true
}

func components(clean string) []string {
	if clean == "/" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(clean, "/"), "/")
}

func sameDevice(a, b string) (bool, error) {
	if !filepath.IsAbs(a) || !filepath.IsAbs(b) {
		return false, fmt.Errorf("%w: SameDevice needs absolute paths", ErrUnsafe)
	}
	_, sa, err := nearestExisting(filepath.Clean(a))
	if err != nil {
		return false, err
	}
	_, sb, err := nearestExisting(filepath.Clean(b))
	if err != nil {
		return false, err
	}
	return sa.Dev == sb.Dev, nil
}

func spaceOf(path string) (avail, total uint64, err error) {
	if !filepath.IsAbs(path) {
		return 0, 0, fmt.Errorf("%w: Space needs an absolute path", ErrUnsafe)
	}
	p, _, err := nearestExisting(filepath.Clean(path))
	if err != nil {
		return 0, 0, err
	}
	return space(p)
}

// reserve is the number of bytes the floor keeps free on a volume of total
// bytes: max(MinBytes, MinFraction × total).
func (f Floor) reserve(total uint64) uint64 {
	var r uint64
	if f.MinBytes > 0 {
		r = uint64(f.MinBytes)
	}
	if frac := f.MinFraction; frac > 0 && !math.IsNaN(frac) {
		if frac > 1 {
			frac = 1
		}
		if b := uint64(frac * float64(total)); b > r {
			r = b
		}
	}
	return r
}

func checkSpace(path string, need int64, floor Floor) error {
	avail, total, err := spaceOf(path)
	if err != nil {
		return err
	}
	if need < 0 {
		need = 0
	}
	reserve := floor.reserve(total)
	if avail < reserve || avail-reserve < uint64(need) {
		return fmt.Errorf("%w: %s: need %d bytes plus a floor of %d, %d available", ErrNoSpace, path, need, reserve, avail)
	}
	return nil
}

// stagingDirName is the per-volume staging directory used when the
// preferred staging directory is on another file system (SPEC §6.1).
const stagingDirName = ".precinto-staging"

func newStaging(preferred, target, id string) (*Staging, error) {
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\x00") {
		return nil, fmt.Errorf("%w: bad staging id %q", ErrUnsafe, id)
	}
	if !filepath.IsAbs(preferred) || !filepath.IsAbs(target) {
		return nil, fmt.Errorf("%w: staging needs absolute paths", ErrUnsafe)
	}
	preferred, target = filepath.Clean(preferred), filepath.Clean(target)
	if err := mkdirPrivate(preferred); err != nil {
		return nil, err
	}
	if err := checkPrivateDir(preferred); err != nil {
		return nil, err
	}
	same, err := sameDevice(preferred, target)
	if err != nil {
		return nil, err
	}
	parent := preferred
	if !same {
		root, err := volumeRoot(target)
		if err != nil {
			return nil, err
		}
		parent = filepath.Join(root, stagingDirName)
		if err := mkdirPrivate(parent); err != nil {
			return nil, err
		}
		if err := checkPrivateDir(parent); err != nil {
			return nil, err
		}
		if ok, err := sameDevice(parent, target); err != nil || !ok {
			if err == nil {
				err = fmt.Errorf("fsx: %s is not on the volume of %s", parent, target)
			}
			return nil, err
		}
	}
	path := filepath.Join(parent, id)
	if err := mkdirOne(path); err != nil {
		return nil, err
	}
	if err := fixDirMode(path); err != nil {
		return nil, err
	}
	if err := checkPrivateDir(path); err != nil {
		return nil, err
	}
	d, err := openBase(path)
	if err != nil {
		return nil, err
	}
	return &Staging{Dir: d, Path: path, ID: id}, nil
}

// volumeRoot returns the mount point of the file system holding path: the
// highest ancestor of its deepest existing prefix on the same device.
func volumeRoot(path string) (string, error) {
	p, st, err := nearestExisting(path)
	if err != nil {
		return "", err
	}
	for {
		up := filepath.Dir(p)
		if up == p {
			return p, nil
		}
		ust, err := statPath(up)
		if err != nil {
			return "", err
		}
		if ust.Dev != st.Dev {
			return p, nil
		}
		p = up
	}
}

func openStaging(path string) (*Staging, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%w: staging path %q is not absolute and clean", ErrUnsafe, path)
	}
	if err := checkPrivateDir(path); err != nil {
		return nil, err
	}
	d, err := openBase(path)
	if err != nil {
		return nil, err
	}
	return &Staging{Dir: d, Path: path, ID: filepath.Base(path)}, nil
}

func classify(err error) Class {
	switch {
	case err == nil:
		return ClassNone
	case errors.Is(err, ErrNoSpace):
		return ClassNoSpace
	case errors.Is(err, ErrLocked):
		return ClassBusy
	case errors.Is(err, ErrUnsafe), errors.Is(err, ErrHardlink):
		return ClassUnsafe
	case errors.Is(err, ErrExist), errors.Is(err, ErrChanged),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ClassOther
	}
	return classifyErrno(err)
}
