//go:build darwin || linux

package fsx

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/precinto/precinto/internal/fsx/failpoint"
)

// Directory handles are opened read-only, as directories, never through a
// symlink, and never inherited across exec.
const oDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// maxWalkDepth bounds Walk and the recursive removal of staging trees: every
// level holds one descriptor, so an adversarial tree must not exhaust them.
const maxWalkDepth = 256

func euid() uint32 { return uint32(os.Geteuid()) }

// retry repeats a system call interrupted by a signal.
func retry(f func() error) error {
	for {
		err := f()
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func openat(dirfd int, name string, flags int, mode uint32) (int, error) {
	var fd int
	err := retry(func() error {
		var e error
		fd, e = unix.Openat(dirfd, name, flags, mode)
		return e
	})
	return fd, err
}

func fstatFD(fd int) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := retry(func() error { return unix.Fstat(fd, &st) })
	return st, err
}

func lstatAt(dirfd int, name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := retry(func() error { return unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) })
	return st, err
}

func closeFD(fd int) { _ = unix.Close(fd) }

func pathErr(op, path string, err error) error {
	return &os.PathError{Op: op, Path: path, Err: err}
}

// sentinelErr wraps a kernel error with one of the package sentinels so
// that both errors.Is(err, ErrX) and errors.Is(err, fs.ErrY) hold.
func sentinelErr(sentinel error, op, path string, err error) error {
	return fmt.Errorf("%w: %w", sentinel, pathErr(op, path, err))
}

func unsafeErr(path, reason string) error {
	return fmt.Errorf("%w: %s: %s", ErrUnsafe, path, reason)
}

func typeOfMode(mode uint32) EntryType {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return TypeRegular
	case unix.S_IFDIR:
		return TypeDir
	case unix.S_IFLNK:
		return TypeSymlink
	default:
		return TypeOther
	}
}

// splitRel validates a '/'-separated path relative to a Dir and returns its
// components; "" and "." name the directory itself. Absolute, non-clean or
// escaping paths are ErrUnsafe.
func splitRel(rel string) ([]string, error) {
	if rel == "" || rel == "." {
		return nil, nil
	}
	if strings.IndexByte(rel, 0) >= 0 || !filepath.IsLocal(rel) || filepath.Clean(rel) != rel {
		return nil, fmt.Errorf("%w: %q is not a clean relative path", ErrUnsafe, rel)
	}
	return strings.Split(rel, "/"), nil
}

// validName checks a single new path component (temporary names, staging
// ids).
func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}

func (d *Dir) alive() error {
	if d == nil || !d.open {
		return os.ErrClosed
	}
	return nil
}

func (d *Dir) join(rel string) string {
	if rel == "" || rel == "." {
		return d.path
	}
	return d.path + "/" + rel
}

// checkDirStat enforces the rule for every directory below a base: owned by
// the effective uid and not writable by group or others (D12), a
// user-private group excepted (D67).
func checkDirStat(st *unix.Stat_t, path string) error {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unsafeErr(path, "not a directory")
	}
	if st.Uid != euid() {
		return unsafeErr(path, fmt.Sprintf("owned by uid %d", st.Uid))
	}
	if othersMayWrite(st) {
		return unsafeErr(path, fmt.Sprintf("group/other-writable directory (mode %04o)", st.Mode&0o7777))
	}
	return nil
}

// othersMayWrite reports whether anyone but the user may write the
// directory st: it is other-writable, or group-writable with a group that
// is not the user's private group (D67, linux only).
func othersMayWrite(st *unix.Stat_t) bool {
	switch {
	case st.Mode&0o002 != 0:
		return true
	case st.Mode&0o020 != 0:
		return !groupWritableOK(st.Gid)
	}
	return false
}

// openComponent opens the directory name below dirfd without following a
// symlink, optionally creating it 0700, and checks owner and mode.
func openComponent(dirfd int, name, path string, create bool) (int, error) {
	created := false
	for attempt := 0; ; attempt++ {
		fd, err := openat(dirfd, name, oDirFlags, 0)
		if err == nil {
			st, err := fstatFD(fd)
			if err != nil {
				closeFD(fd)
				return -1, pathErr("fstat", path, err)
			}
			if created && st.Mode&0o777 != 0o700 && st.Uid == euid() {
				// A umask can only remove bits; restore the owner's so that
				// the next component stays creatable.
				if err := retry(func() error { return unix.Fchmod(fd, 0o700) }); err != nil {
					closeFD(fd)
					return -1, pathErr("fchmod", path, err)
				}
				st.Mode = st.Mode&^0o7777 | 0o700
			}
			if err := checkDirStat(&st, path); err != nil {
				closeFD(fd)
				return -1, err
			}
			return fd, nil
		}
		switch {
		case errors.Is(err, unix.ENOENT) && create && attempt == 0:
			if err := failpoint.Hit("fsx.write"); err != nil {
				return -1, pathErr("mkdirat", path, err)
			}
			err := retry(func() error { return unix.Mkdirat(dirfd, name, 0o700) })
			if err != nil && !errors.Is(err, unix.EEXIST) {
				return -1, pathErr("mkdirat", path, err)
			}
			created = err == nil
			if created {
				note(failpoint.FSMkdir, path, "", true)
			}
		case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EMLINK):
			return -1, unsafeErr(path, "symlink component")
		case errors.Is(err, unix.ENOTDIR):
			// darwin and linux report ENOTDIR for O_NOFOLLOW|O_DIRECTORY on a symlink.
			if st, serr := lstatAt(dirfd, name); serr == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
				return -1, unsafeErr(path, "symlink component")
			}
			return -1, pathErr("openat", path, err)
		default:
			return -1, pathErr("openat", path, err)
		}
	}
}

// walkTo opens every component of parts below d (all of them when the
// result must be a directory, or all but the last when the caller acts on
// the last name). The returned release closes the descriptor unless it is
// d's own.
func (d *Dir) walkTo(parts []string, create bool) (int, func(), error) {
	fd := d.fd
	release := func() {}
	for i, name := range parts {
		next, err := openComponent(fd, name, d.join(strings.Join(parts[:i+1], "/")), create)
		release()
		if err != nil {
			return -1, func() {}, err
		}
		fd = next
		release = func() { closeFD(next) }
	}
	return fd, release, nil
}

// parent opens the directory holding the last component of rel and returns
// it with that component's name. rel must name an entry, not d itself.
func (d *Dir) parent(rel string, create bool) (int, string, func(), error) {
	if err := d.alive(); err != nil {
		return -1, "", func() {}, err
	}
	parts, err := splitRel(rel)
	if err != nil {
		return -1, "", func() {}, err
	}
	if len(parts) == 0 {
		return -1, "", func() {}, fmt.Errorf("%w: %q names the directory itself", ErrUnsafe, rel)
	}
	fd, release, err := d.walkTo(parts[:len(parts)-1], create)
	if err != nil {
		return -1, "", release, err
	}
	return fd, parts[len(parts)-1], release, nil
}

// dirFD opens rel as a directory (d itself for "" or ".").
func (d *Dir) dirFD(rel string, create bool) (int, func(), error) {
	if err := d.alive(); err != nil {
		return -1, func() {}, err
	}
	parts, err := splitRel(rel)
	if err != nil {
		return -1, func() {}, err
	}
	return d.walkTo(parts, create)
}

func openBase(path string) (*Dir, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%w: base %q is not an absolute clean path", ErrUnsafe, path)
	}
	fd, err := openat(unix.AT_FDCWD, path, oDirFlags, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, unsafeErr(path, "base is a symlink")
		}
		if errors.Is(err, unix.ENOTDIR) {
			// O_NOFOLLOW|O_DIRECTORY on a symlink is ENOTDIR on darwin and
			// linux alike.
			var st unix.Stat_t
			if unix.Lstat(path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
				return nil, unsafeErr(path, "base is a symlink")
			}
		}
		return nil, pathErr("open", path, err)
	}
	st, err := fstatFD(fd)
	if err != nil {
		closeFD(fd)
		return nil, pathErr("fstat", path, err)
	}
	if st.Uid != euid() {
		closeFD(fd)
		return nil, unsafeErr(path, fmt.Sprintf("base owned by uid %d", st.Uid))
	}
	return &Dir{fd: fd, path: path, open: true}, nil
}

func (d *Dir) close() error {
	if d == nil || !d.open {
		return nil
	}
	d.open = false
	fd := d.fd
	d.fd = -1
	if err := unix.Close(fd); err != nil {
		return pathErr("close", d.path, err)
	}
	return nil
}

func (d *Dir) openDir(rel string, create bool) (*Dir, error) {
	fd, release, err := d.dirFD(rel, create)
	if err != nil {
		return nil, err
	}
	if fd == d.fd {
		// "" or ".": hand out an independent descriptor of the same
		// directory so that closing either never affects the other.
		nfd, err := openat(d.fd, ".", oDirFlags, 0)
		if err != nil {
			return nil, pathErr("openat", d.path, err)
		}
		return &Dir{fd: nfd, path: d.path, open: true}, nil
	}
	_ = release // ownership moves to the new Dir
	return &Dir{fd: fd, path: d.join(rel), open: true}, nil
}

func (d *Dir) openFile(rel string) (*os.File, Stat, error) {
	pfd, name, release, err := d.parent(rel, false)
	defer release()
	if err != nil {
		return nil, Stat{}, err
	}
	path := d.join(rel)
	fd, err := openat(pfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, Stat{}, unsafeErr(path, "symlink")
		}
		return nil, Stat{}, pathErr("openat", path, err)
	}
	st, err := fstatFD(fd)
	if err != nil {
		closeFD(fd)
		return nil, Stat{}, pathErr("fstat", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		closeFD(fd)
		return nil, Stat{}, unsafeErr(path, "not a regular file")
	}
	if isDataless(&st) {
		closeFD(fd)
		return nil, Stat{}, pathErr("open", path, fmt.Errorf("dataless cloud placeholder: %w", unix.EACCES))
	}
	// O_NONBLOCK only guarded the open against FIFOs; regular-file reads
	// are blocking.
	if err := setBlocking(fd); err != nil {
		closeFD(fd)
		return nil, Stat{}, pathErr("fcntl", path, err)
	}
	return os.NewFile(uintptr(fd), path), statFrom(&st), nil
}

func setBlocking(fd int) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if flags&unix.O_NONBLOCK == 0 {
		return nil
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK)
	return err
}

func (d *Dir) lstat(rel string) (Stat, error) {
	if err := d.alive(); err != nil {
		return Stat{}, err
	}
	parts, err := splitRel(rel)
	if err != nil {
		return Stat{}, err
	}
	if len(parts) == 0 {
		st, err := fstatFD(d.fd)
		if err != nil {
			return Stat{}, pathErr("fstat", d.path, err)
		}
		return statFrom(&st), nil
	}
	pfd, name, release, err := d.parent(rel, false)
	defer release()
	if err != nil {
		return Stat{}, err
	}
	st, err := lstatAt(pfd, name)
	if err != nil {
		return Stat{}, pathErr("lstat", d.join(rel), err)
	}
	return statFrom(&st), nil
}

// readNames lists a directory through a fresh open file description, so
// the read offset of the handle itself is never disturbed.
func readNames(fd int, path string) ([]string, error) {
	if err := failpoint.Hit("fsx.readdir"); err != nil {
		return nil, pathErr("readdir", path, err)
	}
	dfd, err := openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, pathErr("openat", path, err)
	}
	f := os.NewFile(uintptr(dfd), path)
	names, err := f.Readdirnames(-1)
	cerr := f.Close()
	if err != nil {
		return nil, err
	}
	if cerr != nil {
		return nil, cerr
	}
	sort.Strings(names)
	return names, nil
}

func (d *Dir) readDir(rel string) ([]Entry, error) {
	fd, release, err := d.dirFD(rel, false)
	defer release()
	if err != nil {
		return nil, err
	}
	path := d.join(rel)
	names, err := readNames(fd, path)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(names))
	for _, name := range names {
		st, err := lstatAt(fd, name)
		if errors.Is(err, unix.ENOENT) {
			continue // removed since the listing
		}
		if err != nil {
			return nil, pathErr("lstat", path+"/"+name, err)
		}
		out = append(out, Entry{Name: name, Type: typeOfMode(uint32(st.Mode)), Stat: statFrom(&st)})
	}
	return out, nil
}

// hazardOf classifies an lstat'ed entry for Walk.
func hazardOf(st *unix.Stat_t) Hazard {
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return HazardSymlink
	case unix.S_IFREG:
		switch {
		case st.Uid != euid():
			return HazardForeign
		case st.Nlink > 1:
			return HazardHardlink
		case isDataless(st):
			return HazardAccess
		}
		return HazardNone
	case unix.S_IFDIR:
		switch {
		case st.Uid != euid(), othersMayWrite(st):
			// Another user could swap entries below it (D12, D67).
			return HazardForeign
		case isDataless(st):
			return HazardAccess // listing it would trigger a download
		}
		return HazardNone
	default:
		return HazardSpecial
	}
}

func isAccessErr(err error) bool {
	return errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM)
}

func joinRel(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}

func (d *Dir) walk(rel string, fn func(WalkEntry) error) error {
	parts, err := splitRel(rel)
	if err != nil {
		return err
	}
	fd, release, err := d.dirFD(rel, false)
	defer release()
	if err != nil {
		return err
	}
	names, err := readNames(fd, d.join(rel))
	if err != nil {
		return err
	}
	err = d.walkDir(fd, strings.Join(parts, "/"), names, fn, 0)
	if errors.Is(err, fs.SkipAll) || errors.Is(err, fs.SkipDir) {
		return nil
	}
	return err
}

// walkDir visits the sorted names of the directory fd. A subdirectory is
// opened (by name, without following) and listed before fn sees it, so
// that an unreadable one is reported as HazardAccess and a replaced one is
// detected; hazardous entries are never descended into.
func (d *Dir) walkDir(fd int, prefix string, names []string, fn func(WalkEntry) error, depth int) error {
	if depth >= maxWalkDepth {
		return unsafeErr(d.join(prefix), "directory tree too deep")
	}
	for _, name := range names {
		rel := joinRel(prefix, name)
		path := d.join(rel)
		st, err := lstatAt(fd, name)
		if errors.Is(err, unix.ENOENT) {
			continue // removed since the listing
		}
		if err != nil {
			if !isAccessErr(err) {
				return pathErr("lstat", path, err)
			}
			if err := fn(WalkEntry{Rel: rel, Type: TypeOther, Hazard: HazardAccess}); err != nil {
				if errors.Is(err, fs.SkipDir) {
					return nil
				}
				return err
			}
			continue
		}
		we := WalkEntry{Rel: rel, Type: typeOfMode(uint32(st.Mode)), Stat: statFrom(&st), Hazard: hazardOf(&st)}
		if we.Type != TypeDir || we.Hazard != HazardNone {
			if err := fn(we); err != nil {
				if !errors.Is(err, fs.SkipDir) {
					return err
				}
				if we.Type != TypeDir {
					return nil // SkipDir on a file skips the rest of this directory
				}
			}
			continue
		}
		sub, subNames, gone, err := openSubdir(fd, name, path, &we)
		if err != nil {
			return err
		}
		if gone {
			continue
		}
		ferr := fn(we)
		if ferr == nil && sub >= 0 {
			ferr = d.walkDir(sub, rel, subNames, fn, depth+1)
		}
		if sub >= 0 {
			closeFD(sub)
		}
		if ferr != nil {
			if errors.Is(ferr, fs.SkipDir) {
				continue // fn skipped this directory
			}
			return ferr
		}
	}
	return nil
}

// openSubdir opens and lists the directory entry we (named name below fd)
// for walkDir. It returns sub = -1 when the directory must not be
// descended into (we.Hazard is then set), gone when it vanished, and an
// error when it was replaced by something else since it was lstat'ed.
func openSubdir(fd int, name, path string, we *WalkEntry) (sub int, names []string, gone bool, err error) {
	sub, err = openat(fd, name, oDirFlags, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return -1, nil, true, nil
	case isAccessErr(err):
		we.Hazard = HazardAccess
		return -1, nil, false, nil
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return -1, nil, false, fmt.Errorf("%w: %s was replaced while walking", ErrChanged, path)
	case err != nil:
		return -1, nil, false, pathErr("openat", path, err)
	}
	sst, err := fstatFD(sub)
	if err != nil {
		closeFD(sub)
		return -1, nil, false, pathErr("fstat", path, err)
	}
	if got := statFrom(&sst); !got.SameFile(we.Stat) {
		closeFD(sub)
		return -1, nil, false, fmt.Errorf("%w: %s was replaced while walking", ErrChanged, path)
	}
	names, err = readNames(sub, path)
	if err != nil {
		closeFD(sub)
		if !isAccessErr(err) {
			return -1, nil, false, err
		}
		we.Hazard = HazardAccess // e.g. a TCC denial on getdirentries
		return -1, nil, false, nil
	}
	return sub, names, false, nil
}

// randomSuffix returns 12 hex characters for temporary names.
func randomSuffix() string {
	var b [6]byte
	_, _ = rand.Read(b[:]) // never fails (Go ≥ 1.24)
	return hex.EncodeToString(b[:])
}

func (d *Dir) createTemp(dirRel, pattern string) (*os.File, string, error) {
	if !validName(strings.ReplaceAll(pattern, "*", "x")) {
		return nil, "", fmt.Errorf("%w: bad temporary name pattern %q", ErrUnsafe, pattern)
	}
	fd, release, err := d.dirFD(dirRel, true)
	defer release()
	if err != nil {
		return nil, "", err
	}
	// A pattern with '*' gets a random string in place of its last '*';
	// a pattern without one is used as the exact name (exclusive create).
	i := strings.LastIndexByte(pattern, '*')
	for attempt := 0; attempt < 100; attempt++ {
		name := pattern
		if i >= 0 {
			name = pattern[:i] + randomSuffix() + pattern[i+1:]
		}
		rel := name
		if dirRel != "" && dirRel != "." {
			rel = dirRel + "/" + name
		}
		path := d.join(rel)
		if err := failpoint.Hit("fsx.write"); err != nil {
			return nil, "", pathErr("openat", path, err)
		}
		nfd, err := openat(fd, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			if i < 0 {
				return nil, "", sentinelErr(ErrExist, "openat", path, err)
			}
			continue
		}
		if err != nil {
			return nil, "", pathErr("openat", path, err)
		}
		note(failpoint.FSCreate, path, "", true)
		if st, err := fstatFD(nfd); err == nil && st.Mode&0o777 != 0o600 {
			if err := retry(func() error { return unix.Fchmod(nfd, 0o600) }); err != nil {
				closeFD(nfd)
				_ = unix.Unlinkat(fd, name, 0)
				return nil, "", pathErr("fchmod", path, err)
			}
		}
		return os.NewFile(uintptr(nfd), path), rel, nil
	}
	return nil, "", fmt.Errorf("fsx: could not create a temporary in %s", d.join(dirRel))
}

func (d *Dir) appendLine(rel string, line []byte) error {
	if l := len(line); l > 0 && line[l-1] == '\n' {
		line = line[:l-1]
	}
	if len(line) > MaxLine || bytes.IndexByte(line, '\n') >= 0 {
		return fmt.Errorf("%w: bad line for AppendLine", ErrUnsafe)
	}
	pfd, name, release, err := d.parent(rel, false)
	defer release()
	if err != nil {
		return err
	}
	path := d.join(rel)
	f, created, err := openAppendAt(pfd, name, path)
	if err != nil {
		return err
	}
	defer f.Close()
	if created {
		note(failpoint.FSCreate, path, "", true)
	}
	if err := failpoint.Hit("fsx.write"); err != nil {
		return pathErr("write", path, err)
	}
	buf := make([]byte, 0, len(line)+1)
	buf = append(append(buf, line...), '\n')
	n, err := f.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("fsx: short append to %s (%d of %d bytes)", path, n, len(buf))
	}
	if err := FullSync(f); err != nil {
		return err
	}
	if created {
		return syncFD(pfd, filepath.Dir(path))
	}
	return nil
}

// openAppendAt opens name below pfd for appending (never following a
// symlink, never blocking on a FIFO), creating it 0600 with O_EXCL when it
// is missing. Only a regular file owned by the effective uid is accepted.
func openAppendAt(pfd int, name, path string) (*os.File, bool, error) {
	for attempt := 0; attempt < 3; attempt++ {
		if st, err := lstatAt(pfd, name); err == nil && isDataless(&st) {
			// Opening a dataless cloud placeholder for writing would
			// trigger a download (SPEC §17).
			return nil, false, pathErr("open", path, fmt.Errorf("dataless cloud placeholder: %w", unix.EACCES))
		}
		const flags = unix.O_WRONLY | unix.O_APPEND | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		created := false
		fd, err := openat(pfd, name, flags, 0)
		if errors.Is(err, unix.ENOENT) {
			if herr := failpoint.Hit("fsx.write"); herr != nil {
				return nil, false, pathErr("openat", path, herr)
			}
			fd, err = openat(pfd, name, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
			if errors.Is(err, unix.EEXIST) {
				continue // created concurrently: reopen without O_CREAT
			}
			created = err == nil
		}
		if err != nil {
			switch {
			case errors.Is(err, unix.ELOOP):
				return nil, false, unsafeErr(path, "symlink")
			case errors.Is(err, unix.ENXIO), errors.Is(err, unix.EOPNOTSUPP):
				// A FIFO without a reader or a socket: never a regular file.
				return nil, false, unsafeErr(path, "not a regular file")
			}
			return nil, false, pathErr("openat", path, err)
		}
		st, err := fstatFD(fd)
		if err != nil {
			closeFD(fd)
			return nil, false, pathErr("fstat", path, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			closeFD(fd)
			return nil, false, unsafeErr(path, "not a regular file")
		}
		if st.Uid != euid() {
			closeFD(fd)
			return nil, false, unsafeErr(path, fmt.Sprintf("owned by uid %d", st.Uid))
		}
		if created && st.Mode&0o777 != 0o600 {
			if err := retry(func() error { return unix.Fchmod(fd, 0o600) }); err != nil {
				closeFD(fd)
				return nil, false, pathErr("fchmod", path, err)
			}
		}
		return os.NewFile(uintptr(fd), path), created, nil
	}
	return nil, false, fmt.Errorf("fsx: could not open %s for appending", path)
}

// syncFD fsyncs a directory or file descriptor (F_FULLFSYNC on darwin).
func syncFD(fd int, path string) error {
	if err := failpoint.Hit("fsx.fsync"); err != nil {
		return pathErr("fsync", path, err)
	}
	if err := fullSyncFD(fd); err != nil {
		return pathErr("fsync", path, err)
	}
	note(failpoint.FSDirSync, path, "", true)
	return nil
}

func sameDirFD(a, b int) bool {
	if a == b {
		return true
	}
	sa, err1 := fstatFD(a)
	sb, err2 := fstatFD(b)
	return err1 == nil && err2 == nil && sa.Dev == sb.Dev && sa.Ino == sb.Ino
}

func (d *Dir) renameTo(oldRel string, dst *Dir, newRel string, mode RenameMode) error {
	if err := dst.alive(); err != nil {
		return err
	}
	if mode != NoReplace && mode != Replace {
		return fmt.Errorf("fsx: unknown rename mode %d", mode)
	}
	ofd, oname, orelease, err := d.parent(oldRel, false)
	defer orelease()
	if err != nil {
		return err
	}
	nfd, nname, nrelease, err := dst.parent(newRel, false)
	defer nrelease()
	if err != nil {
		return err
	}
	opath, npath := d.join(oldRel), dst.join(newRel)
	if err := failpoint.Hit("fsx.rename"); err != nil {
		return pathErr("rename", opath, err)
	}
	note(failpoint.FSRename, opath, npath, false)
	if mode == NoReplace {
		err = renameNoReplace(ofd, oname, nfd, nname)
	} else {
		err = retry(func() error { return unix.Renameat(ofd, oname, nfd, nname) })
	}
	if err == nil {
		note(failpoint.FSRename, opath, npath, true)
	}
	if err != nil {
		if mode == NoReplace && (errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY)) {
			return sentinelErr(ErrExist, "rename", npath, err)
		}
		return pathErr("rename", opath, err)
	}
	if err := syncFD(nfd, filepath.Dir(npath)); err != nil {
		return err
	}
	if !sameDirFD(ofd, nfd) {
		return syncFD(ofd, filepath.Dir(opath))
	}
	return nil
}

// linkNoReplace is the portable NoReplace fallback: link the new name (which
// fails if it exists), then unlink the old one.
func linkNoReplace(ofd int, oname string, nfd int, nname string) error {
	if err := failpoint.Hit("fsx.link"); err != nil {
		return err
	}
	if err := retry(func() error { return unix.Linkat(ofd, oname, nfd, nname, 0) }); err != nil {
		return err
	}
	if err := failpoint.Hit("fsx.unlink"); err != nil {
		return err
	}
	return retry(func() error { return unix.Unlinkat(ofd, oname, 0) })
}

func (d *Dir) link(oldRel, newRel string) error {
	ofd, oname, orelease, err := d.parent(oldRel, false)
	defer orelease()
	if err != nil {
		return err
	}
	nfd, nname, nrelease, err := d.parent(newRel, false)
	defer nrelease()
	if err != nil {
		return err
	}
	opath, npath := d.join(oldRel), d.join(newRel)
	st, err := lstatAt(ofd, oname)
	if err != nil {
		return pathErr("lstat", opath, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return unsafeErr(opath, "not a regular file")
	}
	if err := failpoint.Hit("fsx.link"); err != nil {
		return pathErr("link", npath, err)
	}
	note(failpoint.FSLink, opath, npath, false)
	if err := retry(func() error { return unix.Linkat(ofd, oname, nfd, nname, 0) }); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return sentinelErr(ErrExist, "link", npath, err)
		}
		return pathErr("link", npath, err)
	}
	note(failpoint.FSLink, opath, npath, true)
	return syncFD(nfd, filepath.Dir(npath))
}

func (d *Dir) unlinkIfUnchanged(rel string, expect Stat) error {
	pfd, name, release, err := d.parent(rel, false)
	defer release()
	if err != nil {
		return err
	}
	path := d.join(rel)
	st, err := lstatAt(pfd, name)
	if err != nil {
		return pathErr("lstat", path, err)
	}
	cur := statFrom(&st)
	if !cur.Unchanged(expect) {
		return fmt.Errorf("%w: %s", ErrChanged, path)
	}
	if typeOfMode(cur.Mode) == TypeDir {
		return unsafeErr(path, "is a directory")
	}
	if cur.Nlink != 1 {
		return fmt.Errorf("%w: %s has %d links", ErrHardlink, path, cur.Nlink)
	}
	if err := failpoint.Hit("fsx.unlink"); err != nil {
		return pathErr("unlink", path, err)
	}
	note(failpoint.FSUnlink, path, "", false)
	if err := retry(func() error { return unix.Unlinkat(pfd, name, 0) }); err != nil {
		return pathErr("unlink", path, err)
	}
	note(failpoint.FSUnlink, path, "", true)
	return syncFD(pfd, filepath.Dir(path))
}

func (d *Dir) remove(rel string) error {
	pfd, name, release, err := d.parent(rel, false)
	defer release()
	if err != nil {
		return err
	}
	path := d.join(rel)
	if err := failpoint.Hit("fsx.unlink"); err != nil {
		return pathErr("unlink", path, err)
	}
	kind := failpoint.FSUnlink
	if st, serr := lstatAt(pfd, name); serr == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR {
		kind = failpoint.FSRmdir
	}
	note(kind, path, "", false)
	err = retry(func() error { return unix.Unlinkat(pfd, name, 0) })
	if errors.Is(err, unix.EISDIR) || errors.Is(err, unix.EPERM) {
		if st, serr := lstatAt(pfd, name); serr == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR {
			err = retry(func() error { return unix.Unlinkat(pfd, name, unix.AT_REMOVEDIR) })
		}
	}
	if err != nil {
		return pathErr("unlink", path, err)
	}
	note(kind, path, "", true)
	return nil
}

func (d *Dir) removeEmptyDirs(rel, stopAt string) error {
	if err := d.alive(); err != nil {
		return err
	}
	parts, err := splitRel(rel)
	if err != nil {
		return err
	}
	stop, err := splitRel(stopAt)
	if err != nil {
		return err
	}
	if len(stop) > len(parts) || strings.Join(parts[:len(stop)], "/") != strings.Join(stop, "/") {
		return fmt.Errorf("%w: %q is not below %q", ErrUnsafe, rel, stopAt)
	}
	for n := len(parts); n > len(stop); n-- {
		pfd, release, err := d.walkTo(parts[:n-1], false)
		if errors.Is(err, fs.ErrNotExist) {
			release()
			continue
		}
		if err != nil {
			release()
			return err
		}
		path := d.join(strings.Join(parts[:n], "/"))
		if err := failpoint.Hit("fsx.unlink"); err != nil {
			release()
			return pathErr("rmdir", path, err)
		}
		note(failpoint.FSRmdir, path, "", false)
		err = retry(func() error { return unix.Unlinkat(pfd, parts[n-1], unix.AT_REMOVEDIR) })
		switch {
		case err == nil:
			note(failpoint.FSRmdir, path, "", true)
			serr := syncFD(pfd, filepath.Dir(path))
			release()
			if serr != nil {
				return serr
			}
		case errors.Is(err, unix.ENOENT):
			release()
		case errors.Is(err, unix.ENOTEMPTY), errors.Is(err, unix.EEXIST), errors.Is(err, unix.ENOTDIR):
			release()
			return nil // not empty (or not a directory): left alone
		default:
			release()
			return pathErr("rmdir", path, err)
		}
	}
	return nil
}

func (d *Dir) chtimes(rel string, mtime time.Time) error {
	fd, name, release, path, err := d.target(rel)
	defer release()
	if err != nil {
		return err
	}
	if err := failpoint.Hit("fsx.write"); err != nil {
		return pathErr("utimensat", path, err)
	}
	ts := unix.NsecToTimespec(mtime.UnixNano())
	if err := retry(func() error {
		return unix.UtimesNanoAt(fd, name, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW)
	}); err != nil {
		return pathErr("utimensat", path, err)
	}
	return nil
}

func (d *Dir) chmod(rel string, perm fs.FileMode) error {
	fd, name, release, path, err := d.target(rel)
	defer release()
	if err != nil {
		return err
	}
	if err := failpoint.Hit("fsx.write"); err != nil {
		return pathErr("chmod", path, err)
	}
	if err := chmodNoFollow(fd, name, uint32(perm.Perm()&0o700)); err != nil {
		if errors.Is(err, unix.ELOOP) {
			return unsafeErr(path, "symlink")
		}
		return pathErr("chmod", path, err)
	}
	return nil
}

// target resolves rel for calls that also accept the directory itself: the
// descriptor to act relative to and the final name ("." for d itself).
func (d *Dir) target(rel string) (int, string, func(), string, error) {
	if err := d.alive(); err != nil {
		return -1, "", func() {}, "", err
	}
	parts, err := splitRel(rel)
	if err != nil {
		return -1, "", func() {}, "", err
	}
	if len(parts) == 0 {
		return d.fd, ".", func() {}, d.path, nil
	}
	fd, name, release, err := d.parent(rel, false)
	return fd, name, release, d.join(rel), err
}

func (d *Dir) sync() error {
	if err := d.alive(); err != nil {
		return err
	}
	return syncFD(d.fd, d.path)
}

func (d *Dir) device() (uint64, error) {
	if err := d.alive(); err != nil {
		return 0, err
	}
	st, err := fstatFD(d.fd)
	if err != nil {
		return 0, pathErr("fstat", d.path, err)
	}
	return statFrom(&st).Dev, nil
}

// removeTree empties the directory fd without following any symlink: files,
// symlinks and special files are unlinked, subdirectories emptied
// recursively and removed.
func removeTree(fd int, path string, depth int) error {
	if depth >= maxWalkDepth {
		return unsafeErr(path, "directory tree too deep")
	}
	names, err := readNames(fd, path)
	if err != nil {
		return err
	}
	for _, name := range names {
		p := path + "/" + name
		st, err := lstatAt(fd, name)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return pathErr("lstat", p, err)
		}
		flags := 0
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			sub, err := openat(fd, name, oDirFlags, 0)
			if err != nil {
				return pathErr("openat", p, err)
			}
			err = removeTree(sub, p, depth+1)
			closeFD(sub)
			if err != nil {
				return err
			}
			flags = unix.AT_REMOVEDIR
		}
		if err := failpoint.Hit("fsx.unlink"); err != nil {
			return pathErr("unlink", p, err)
		}
		kind := failpoint.FSUnlink
		if flags != 0 {
			kind = failpoint.FSRmdir
		}
		note(kind, p, "", false)
		if err := retry(func() error { return unix.Unlinkat(fd, name, flags) }); err != nil && !errors.Is(err, unix.ENOENT) {
			return pathErr("unlink", p, err)
		}
		note(kind, p, "", true)
	}
	return nil
}

func statPath(path string) (Stat, error) {
	var st unix.Stat_t
	if err := retry(func() error { return unix.Stat(path, &st) }); err != nil {
		return Stat{}, pathErr("stat", path, err)
	}
	return statFrom(&st), nil
}

func mkdirOne(path string) error {
	if err := failpoint.Hit("fsx.write"); err != nil {
		return pathErr("mkdir", path, err)
	}
	if err := retry(func() error { return unix.Mkdir(path, 0o700) }); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return sentinelErr(ErrExist, "mkdir", path, err)
		}
		return pathErr("mkdir", path, err)
	}
	note(failpoint.FSMkdir, path, "", true)
	return nil
}

// fixDirMode sets a directory this process just created to exactly 0700
// (a umask may have removed owner bits), never following a symlink.
func fixDirMode(path string) error {
	fd, err := openat(unix.AT_FDCWD, path, oDirFlags, 0)
	if err != nil {
		return pathErr("open", path, err)
	}
	defer closeFD(fd)
	st, err := fstatFD(fd)
	if err != nil {
		return pathErr("fstat", path, err)
	}
	if st.Uid != euid() || st.Mode&0o7777 == 0o700 {
		return nil
	}
	if err := retry(func() error { return unix.Fchmod(fd, 0o700) }); err != nil {
		return pathErr("fchmod", path, err)
	}
	return nil
}

// removeStaging empties and removes the staging directory at path.
func removeStaging(s *Staging) error {
	if s.Dir != nil && s.Dir.open {
		if err := removeTree(s.Dir.fd, s.Path, 0); err != nil {
			return err
		}
		if err := s.Dir.close(); err != nil {
			return err
		}
	} else {
		d, err := openBase(s.Path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		err = removeTree(d.fd, s.Path, 0)
		_ = d.close()
		if err != nil {
			return err
		}
	}
	pfd, err := openat(unix.AT_FDCWD, filepath.Dir(s.Path), oDirFlags, 0)
	if err != nil {
		return pathErr("open", filepath.Dir(s.Path), err)
	}
	defer closeFD(pfd)
	if err := failpoint.Hit("fsx.unlink"); err != nil {
		return pathErr("rmdir", s.Path, err)
	}
	note(failpoint.FSRmdir, s.Path, "", false)
	if err := retry(func() error { return unix.Unlinkat(pfd, filepath.Base(s.Path), unix.AT_REMOVEDIR) }); err != nil && !errors.Is(err, unix.ENOENT) {
		return pathErr("rmdir", s.Path, err)
	}
	note(failpoint.FSRmdir, s.Path, "", true)
	return syncFD(pfd, filepath.Dir(s.Path))
}

// flockFn is the flock(2) used by ProbeHeld (a seam for ENOTSUP tests).
var flockFn = unix.Flock

func probeHeld(path string) (bool, error) {
	fd, err := openat(unix.AT_FDCWD, path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return true, unsafeErr(path, "symlink")
		}
		if errors.Is(err, unix.ENOENT) {
			// Lease and lock files are created before use and never
			// deleted (SPEC §9.3): a missing one was never held.
			return false, nil
		}
		return true, pathErr("open", path, err)
	}
	defer closeFD(fd)
	st, err := fstatFD(fd)
	if err != nil {
		return true, pathErr("fstat", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return true, unsafeErr(path, "not a regular file")
	}
	err = retry(func() error { return flockFn(fd, unix.LOCK_EX|unix.LOCK_NB) })
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return true, nil
	}
	if err != nil {
		return true, pathErr("flock", path, err) // ENOTSUP, ENOLCK…: cannot tell
	}
	_ = retry(func() error { return flockFn(fd, unix.LOCK_UN) })
	var cur unix.Stat_t
	if err := retry(func() error { return unix.Lstat(path, &cur) }); err != nil {
		return true, nil // unlinked during the probe: cannot tell (R17)
	}
	if cur.Dev != st.Dev || cur.Ino != st.Ino {
		return true, nil // recreated during the probe (R17)
	}
	return false, nil
}

func space(path string) (avail, total uint64, err error) {
	var sf unix.Statfs_t
	if err := retry(func() error { return unix.Statfs(path, &sf) }); err != nil {
		return 0, 0, pathErr("statfs", path, err)
	}
	a, t := statfsBytes(&sf)
	return a, t, nil
}

func classifyErrno(err error) Class {
	var errno unix.Errno
	if !errors.As(err, &errno) {
		return ClassOther
	}
	switch errno {
	case unix.ENOSPC, unix.EDQUOT, unix.EFBIG:
		return ClassNoSpace
	case unix.EACCES, unix.EPERM:
		return ClassAccess
	case unix.EROFS:
		return ClassReadOnly
	case unix.EBUSY, unix.ETXTBSY, unix.EDEADLK, unix.EAGAIN:
		return ClassBusy
	case unix.ELOOP, unix.EMLINK:
		return ClassUnsafe
	case unix.ENOENT, unix.ENOTDIR:
		return ClassMissing
	default:
		return ClassIO
	}
}
