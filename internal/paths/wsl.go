package paths

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Windows through WSL 2 (D155, D156). precinto runs inside a WSL 2
// distribution as the Linux binary it is. What it must know about WSL is
// read from the kernel and from WSL's own files, never from the
// environment, which an agent can set: the WSL generation (WSL 1 is
// refused), whether programs of the distribution can start Windows
// programs (interop), where the Windows drives are mounted, and which
// file system holds a path (a Windows drive mounted into WSL hides the
// Windows programs that write it from precinto). The parsing lives here,
// in pure functions every OS tests; wsl_linux.go only reads the files,
// and outside WSL only the kernel's release strings and /run/WSL.

// WSL is what precinto knows about the Windows Subsystem for Linux
// instance it runs in (D155). The zero value means "not WSL".
type WSL struct {
	// Version is 0 outside WSL, 1 under WSL 1 and 2 under WSL 2, from the
	// kernel's release and version strings and /run/WSL.
	Version int
	// Interop reports whether programs of this distribution can start
	// Windows programs: /etc/wsl.conf does not turn interop off ([interop]
	// enabled, true by default). The WSLInterop entry of binfmt_misc tells
	// nothing about it: under WSL 2 it is registered for the whole virtual
	// machine whatever a distribution's setting, and /init starts a
	// Windows program without it (run directly, it starts the program its
	// arguments name), as long as WSL runs this distribution's interop
	// servers, which the setting decides. A change of the setting applies
	// once WSL restarts the distribution. InteropKnown is false when
	// /etc/wsl.conf exists but could not be read.
	Interop      bool
	InteropKnown bool
	// MountRoot is the directory under which WSL mounts the Windows drives
	// ([automount] root of /etc/wsl.conf, default /mnt/); it ends in "/".
	MountRoot string
}

// DefaultWSLMountRoot is where WSL mounts the Windows drives unless
// /etc/wsl.conf says otherwise.
const DefaultWSLMountRoot = "/mnt/"

// DetectWSL returns the WSL facts of this system, read once per process
// (D155): on linux from /proc/sys/kernel/osrelease, /proc/version and
// /run/WSL, then, under WSL only, /etc/wsl.conf; elsewhere the zero WSL.
func DetectWSL() WSL {
	wslOnce.Do(func() { wslInfo = detectWSL() })
	return wslInfo
}

var (
	wslOnce sync.Once
	wslInfo WSL
)

// UsersFolder reports whether p lies in the Users folder of a Windows drive
// mounted into WSL: <MountRoot><drive letter>/Users or below, compared
// without case as the drives compare names. OneDrive, and its Known Folder
// Move of Desktop and Documents, sync files there (D156). It is always
// false outside WSL and for a relative p. The path is compared as given:
// callers pass a resolved path.
func (w WSL) UsersFolder(p string) bool {
	if w.Version == 0 || !filepath.IsAbs(p) {
		return false
	}
	root := w.MountRoot
	if root == "" {
		root = DefaultWSLMountRoot
	}
	rel, ok := strings.CutPrefix(filepath.Clean(p), filepath.Clean(root))
	if !ok {
		return false
	}
	if filepath.Clean(root) != "/" {
		if rel, ok = strings.CutPrefix(rel, "/"); !ok {
			return false // /mntx/… is not below /mnt
		}
	} else {
		rel = strings.TrimPrefix(rel, "/")
	}
	drive, rest, _ := strings.Cut(rel, "/")
	if len(drive) != 1 || !isASCIILetter(drive[0]) {
		return false
	}
	first, _, _ := strings.Cut(rest, "/")
	return strings.EqualFold(first, "Users")
}

func isASCIILetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// wslFiles is what wsl_linux.go reads for DetectWSL; wslFrom interprets it.
type wslFiles struct {
	osrelease []byte // /proc/sys/kernel/osrelease
	version   []byte // /proc/version
	runWSL    bool   // /run/WSL is a directory owned by root
	// wslConf is /etc/wsl.conf, nil when absent; wslConfErr reports one
	// that exists but could not be read whole. Read under WSL only.
	wslConf    []byte
	wslConfErr bool
}

// wslFrom interprets the files: the WSL generation, interop, mount root.
func wslFrom(f wslFiles) WSL {
	v := wslVersion(string(f.osrelease), string(f.version), f.runWSL)
	if v == 0 {
		return WSL{}
	}
	w := WSL{Version: v, MountRoot: wslMountRoot(f.wslConf)}
	if !f.wslConfErr {
		w.Interop, w.InteropKnown = wslInterop(f.wslConf), true
	}
	return w
}

// wslVersion classifies the kernel. WSL 2 runs a real Linux kernel built
// by Microsoft, whose release names it ("5.15.167.4-microsoft-standard-WSL2",
// older "4.19.128-microsoft-standard"); WSL 1 emulates Linux in the
// Windows kernel and reports "4.4.0-19041-Microsoft", built by
// "Microsoft@Microsoft.com". A custom WSL 2 kernel may name neither, but
// WSL still creates /run/WSL (as root) for its interop sockets; WSL 1
// always reports the Microsoft strings, so that alone means WSL 2.
func wslVersion(osrelease, version string, runWSL bool) int {
	rel := strings.TrimSpace(osrelease)
	low := strings.ToLower(rel)
	switch {
	case strings.Contains(low, "microsoft-standard") || strings.Contains(low, "-wsl2"):
		return 2
	case strings.Contains(rel, "-Microsoft") || strings.Contains(version, "Microsoft@Microsoft.com"):
		return 1
	case strings.Contains(low, "microsoft") || strings.Contains(strings.ToLower(version), "microsoft-standard"):
		return 2
	case runWSL:
		return 2
	}
	return 0
}

// wslMountRoot returns [automount] root of /etc/wsl.conf, the last
// absolute value (confValues); the result ends in "/" (WSL appends one),
// and is DefaultWSLMountRoot without a valid value.
func wslMountRoot(conf []byte) string {
	root := ""
	for _, v := range confValues(conf, "automount", "root") {
		if filepath.IsAbs(v) {
			root = v
		}
	}
	if root == "" {
		return DefaultWSLMountRoot
	}
	root = filepath.Clean(root)
	if root != "/" {
		root += "/"
	}
	return root
}

// wslInterop returns [interop] enabled of /etc/wsl.conf: the last value
// WSL reads as a boolean ("true" or "1", "false" or "0", without case for
// the words; WSL ignores any other), true when none.
func wslInterop(conf []byte) bool {
	enabled := true
	for _, v := range confValues(conf, "interop", "enabled") {
		switch {
		case v == "1" || strings.EqualFold(v, "true"):
			enabled = true
		case v == "0" || strings.EqualFold(v, "false"):
			enabled = false
		}
	}
	return enabled
}

// confValues returns, in order, the values of key in section of
// /etc/wsl.conf, read as WSL reads the file: section and key names without
// case, '#' starting a comment outside double quotes, quotes removed, \"
// and \\ escapes; a line WSL would skip (bad escape, open quote) is left
// out.
func confValues(conf []byte, section, key string) []string {
	var out []string
	cur := ""
	sc := bufio.NewScanner(bytes.NewReader(conf))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				cur = ""
				continue
			}
			cur = strings.ToLower(strings.TrimSpace(line[1:end]))
			continue
		}
		k, value, ok := strings.Cut(line, "=")
		if !ok || cur != section || !strings.EqualFold(strings.TrimSpace(k), key) {
			continue
		}
		if v, ok := confValue(value); ok {
			out = append(out, v)
		}
	}
	return out
}

// confValue unquotes one wsl.conf value: double quotes toggle quoting,
// '#' outside quotes ends the value, \" and \\ are escapes (other escapes
// make the line invalid, as WSL skips it); surrounding spaces are trimmed.
func confValue(s string) (string, bool) {
	var b strings.Builder
	quoted := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			quoted = !quoted
		case c == '\\':
			if i+1 >= len(s) || (s[i+1] != '"' && s[i+1] != '\\') {
				return "", false
			}
			i++
			b.WriteByte(s[i])
		case c == '#' && !quoted:
			return strings.TrimSpace(b.String()), true
		default:
			b.WriteByte(c)
		}
	}
	if quoted {
		return "", false
	}
	return strings.TrimSpace(b.String()), true
}

// ErrWindowsDrive marks a location precinto refuses under WSL because it
// lies on a Windows drive mounted into the distribution, or because
// precinto could not tell which file system holds it (D156): Windows
// programs write such files without precinto seeing them, so it never
// seals, restores or keeps its own files there.
var ErrWindowsDrive = errors.New("paths: on a Windows drive")

// DriveError is CheckDrive's refusal of one location.
type DriveError struct {
	Path    string // the location, as the caller named it
	Unknown bool   // precinto could not tell (Why and Err say why); refused all the same
	// Why is, when Unknown, what stopped CheckDrive, short and
	// content-free, for messages: "it is a dangling symlink", "the mount
	// table can't be read", …
	Why string
	Err error
}

func (e *DriveError) Error() string {
	if e.Unknown {
		return fmt.Sprintf("paths: cannot tell whether %s is on a Windows drive: %v", e.Path, e.Err)
	}
	return fmt.Sprintf("paths: %s is on a Windows drive", e.Path)
}

// Is makes errors.Is(err, ErrWindowsDrive) hold for every DriveError.
func (e *DriveError) Is(target error) bool { return target == ErrWindowsDrive }

func (e *DriveError) Unwrap() error { return e.Err }

// CheckDrive refuses a location on a Windows drive under WSL (D156): it
// returns nil outside WSL, without reading anything, and under WSL when p,
// with every symlink resolved (a link into a drive is the drive), lies on
// a Linux file system. Otherwise it returns a *DriveError: p is on a
// Windows drive (DrvFs: a 9p, drvfs or virtiofs mount, which under WSL
// only Windows shares use), or the mount table, the path or the file
// system of p could not be read (Unknown: fail closed). A p that does not
// exist yet is judged by its deepest existing parent. Callers check
// protected folders, harness homes and precinto's own directories with it.
func CheckDrive(p string) error { return checkDrive(DetectWSL(), p, driveProbe) }

// probe is how checkDrive reads the system; wsl_linux.go provides the real
// one and tests fake it.
type probe struct {
	resolve   func(p string) (string, error) // realpath of p, or of its deepest existing parent plus the rest
	exists    func(p string) (string, error) // deepest existing directory at or above a resolved path
	mountinfo func() ([]byte, error)         // /proc/self/mountinfo
	statfs    func(p string) (uint32, error) // statfs f_type of an existing directory
}

// checkDrive implements CheckDrive over an explicit WSL and probe.
func checkDrive(w WSL, p string, pr probe) error {
	if w.Version == 0 {
		return nil
	}
	unknown := func(why string, err error) error { return &DriveError{Path: p, Unknown: true, Why: why, Err: err} }
	if !filepath.IsAbs(p) {
		return unknown("it is not an absolute path", errors.New("the path is not absolute"))
	}
	real, err := pr.resolve(filepath.Clean(p))
	if err != nil {
		return unknown(resolveWhy(err), err)
	}
	b, err := pr.mountinfo()
	if err != nil {
		return unknown("the mount table can't be read", err)
	}
	m, ok := mountOf(parseMountinfo(b), real)
	if !ok {
		return unknown("no mount holds it", errors.New("no mount holds the path"))
	}
	magic, merr := uint32(0), errors.New("not measured")
	if dir, err := pr.exists(real); err == nil {
		magic, merr = pr.statfs(dir)
	}
	windows, known := driveVerdict(m.fstype, magic, merr == nil)
	switch {
	case !known:
		return unknown("the mount table and the file system disagree", fmt.Errorf("the mount table says %s but the file system says otherwise", m.fstype))
	case windows:
		return &DriveError{Path: p}
	}
	return nil
}

// errDangling marks a path whose last existing component is a symlink to
// nothing: its target could still be created anywhere.
var errDangling = errors.New("paths: a dangling symlink")

// resolveWhy names, for DriveError.Why, why a path could not be resolved.
func resolveWhy(err error) string {
	switch {
	case errors.Is(err, errDangling):
		return "it is a dangling symlink"
	case errors.Is(err, fs.ErrPermission):
		return "it or a folder above it can't be read"
	case errors.Is(err, syscall.ELOOP):
		return "its symlinks loop"
	case errors.Is(err, syscall.ENOTDIR):
		return "a file stands where a folder of its path should be"
	}
	return "its path can't be resolved"
}

// Magic numbers of statfs f_type (linux/magic.h).
const (
	v9fsMagic = 0x01021997 // 9p: WSL 2's DrvFs over Plan 9
	fuseMagic = 0x65735546 // FUSE, and virtiofs, which is FUSE in the kernel
)

// windowsFS reports whether a mount of fstype holds Windows files under
// WSL: drvfs (WSL 1), 9p (WSL 2's DrvFs, aname=drvfs; WSL's other 9p
// shares come from the Windows host too) and virtiofs (WSL 2's DrvFs when
// virtiofs is on). Only meaningful under WSL: on plain linux these file
// systems are ordinary.
func windowsFS(fstype string) bool {
	switch fstype {
	case "drvfs", "9p", "virtiofs":
		return true
	}
	return false
}

// fuseFS reports whether statfs may report fuseMagic for fstype.
func fuseFS(fstype string) bool {
	return fstype == "fuse" || fstype == "fuseblk" || strings.HasPrefix(fstype, "fuse.") || fstype == "virtiofs"
}

// driveVerdict combines the mount table's type with the statfs magic, a
// hint only (D156): a Windows type is a Windows drive; a 9p magic is one
// whatever the table says; a FUSE magic on a type that is not FUSE (or
// virtiofs) means the two reads disagree, which is unknown.
func driveVerdict(fstype string, magic uint32, haveMagic bool) (windows, known bool) {
	switch {
	case windowsFS(fstype):
		return true, true
	case haveMagic && magic == v9fsMagic:
		return true, true
	case haveMagic && magic == fuseMagic && !fuseFS(fstype):
		return false, false
	}
	return false, true
}

// mountEntry is one line of /proc/self/mountinfo.
type mountEntry struct {
	point  string // mount point, unescaped
	fstype string
	source string
	super  string // super options (9p: aname=drvfs;path=C:\…)
}

// parseMountinfo parses /proc/self/mountinfo (proc(5)): "ID PARENT
// MAJ:MIN ROOT POINT OPTIONS [OPTIONAL…] - FSTYPE SOURCE SUPER". Lines
// that do not have that shape are skipped.
func parseMountinfo(b []byte) []mountEntry {
	var out []mountEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || len(f) < sep+3 {
			continue
		}
		e := mountEntry{point: unescapeMount(f[4]), fstype: f[sep+1], source: unescapeMount(f[sep+2])}
		if len(f) > sep+3 {
			e.super = unescapeMount(strings.Join(f[sep+3:], " "))
		}
		if !filepath.IsAbs(e.point) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// unescapeMount undoes the kernel's octal escapes of space, tab, newline
// and backslash in mountinfo fields (\040, \011, \012, \134).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mountOf returns the mount that holds p: the longest mount point at or
// above p, the last one listed when several share it (a later mount hides
// an earlier one).
func mountOf(ms []mountEntry, p string) (mountEntry, bool) {
	best, found := mountEntry{}, false
	for _, m := range ms {
		if !Within(m.point, p) {
			continue
		}
		if !found || len(components(filepath.Clean(m.point))) >= len(components(filepath.Clean(best.point))) {
			best, found = m, true
		}
	}
	return best, found
}

// resolveExisting returns the realpath of p, or, when p does not exist yet,
// the realpath of its deepest existing parent joined with the rest. Any
// other error (a component that cannot be read, a symlink loop) is
// returned: the caller cannot tell where p lies.
func resolveExisting(p string) (string, error) {
	rest := ""
	for cur := filepath.Clean(p); ; cur = filepath.Dir(cur) {
		real, err := filepath.EvalSymlinks(cur)
		if err == nil {
			if rest == "" {
				return real, nil
			}
			return filepath.Join(real, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) || filepath.Dir(cur) == cur {
			return "", err
		}
		// Only a missing final component may be skipped: a dangling
		// symlink would name a target that can still be created.
		if _, lerr := os.Lstat(cur); lerr == nil {
			return "", fmt.Errorf("%w: %s", errDangling, cur)
		}
		rest = filepath.Join(filepath.Base(cur), rest)
	}
}

// errTooLong: a file is longer than its reader's bound, so a part of it
// that matters may be missing.
var errTooLong = errors.New("paths: file too long to read whole")

// readWhole reads all of a file of at most max bytes; a longer one is
// errTooLong.
func readWhole(p string, max int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errTooLong
	}
	return b, nil
}

// existingDir returns the deepest existing directory at or above p (a
// resolved path), for statfs.
func existingDir(p string) (string, error) {
	for cur := filepath.Clean(p); ; cur = filepath.Dir(cur) {
		if st, err := os.Stat(cur); err == nil {
			if st.IsDir() {
				return cur, nil
			}
			return filepath.Dir(cur), nil
		} else if !errors.Is(err, fs.ErrNotExist) || filepath.Dir(cur) == cur {
			return "", err
		}
	}
}
