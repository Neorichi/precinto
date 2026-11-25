package paths

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// Kernel strings as WSL reports them (Microsoft's WSL documentation and
// the microsoft/WSL issue tracker) and as plain distributions do.
const (
	wsl1Release = "4.4.0-19041-Microsoft\n"
	wsl1Version = "Linux version 4.4.0-19041-Microsoft (Microsoft@Microsoft.com) (gcc version 5.4.0 (GCC) ) #1237-Microsoft Sat Sep 11 14:32:00 PST 2021\n"
	wsl2Release = "5.15.167.4-microsoft-standard-WSL2\n"
	wsl2Version = "Linux version 5.15.167.4-microsoft-standard-WSL2 (root@buildhost) (gcc (GCC) 11.2.0, GNU ld (GNU Binutils) 2.37) #1 SMP Tue Nov 5 00:21:55 UTC 2024\n"
	ubuntuRel   = "6.8.0-45-generic\n"
	ubuntuVer   = "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-075) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024\n"
)

// D155: WSL 1 against WSL 2 against plain linux, from osrelease,
// /proc/version and /run/WSL.
func TestWSLVersion(t *testing.T) {
	for _, c := range []struct {
		name, rel, ver string
		runWSL         bool
		want           int
	}{
		{"wsl1", wsl1Release, wsl1Version, true, 1},
		{"wsl1 newer build", "4.4.0-22621-Microsoft", "", false, 1},
		{"wsl1 by version only", "4.4.0-1", wsl1Version, false, 1},
		{"wsl2", wsl2Release, wsl2Version, true, 2},
		{"wsl2 without /run/WSL", wsl2Release, wsl2Version, false, 2},
		{"wsl2 older kernel", "4.19.128-microsoft-standard", "", false, 2},
		{"wsl2 5.10", "5.10.16.3-microsoft-standard-WSL2", "", false, 2},
		{"wsl2 6.6", "6.6.87.2-microsoft-standard-WSL2", "", false, 2},
		{"wsl2 custom build", "6.1.21.2-microsoft-standard-WSL2+", "", false, 2},
		{"wsl2 custom kernel named otherwise", "6.8.12-custom", "Linux version 6.8.12-custom (me@box)", true, 2},
		{"ubuntu", ubuntuRel, ubuntuVer, false, 0},
		{"azure vm", "5.15.0-1073-azure", "Linux version 5.15.0-1073-azure (buildd@lcy02-amd64-048)", false, 0},
		{"azure linux", "5.15.153.1-2.cm2", "", false, 0},
		{"empty", "", "", false, 0},
	} {
		if got := wslVersion(c.rel, c.ver, c.runWSL); got != c.want {
			t.Errorf("%s: wslVersion = %d, want %d", c.name, got, c.want)
		}
	}
}

// D155: interop follows [interop] enabled of /etc/wsl.conf (true unless
// set false), as WSL decides whether it runs the distribution's interop
// servers; WSL 2's WSLInterop binfmt entry is the whole virtual machine's
// and is not read. Unknown only when wsl.conf exists but cannot be read.
func TestWSLFromInterop(t *testing.T) {
	base := wslFiles{osrelease: []byte(wsl2Release), version: []byte(wsl2Version)}
	for _, c := range []struct {
		name      string
		conf      string
		confErr   bool
		on, known bool
	}{
		{"no wsl.conf", "", false, true, true},
		{"no interop section", "[automount]\nroot = /\n", false, true, true},
		{"enabled", "[interop]\nenabled = true\n", false, true, true},
		{"disabled", "[interop]\nenabled = false\n", false, false, true},
		{"disabled by 0", "[interop]\nenabled=0\n", false, false, true},
		{"case of the word and names", "[Interop]\nEnabled = FALSE\n", false, false, true},
		{"quoted, with a comment", "[interop]\nenabled = \"false\" # no Windows programs\n", false, false, true},
		{"last valid wins", "[interop]\nenabled = false\nenabled = true\n", false, true, true},
		{"invalid value ignored", "[interop]\nenabled = false\nenabled = no\n", false, false, true},
		{"only invalid", "[interop]\nenabled = off\n", false, true, true},
		{"other section's enabled", "[automount]\nenabled = false\n", false, true, true},
		{"appendWindowsPath only", "[interop]\nappendWindowsPath = false\n", false, true, true},
		{"commented out", "[interop]\n# enabled = false\n", false, true, true},
		{"unreadable", "", true, false, false},
	} {
		f := base
		f.wslConf, f.wslConfErr = []byte(c.conf), c.confErr
		w := wslFrom(f)
		if w.Version != 2 || w.Interop != c.on || w.InteropKnown != c.known {
			t.Errorf("%s: %+v, want interop %v known %v", c.name, w, c.on, c.known)
		}
	}
	if w := wslFrom(wslFiles{osrelease: []byte(ubuntuRel), version: []byte(ubuntuVer), wslConf: []byte("[interop]\nenabled = true\n")}); w != (WSL{}) {
		t.Errorf("plain linux: %+v, want the zero WSL", w)
	}
}

// readWhole reads a file whole or not at all: a file longer than the
// bound (a mount table of more than 8 MiB, an oversized wsl.conf) is an
// error, never a truncated read (D156).
func TestReadWhole(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readWhole(p, 10); err != nil || string(b) != "0123456789" {
		t.Fatalf("at the bound: %q, %v", b, err)
	}
	if b, err := readWhole(p, 9); !errors.Is(err, errTooLong) || b != nil {
		t.Fatalf("over the bound: %q, %v", b, err)
	}
	if _, err := readWhole(filepath.Join(filepath.Dir(p), "missing"), 10); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
}

// D156: [automount] root of /etc/wsl.conf, read as WSL reads it.
func TestWSLMountRoot(t *testing.T) {
	for _, c := range []struct{ name, conf, want string }{
		{"absent", "", "/mnt/"},
		{"no automount section", "[interop]\nenabled = false\n", "/mnt/"},
		{"root slash", "[automount]\nroot = /\n", "/"},
		{"no trailing slash", "[automount]\nroot = /windir\n", "/windir/"},
		{"quoted", "[automount]\nroot = \"/win/\"\n", "/win/"},
		{"trailing comment", "[automount]\nroot = /drives/ # where the drives go\n", "/drives/"},
		{"case of names", "[AutoMount]\nRoot=/x/\n", "/x/"},
		{"last wins", "[automount]\nroot = /a/\nroot = /b/\n", "/b/"},
		{"relative ignored", "[automount]\nroot = mnt/\n", "/mnt/"},
		{"other section's root", "[boot]\nroot = /nope/\n[automount]\nenabled = true\n", "/mnt/"},
		{"unterminated quote", "[automount]\nroot = \"/x/\n", "/mnt/"},
		{"bad escape", "[automount]\nroot = /a\\q/\n", "/mnt/"},
		{"escaped quote", "[automount]\nroot = \"/a\\\\b/\"\n", "/a\\b/"},
		{"comment line", "# [automount]\n# root = /c/\n", "/mnt/"},
		{"options too", "[automount]\nenabled = true\nroot = /\noptions = \"metadata,umask=22,fmask=11\"\n", "/"},
		{"unclean", "[automount]\nroot = //mnt//\n", "/mnt/"},
	} {
		if got := wslMountRoot([]byte(c.conf)); got != c.want {
			t.Errorf("%s: wslMountRoot = %q, want %q", c.name, got, c.want)
		}
	}
	w := wslFrom(wslFiles{osrelease: []byte(wsl2Release), wslConf: []byte("[automount]\nroot = /\n")})
	if w.MountRoot != "/" {
		t.Errorf("wslFrom mount root %q", w.MountRoot)
	}
}

// D156: <automount root>/<drive>/Users/** is synced by OneDrive and Known
// Folder Move.
func TestUsersFolder(t *testing.T) {
	wsl := WSL{Version: 2, MountRoot: "/mnt/"}
	top := WSL{Version: 2, MountRoot: "/"}
	for _, c := range []struct {
		w    WSL
		p    string
		want bool
	}{
		{wsl, "/mnt/c/Users/Public/key.txt", true},
		{wsl, "/mnt/c/Users", true},
		{wsl, "/mnt/d/users/someone/OneDrive/Documents", true},
		{wsl, "/mnt/C/USERS/x", true},
		{wsl, "/mnt/c/Windows/Temp", false},
		{wsl, "/mnt/c", false},
		{wsl, "/mnt/cd/Users/x", false},
		{wsl, "/mnt/wsl/Users/x", false},
		{wsl, "/mntc/Users/x", false},
		{wsl, "/home/u/Users/x", false},
		{wsl, "mnt/c/Users/x", false},
		{wsl, "/mnt/c/Users/../Windows", false},
		{top, "/c/Users/Public", true},
		{top, "/mnt/c/Users/Public", false},
		{WSL{Version: 2}, "/mnt/c/Users/x", true}, // the default root
		{WSL{}, "/mnt/c/Users/x", false},
	} {
		if got := c.w.UsersFolder(c.p); got != c.want {
			t.Errorf("%+v UsersFolder(%q) = %v, want %v", c.w, c.p, got, c.want)
		}
	}
}

// mountinfo of a WSL 2 distribution (systemd, WSLg, two drives over 9p),
// in the kernel's format: the backslash of "C:\" is escaped as \134.
const wsl2Mountinfo = `55 60 8:48 / / rw,relatime - ext4 /dev/sdd rw,discard,errors=remount-ro,data=ordered
56 55 0:5 / /mnt/wsl rw,relatime shared:1 - tmpfs none rw
57 55 0:58 / /usr/lib/wsl/drivers ro,nosuid,nodev,noatime - 9p drivers ro,dirsync,aname=drivers;fmask=222;dmask=222,mmap,access=client,msize=65536,trans=fd,rfd=7,wfd=7
58 55 0:59 / /usr/lib/wsl/lib rw,relatime - overlay none rw,lowerdir=/gpu_lib_packaged:/gpu_lib_inbox,upperdir=/gpu_lib/rw/upper,workdir=/gpu_lib/rw/work
59 55 0:62 / /mnt/wslg rw,relatime - tmpfs none rw
60 59 8:48 / /mnt/wslg/distro ro,relatime - ext4 /dev/sdd rw,discard,errors=remount-ro,data=ordered
61 55 0:65 / /mnt/c rw,noatime - 9p C:\134 rw,dirsync,aname=drvfs;path=C:\134;uid=1000;gid=1000;symlinkroot=/mnt/,mmap,access=client,msize=65536,trans=fd,rfd=5,wfd=5
62 55 0:66 / /mnt/d rw,noatime - 9p D:\134 rw,dirsync,aname=drvfs;path=D:\134;uid=1000;gid=1000;symlinkroot=/mnt/,mmap,access=client,msize=65536,trans=fd,rfd=5,wfd=5
63 55 0:67 / /home/u/My\040Drive rw,nosuid,nodev,relatime - fuse.rclone remote: rw,user_id=1000,group_id=1000
64 55 0:68 / /mnt/e rw,relatime - virtiofs drvfs rw
65 55 0:69 /work /home/u/win-work rw,noatime - 9p C:\134 rw,dirsync,aname=drvfs;path=C:\134;uid=1000;gid=1000,mmap,access=client,msize=65536,trans=fd,rfd=5,wfd=5
`

// The same in WSL 1, where the drives are drvfs.
const wsl1Mountinfo = `1 0 0:2 / / rw,relatime - lxfs rootfs rw
2 1 0:4 / /mnt/c rw,noatime - drvfs C: rw,uid=1000,gid=1000,case=off
`

func TestParseMountinfo(t *testing.T) {
	ms := parseMountinfo([]byte(wsl2Mountinfo + "malformed line\n7 6 0:1 / relative rw - ext4 x rw\n"))
	if len(ms) != 11 {
		t.Fatalf("%d entries, want 11: %+v", len(ms), ms)
	}
	c := ms[6]
	if c.point != "/mnt/c" || c.fstype != "9p" || c.source != `C:\` || !strings.Contains(c.super, `aname=drvfs;path=C:\;`) {
		t.Errorf("drive C: %+v", c)
	}
	if ms[8].point != "/home/u/My Drive" || ms[8].fstype != "fuse.rclone" {
		t.Errorf("escaped mount point: %+v", ms[8])
	}
	if ms[1].point != "/mnt/wsl" || ms[1].fstype != "tmpfs" {
		t.Errorf("optional fields: %+v", ms[1])
	}
	if got := unescapeMount(`a\040b\011c\134d\777e\04`); got != "a b\tc\\d\\777e\\04" {
		t.Errorf("unescapeMount = %q", got)
	}
}

func TestMountOf(t *testing.T) {
	ms := parseMountinfo([]byte(wsl2Mountinfo))
	for p, want := range map[string]string{
		"/mnt/c/Users/Public":       "9p",
		"/mnt/c":                    "9p",
		"/mnt/cx/file":              "ext4",
		"/mnt/wslg/distro/home":     "ext4",
		"/mnt/wslg/runtime-dir":     "tmpfs",
		"/home/u/work":              "ext4",
		"/home/u/win-work/notes.md": "9p",
		"/home/u/My Drive/f":        "fuse.rclone",
		"/mnt/e/x":                  "virtiofs",
		"/usr/lib/wsl/drivers/x":    "9p",
		"/":                         "ext4",
	} {
		m, ok := mountOf(ms, p)
		if !ok || m.fstype != want {
			t.Errorf("mountOf(%q) = %+v, %v; want %s", p, m, ok, want)
		}
	}
	// A later mount on the same point hides the earlier one.
	stacked := parseMountinfo([]byte(wsl2Mountinfo + "70 61 0:80 / /mnt/c rw,relatime - tmpfs none rw\n"))
	if m, _ := mountOf(stacked, "/mnt/c/x"); m.fstype != "tmpfs" {
		t.Errorf("overmount: %+v", m)
	}
	if _, ok := mountOf(nil, "/x"); ok {
		t.Error("an empty mount table holds a path")
	}
	if m, _ := mountOf(parseMountinfo([]byte(wsl1Mountinfo)), "/mnt/c/work"); m.fstype != "drvfs" {
		t.Errorf("WSL 1 drive: %+v", m)
	}
}

// D156: the mount table decides; statfs is a hint that can only add a
// Windows drive or an inconsistency.
func TestDriveVerdict(t *testing.T) {
	const ext4 = 0xef53
	for _, c := range []struct {
		fstype    string
		magic     uint32
		haveMagic bool
		windows   bool
		known     bool
	}{
		{"9p", v9fsMagic, true, true, true},
		{"9p", 0, false, true, true},
		{"drvfs", 0, false, true, true},
		{"virtiofs", fuseMagic, true, true, true},
		{"ext4", ext4, true, false, true},
		{"ext4", 0, false, false, true},
		{"ext4", v9fsMagic, true, true, true},
		{"ext4", fuseMagic, true, false, false},
		{"tmpfs", fuseMagic, true, false, false},
		{"fuse.rclone", fuseMagic, true, false, true},
		{"fuse", fuseMagic, true, false, true},
		{"fuseblk", fuseMagic, true, false, true},
		{"overlay", 0x794c7630, true, false, true},
		// A Windows share mounted with mount.cifs (SMB): Windows writes it.
		{"cifs", 0xff534d42, true, true, true},
		{"smb3", 0xfe534d42, true, true, true},
	} {
		w, k := driveVerdict(c.fstype, c.magic, c.haveMagic)
		if w != c.windows || k != c.known {
			t.Errorf("driveVerdict(%s, %#x, %v) = %v, %v; want %v, %v", c.fstype, c.magic, c.haveMagic, w, k, c.windows, c.known)
		}
	}
}

// fakeProbe answers CheckDrive's reads from a mountinfo text, a symlink
// table and a statfs table.
func fakeProbe(mountinfo string, links map[string]string, magic map[string]uint32) probe {
	return probe{
		resolve: func(p string) (string, error) {
			for from, to := range links {
				if Within(from, p) {
					rel, _ := filepath.Rel(from, p)
					return filepath.Join(to, rel), nil
				}
			}
			return p, nil
		},
		exists: func(p string) (string, error) { return p, nil },
		mountinfo: func() ([]byte, error) {
			if mountinfo == "" {
				return nil, fs.ErrPermission
			}
			return []byte(mountinfo), nil
		},
		statfs: func(p string) (uint32, error) {
			for dir, m := range magic {
				if Within(dir, p) {
					return m, nil
				}
			}
			return 0xef53, nil
		},
	}
}

func TestCheckDrive(t *testing.T) {
	wsl := WSL{Version: 2, MountRoot: "/mnt/"}
	pr := fakeProbe(wsl2Mountinfo, map[string]string{"/home/u/link-to-c": "/mnt/c/Users/Public/proj"},
		map[string]uint32{"/mnt/c": v9fsMagic, "/mnt/d": v9fsMagic, "/mnt/e": fuseMagic, "/home/u/My Drive": fuseMagic})

	// Outside WSL nothing is read and everything passes.
	panics := probe{
		resolve:   func(string) (string, error) { panic("resolve read outside WSL") },
		exists:    func(string) (string, error) { panic("exists read outside WSL") },
		mountinfo: func() ([]byte, error) { panic("mountinfo read outside WSL") },
		statfs:    func(string) (uint32, error) { panic("statfs read outside WSL") },
	}
	if err := checkDrive(WSL{}, "/mnt/c/Users/Public", panics); err != nil {
		t.Fatalf("outside WSL: %v", err)
	}

	for _, c := range []struct {
		p       string
		windows bool
		unknown bool
	}{
		{"/home/u/work", false, false},
		{"/mnt/c/Users/Public/proj", true, false},
		{"/mnt/d", true, false},
		{"/mnt/e/data", true, false},
		{"/home/u/link-to-c/sub", true, false}, // a link into a drive is the drive
		{"/home/u/win-work/x", true, false},    // a bind mount of a drive
		{"/home/u/My Drive/x", false, false},   // a user's FUSE mount is not a drive
		{"/usr/lib/wsl/drivers", true, false},  // WSL's other 9p shares come from Windows too
		{"relative/path", false, true},
	} {
		err := checkDrive(wsl, c.p, pr)
		var de *DriveError
		switch {
		case !c.windows && !c.unknown:
			if err != nil {
				t.Errorf("%s: %v, want nil", c.p, err)
			}
		case !errors.As(err, &de) || !errors.Is(err, ErrWindowsDrive) || de.Unknown != c.unknown || de.Path != c.p:
			t.Errorf("%s: %v (%+v), want a DriveError (unknown %v)", c.p, err, de, c.unknown)
		}
	}

	// Fail closed: an unreadable mount table, a path that cannot be
	// resolved, a statfs that contradicts the table; Why says which, in
	// words that hold no path (F7).
	why := func(err error) string {
		var de *DriveError
		if !errors.As(err, &de) || !de.Unknown {
			return "not unknown"
		}
		return de.Why
	}
	noTable := fakeProbe("", nil, nil)
	if err := checkDrive(wsl, "/home/u/work", noTable); !isUnknownDrive(err) || why(err) != "the mount table can't be read" {
		t.Errorf("unreadable mountinfo: %v (%q)", err, why(err))
	}
	broken := pr
	for e, want := range map[error]string{
		fs.ErrPermission:                  "it or a folder above it can't be read",
		fmt.Errorf("%w: /x", errDangling): "it is a dangling symlink",
		syscall.ELOOP:                     "its symlinks loop",
		syscall.ENOTDIR:                   "a file stands where a folder of its path should be",
		syscall.EIO:                       "its path can't be resolved",
	} {
		broken.resolve = func(string) (string, error) { return "", e }
		if err := checkDrive(wsl, "/home/u/work", broken); !isUnknownDrive(err) || why(err) != want {
			t.Errorf("unresolvable path (%v): %v (%q), want %q", e, err, why(err), want)
		}
	}
	odd := fakeProbe(wsl2Mountinfo, nil, map[string]uint32{"/home/u/odd": fuseMagic})
	if err := checkDrive(wsl, "/home/u/odd", odd); !isUnknownDrive(err) || why(err) != "the mount table and the file system disagree" {
		t.Errorf("FUSE magic on an ext4 entry: %v", err)
	}
	if err := checkDrive(wsl, "relative/path", pr); why(err) != "it is not an absolute path" {
		t.Errorf("relative: %v", err)
	}
	ninep := fakeProbe(wsl2Mountinfo, nil, map[string]uint32{"/home/u/odd": v9fsMagic})
	if err := checkDrive(wsl, "/home/u/odd", ninep); err == nil || isUnknownDrive(err) {
		t.Errorf("9p magic on an ext4 entry: %v, want a Windows drive", err)
	}
	unmeasured := pr
	unmeasured.statfs = func(string) (uint32, error) { return 0, fs.ErrPermission }
	if err := checkDrive(wsl, "/home/u/work", unmeasured); err != nil {
		t.Errorf("statfs failing on ext4: %v (the table decides)", err)
	}
	if err := checkDrive(wsl, "/mnt/c/x", unmeasured); err == nil {
		t.Error("statfs failing on a drive: accepted")
	}
	if err := checkDrive(WSL{Version: 1}, "/mnt/c/work", fakeProbe(wsl1Mountinfo, nil, nil)); err == nil {
		t.Error("WSL 1 drvfs drive: accepted")
	}
}

func isUnknownDrive(err error) bool {
	var de *DriveError
	return errors.As(err, &de) && de.Unknown && errors.Is(err, ErrWindowsDrive)
}

func TestDriveErrorText(t *testing.T) {
	if got := (&DriveError{Path: "/mnt/c/x"}).Error(); got != "paths: /mnt/c/x is on a Windows drive" {
		t.Errorf("Error() = %q", got)
	}
	e := &DriveError{Path: "/x", Unknown: true, Err: fs.ErrPermission}
	if !strings.Contains(e.Error(), "cannot tell whether /x is on a Windows drive") || !errors.Is(e, fs.ErrPermission) {
		t.Errorf("unknown: %q", e.Error())
	}
}

// resolveExisting follows every symlink of the existing part of a path
// and keeps the missing tail.
func TestResolveExisting(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		real:                                 filepath.Join(real),
		filepath.Join(link, "sub"):           filepath.Join(real, "sub"),
		filepath.Join(link, "new", "deeper"): filepath.Join(real, "new", "deeper"),
		filepath.Join(dir, "missing"):        filepath.Join(dir, "missing"),
	} {
		got, err := resolveExisting(in)
		if err != nil || got != want {
			t.Errorf("resolveExisting(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveExisting(filepath.Join(dangling, "x")); !errors.Is(err, errDangling) {
		t.Errorf("a path below a dangling symlink: %v", err)
	}
	if got, err := existingDir(filepath.Join(real, "sub", "file", "more")); err != nil || got != filepath.Join(real, "sub") {
		t.Errorf("existingDir = %q, %v", got, err)
	}
}

// D156: NewLayout refuses a base or run directory on a Windows drive and
// still returns the layout for status and doctor.
func TestCheckLayoutDrives(t *testing.T) {
	l, err := LayoutAt("/mnt/c/Users/Public/.local/share/precinto", "/run/user/1000/precinto")
	if err != nil {
		t.Fatal(err)
	}
	onC := func(p string) error {
		if Within("/mnt/c", p) {
			return &DriveError{Path: p}
		}
		return nil
	}
	var checked []string
	record := func(p string) error { checked = append(checked, p); return onC(p) }
	if err := checkLayoutDrives(l, record); !errors.Is(err, ErrWindowsDrive) {
		t.Fatalf("base on C: %v", err)
	}
	l2, _ := LayoutAt("/home/u/.local/share/precinto", "/mnt/c/run")
	if err := checkLayoutDrives(l2, onC); !errors.Is(err, ErrWindowsDrive) {
		t.Fatalf("run dir on C: %v", err)
	}
	checked = nil
	l3, _ := LayoutAt("/home/u/.local/share/precinto", "/home/u/.local/share/precinto/run")
	if err := checkLayoutDrives(l3, record); err != nil || len(checked) != 1 {
		t.Fatalf("run dir inside the base: %v, checked %v", err, checked)
	}
	// Outside WSL NewLayout is unchanged.
	if runtime.GOOS != "linux" || DetectWSL().Version == 0 {
		if _, err := NewLayout(FromMap(map[string]string{"HOME": "/mnt/c/Users/Public"})); err != nil {
			t.Fatalf("NewLayout outside WSL: %v", err)
		}
	}
}
