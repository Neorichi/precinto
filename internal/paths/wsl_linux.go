//go:build linux

package paths

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// The file reads of DetectWSL and CheckDrive (D155, D156); wsl.go
// interprets what they return.

func detectWSL() WSL { return wslFrom(readWSLFiles("/")) }

// readWSLFiles reads the WSL markers below root ("/" outside tests): the
// kernel's release strings and /run/WSL, and, only when they tell WSL,
// /etc/wsl.conf. A plain linux reads nothing more (D155).
func readWSLFiles(root string) wslFiles {
	at := func(p string) string { return filepath.Join(root, p) }
	f := wslFiles{
		osrelease: readSmallFile(at("/proc/sys/kernel/osrelease")),
		version:   readSmallFile(at("/proc/version")),
	}
	if st, err := os.Lstat(at("/run/WSL")); err == nil && st.IsDir() {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid == 0 {
			f.runWSL = true
		}
	}
	if wslVersion(string(f.osrelease), string(f.version), f.runWSL) == 0 {
		return f
	}
	b, err := readWhole(at("/etc/wsl.conf"), maxSmallFile)
	switch {
	case err == nil:
		f.wslConf = b
	case !errors.Is(err, fs.ErrNotExist):
		f.wslConfErr = true // unreadable or too long: interop unknown
	}
	return f
}

// maxSmallFile bounds the system files DetectWSL reads: /proc entries
// and root's /etc/wsl.conf.
const maxSmallFile = 64 << 10

// readSmallFile reads at most maxSmallFile bytes of a system file (nil
// when it cannot be read).
func readSmallFile(p string) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSmallFile))
	if err != nil {
		return nil
	}
	return b
}

// driveProbe reads the real system for CheckDrive.
var driveProbe = probe{
	resolve: resolveExisting,
	exists:  existingDir,
	// A mount table longer than 8 MiB is not read at all: the mount that
	// holds a path may be in the part left out (unknown, fail closed).
	mountinfo: func() ([]byte, error) { return readWhole("/proc/self/mountinfo", 8<<20) },
	statfs: func(p string) (uint32, error) {
		var st syscall.Statfs_t
		if err := syscall.Statfs(p, &st); err != nil {
			return 0, err
		}
		return uint32(st.Type), nil
	},
}
