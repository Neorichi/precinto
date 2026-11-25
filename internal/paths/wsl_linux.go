//go:build linux

package paths

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// The file reads of DetectWSL and CheckDrive (D155, D156); wsl.go
// interprets what they return.

func detectWSL() WSL { return wslFrom(readWSLFiles("/")) }

// readWSLFiles reads the WSL markers below root ("/" outside tests).
func readWSLFiles(root string) wslFiles {
	at := func(p string) string { return filepath.Join(root, p) }
	f := wslFiles{
		osrelease: readSmallFile(at("/proc/sys/kernel/osrelease")),
		version:   readSmallFile(at("/proc/version")),
		wslConf:   readSmallFile(at("/etc/wsl.conf")),
	}
	if st, err := os.Lstat(at("/run/WSL")); err == nil && st.IsDir() {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid == 0 {
			f.runWSL = true
		}
	}
	if ents, err := os.ReadDir(at("/proc/sys/fs/binfmt_misc")); err == nil {
		f.binfmt = map[string][]byte{}
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "WSLInterop") {
				f.binfmt[e.Name()] = readSmallFile(at("/proc/sys/fs/binfmt_misc/" + e.Name()))
			}
		}
	}
	return f
}

// readSmallFile reads at most 64 KiB of a system file (nil when it cannot
// be read): /proc entries and root's /etc/wsl.conf.
func readSmallFile(p string) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil
	}
	return b
}

// driveProbe reads the real system for CheckDrive.
var driveProbe = probe{
	resolve: resolveExisting,
	exists:  existingDir,
	mountinfo: func() ([]byte, error) {
		f, err := os.Open("/proc/self/mountinfo")
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, 8<<20))
	},
	statfs: func(p string) (uint32, error) {
		var st syscall.Statfs_t
		if err := syscall.Statfs(p, &st); err != nil {
			return 0, err
		}
		return uint32(st.Type), nil
	},
}
