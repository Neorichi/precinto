//go:build linux

package platform

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/precinto/precinto/internal/paths"
)

// diskEncryption is a best-effort check that the home directory lives on an
// encrypted file system: ecryptfs, or a device-mapper device that is, or
// sits on, a dm-crypt target. known=false when it cannot tell.
func diskEncryption(context.Context) (on, known bool, err error) {
	home, err := paths.UserHome(paths.FromOS())
	if err != nil {
		return false, false, nil
	}
	mounts, err := readSmall("/proc/self/mounts")
	if err != nil {
		return false, false, nil
	}
	src, fstype, ok := mountOf(mounts, home)
	if !ok {
		return false, false, nil
	}
	if fstype == "ecryptfs" {
		return true, true, nil
	}
	var st unix.Stat_t
	if err := unix.Stat(src, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return false, false, nil
	}
	dir := fmt.Sprintf("/sys/dev/block/%d:%d", unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)))
	if dmCrypt(dir, 0) {
		return true, true, nil
	}
	if strings.HasPrefix(filepath.Base(src), "dm-") || strings.HasPrefix(src, "/dev/mapper/") {
		return false, false, nil // device-mapper without a visible crypt layer: unsure
	}
	return false, true, nil
}

// mountOf returns the source and type of the mount holding p (longest
// mount point within p) from /proc/self/mounts.
func mountOf(mounts []byte, p string) (src, fstype string, ok bool) {
	best := -1
	sc := bufio.NewScanner(bytes.NewReader(mounts))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		mp := strings.ReplaceAll(f[1], `\040`, " ")
		if paths.Within(mp, p) && len(mp) > best {
			best, src, fstype, ok = len(mp), f[0], f[2], true
		}
	}
	return src, fstype, ok
}

// dmCrypt reports whether the block device at sysfs dir is a dm-crypt
// target or is stacked on one (LVM on LUKS).
func dmCrypt(dir string, depth int) bool {
	if depth > 8 {
		return false
	}
	if uuid, err := os.ReadFile(filepath.Join(dir, "dm", "uuid")); err == nil && bytes.HasPrefix(uuid, []byte("CRYPT-")) {
		return true
	}
	ents, err := os.ReadDir(filepath.Join(dir, "slaves"))
	if err != nil {
		return false
	}
	for _, e := range ents {
		if dmCrypt(filepath.Join("/sys/class/block", e.Name()), depth+1) {
			return true
		}
	}
	return false
}

// excludeFromBackup is a no-op on linux (no system backup to configure).
func excludeFromBackup(context.Context, string) error { return nil }

// spotlightIndexed: there is no Spotlight on linux.
func spotlightIndexed(context.Context, string) (indexed, known bool, err error) {
	return false, false, nil
}

// cloudRoots lists the synced folders client apps create in home.
func cloudRoots(home string) []string { return homeCloudRoots(home) }
