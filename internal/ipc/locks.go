package ipc

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// procLock is one granted lock of /proc/locks.
type procLock struct {
	kind   string // FLOCK, POSIX, OFDLCK, LEASE, DELEG
	write  bool   // an exclusive (WRITE) lock
	pid    int    // the locker as the kernel recorded it (-1 for OFD locks)
	major  uint64
	minor  uint64
	inode  uint64
	hasDev bool
}

// parseProcLocks reads /proc/locks: one granted lock per line,
//
//	1: FLOCK  ADVISORY  WRITE 4242 00:2a:1234 0 EOF
//
// (major and minor in hex, the inode in decimal, "<none>:0" without an
// inode). Lines of blocked waiters ("1: -> FLOCK …") and anything that does
// not parse are skipped: the D65 check only ever gains trust from a lock
// it fully understood.
func parseProcLocks(b []byte) []procLock {
	var out []procLock
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), 1<<16)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 || !strings.HasSuffix(f[0], ":") || f[1] == "->" {
			continue
		}
		pid, err := strconv.Atoi(f[4])
		if err != nil {
			continue
		}
		l := procLock{kind: f[1], write: f[3] == "WRITE", pid: pid}
		parts := strings.Split(f[5], ":")
		if len(parts) != 3 {
			continue
		}
		maj, err1 := strconv.ParseUint(parts[0], 16, 32)
		min, err2 := strconv.ParseUint(parts[1], 16, 32)
		ino, err3 := strconv.ParseUint(parts[2], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		l.major, l.minor, l.inode, l.hasDev = maj, min, ino, true
		out = append(out, l)
	}
	return out
}

// holdsFlock reports whether pid holds an exclusive flock(2) lock on the
// inode ino according to locks (D65: the daemon holds run/agent.lock for
// its lifetime). The inode number is what is matched: the device /proc/locks
// prints is the superblock's, which stat(2) does not report on every file
// system (btrfs subvolumes).
func holdsFlock(locks []procLock, pid int, ino uint64) bool {
	if pid <= 1 || ino == 0 {
		return false
	}
	for _, l := range locks {
		if l.kind == "FLOCK" && l.write && l.pid == pid && l.hasDev && l.inode == ino {
			return true
		}
	}
	return false
}
