//go:build linux

package ipc

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"syscall"
)

// D65 (linux daemon identity is best effort). Every hardened precinto
// process is non-dumpable (PR_SET_DUMPABLE=0, SPEC §4.6), and the kernel
// then hides its /proc/<pid>/exe from same-uid peers, so the executable
// check of D6 cannot run against a hardened daemon. What an unprivileged
// client can still verify, before it writes a single byte:
//
//   - the peer uid (SO_PEERCRED, checked by dialOnce for every server);
//   - that the peer pid holds the exclusive flock(2) on the inode of
//     run/agent.lock of the client's own layout (/proc/locks, matched by
//     inode): the daemon takes it in Listen and keeps it for its lifetime,
//     and a squatter that merely binds the socket does not hold it;
//   - that the peer's kernel name (comm, /proc/<pid>/stat) equals the
//     client's own.
//
// Residual (SPEC §19): this stops accidents and naive squatters, not a
// same-uid process that kills the daemon, takes run/agent.lock itself
// under a binary named like precinto, and binds the socket; persistent
// same-uid malware is outside the threat model. darwin keeps the full
// executable check. The daemon's own check of its clients uses the comm
// rule only (clients hold no lock).

// sameExeFallback is the server's check of a hardened client whose
// /proc/<pid>/exe is denied: the kernel name must equal ours. It only
// guards against accidents; the operations that need more (keys, unlock)
// also re-verify the peer incarnation (Conn.PeerSameExecutable).
func sameExeFallback(pid int) bool { return sameComm(pid) }

// daemonFallback is the client's D65 check of a hardened daemon at pid
// whose executable cannot be read: same comm, and pid holds the flock of
// lockPath (run/agent.lock, a regular file of this uid).
func daemonFallback(pid int, lockPath string) bool {
	if !sameComm(pid) {
		return false
	}
	st, err := os.Lstat(lockPath)
	if err != nil || !st.Mode().IsRegular() || !ownedByMe(st) {
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	b, err := readProcLocks()
	if err != nil {
		return false
	}
	return holdsFlock(parseProcLocks(b), pid, sys.Ino)
}

// readProcLocks reads /proc/locks (bounded: one line per lock on the
// system).
func readProcLocks() ([]byte, error) {
	f, err := os.Open("/proc/locks")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 8<<20))
}

// sameComm reports whether pid's kernel name equals ours (world-readable
// /proc/<pid>/stat, available for non-dumpable processes too).
func sameComm(pid int) bool {
	other, ok1 := comm("/proc/" + strconv.Itoa(pid) + "/stat")
	mine, ok2 := comm("/proc/self/stat")
	return ok1 && ok2 && other != "" && other == mine
}

func comm(statPath string) (string, bool) {
	b, err := os.ReadFile(statPath)
	if err != nil {
		return "", false
	}
	i, j := bytes.IndexByte(b, '('), bytes.LastIndexByte(b, ')')
	if i < 0 || j < i {
		return "", false
	}
	return string(b[i+1 : j]), true
}
