//go:build linux

package ipc

import (
	"bytes"
	"os"
	"strconv"
)

// sameExeFallback applies when /proc/<pid>/exe is denied: every hardened
// precinto process is non-dumpable (PR_SET_DUMPABLE=0, SPEC §4.6), and the
// kernel then hides its executable from same-uid peers. The strongest fact
// left to an unprivileged peer is the kernel name in /proc/<pid>/stat
// (world-readable), which must equal ours. This only guards against
// accidents (another program on the socket); a same-uid attacker is out of
// scope on linux (reported to the lead as a contract gap).
func sameExeFallback(pid int) bool {
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
