//go:build darwin || linux

package fsx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// User-private groups (D67, SPEC §11.4). Below a base a group-writable
// directory is unsafe (S7), except a group-writable, not other-writable
// directory whose group is the user's primary group when that group is
// named like the user and no other account can be a member of it (the
// Debian/Ubuntu user-private group scheme, umask 002). Only linux enables
// the exception (privateGroups in sys_linux.go): on darwin every user's
// primary group is the shared "staff".
//
// The databases are /etc/passwd and /etc/group, the files os/user's pure-Go
// lookup reads. NSS (LDAP, sssd, systemd-userdb) is never consulted, so a
// user or group known only there is undeterminable, and anything
// undeterminable keeps the directory unsafe: a missing, unreadable,
// symlinked, oversized or foreign-writable database, a malformed or NIS
// compat ("+"/"-") line, an ambiguous account, a group that lists another
// member, or another account whose primary group it is.

// accountFiles are the user and group databases (a seam for tests).
var accountFiles = struct{ passwd, group string }{"/etc/passwd", "/etc/group"}

// maxAccountFile bounds each database read.
const maxAccountFile = 4 << 20

// upgCache remembers the user-private group of the effective uid for one
// identity of both databases, so a walk over many group-writable
// directories reads them once (and a changed database is read again).
var upgCache struct {
	mu  sync.Mutex
	key string
	gid uint32
	ok  bool
}

// groupWritableOK reports whether a group-writable, not other-writable
// directory whose group is gid may be treated as the user's own (D67): gid
// is the process's effective gid and the user-private group of the
// effective uid.
func groupWritableOK(gid uint32) bool {
	if !privateGroups || euid() == 0 || gid != uint32(os.Getegid()) {
		return false
	}
	upg, ok := userPrivateGroup()
	return ok && upg == gid
}

// userPrivateGroup returns the user-private group of the effective uid, or
// ok=false when there is none or it cannot be determined.
func userPrivateGroup() (uint32, bool) {
	key, err := accountKey()
	if err != nil {
		return 0, false
	}
	upgCache.mu.Lock()
	defer upgCache.mu.Unlock()
	if upgCache.key == key {
		return upgCache.gid, upgCache.ok
	}
	passwd, err := readAccountFile(accountFiles.passwd)
	if err != nil {
		return 0, false
	}
	group, err := readAccountFile(accountFiles.group)
	if err != nil {
		return 0, false
	}
	// The key is taken again after reading: a database replaced meanwhile
	// is judged at the next call instead of being cached under a stale key.
	if again, err := accountKey(); err != nil || again != key {
		return 0, false
	}
	gid, ok := privateGroupOf(euid(), passwd, group)
	upgCache.key, upgCache.gid, upgCache.ok = key, gid, ok
	return gid, ok
}

// accountKey identifies the current version of both databases.
func accountKey() (string, error) {
	var b strings.Builder
	for _, p := range []string{accountFiles.passwd, accountFiles.group} {
		st, err := lstatAt(unix.AT_FDCWD, p)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s\x00%d\x00%d\x00%d\x00%d\x00%d\x00%o\x00%d\n", p, st.Dev, st.Ino, st.Size,
			st.Mtim.Nano(), st.Ctim.Nano(), st.Mode, st.Uid)
	}
	return b.String(), nil
}

// readAccountFile reads one database: a regular file (never through a
// symlink, never blocking on a FIFO) owned by root or the user, writable by
// nobody else, of at most maxAccountFile bytes.
func readAccountFile(path string) ([]byte, error) {
	fd, err := openat(unix.AT_FDCWD, path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, pathErr("open", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := fstatFD(fd)
	if err != nil {
		return nil, pathErr("fstat", path, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, unsafeErr(path, "not a regular file")
	case st.Uid != 0 && st.Uid != euid():
		return nil, unsafeErr(path, fmt.Sprintf("owned by uid %d", st.Uid))
	case st.Mode&0o022 != 0:
		return nil, unsafeErr(path, "group/other-writable")
	case st.Size > maxAccountFile:
		return nil, unsafeErr(path, "too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAccountFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxAccountFile {
		return nil, unsafeErr(path, "too large")
	}
	return b, nil
}

// errUndeterminable marks a database line the check cannot judge.
var errUndeterminable = errors.New("fsx: account database cannot be judged")

// accountLines splits a passwd or group database into its records with
// glibc's tolerance (leading and trailing blanks, blank and comment lines
// skipped). Each record must have exactly fields colon-separated fields; a
// malformed record or a NIS compat record ("+…", "-…") makes the whole
// database undeterminable.
func accountLines(db []byte, fields int) ([][]string, error) {
	var out [][]string
	for _, line := range bytes.Split(db, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if line[0] == '+' || line[0] == '-' {
			return nil, errUndeterminable
		}
		parts := strings.Split(string(line), ":")
		if len(parts) != fields || parts[0] == "" {
			return nil, errUndeterminable
		}
		out = append(out, parts)
	}
	return out, nil
}

func parseID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, errUndeterminable
	}
	return uint32(n), nil
}

// privateGroupOf returns the user-private group of uid in the given
// databases: the primary group G of uid's only passwd record (name U),
// where G is no other account's primary group and the group database has
// exactly one record with gid G, named U, listing no member but U.
func privateGroupOf(uid uint32, passwd, group []byte) (uint32, bool) {
	users, err := accountLines(passwd, 7)
	if err != nil {
		return 0, false
	}
	type account struct {
		name     string
		uid, gid uint32
	}
	var accounts []account
	for _, u := range users {
		id, err := parseID(u[2])
		if err != nil {
			return 0, false
		}
		gid, err := parseID(u[3])
		if err != nil {
			return 0, false
		}
		accounts = append(accounts, account{name: u[0], uid: id, gid: gid})
	}
	var me *account
	for i := range accounts {
		if accounts[i].uid != uid {
			continue
		}
		if me != nil {
			return 0, false // two names for one uid: ambiguous
		}
		me = &accounts[i]
	}
	if me == nil {
		return 0, false
	}
	for _, a := range accounts {
		if a.uid != uid && a.gid == me.gid {
			return 0, false // another account's primary group too
		}
	}
	groups, err := accountLines(group, 4)
	if err != nil {
		return 0, false
	}
	found := false
	for _, g := range groups {
		gid, err := parseID(g[2])
		if err != nil {
			return 0, false
		}
		if gid != me.gid {
			continue
		}
		if found || g[0] != me.name {
			return 0, false // listed twice, or not named like the user
		}
		found = true
		for _, m := range strings.Split(g[3], ",") {
			if m = strings.TrimSpace(m); m != "" && m != me.name {
				return 0, false // another member
			}
		}
	}
	if !found {
		return 0, false // NSS-only or missing group
	}
	return me.gid, true
}
