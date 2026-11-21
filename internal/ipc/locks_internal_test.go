package ipc

import "testing"

// D65: /proc/locks fixtures. Only a granted exclusive flock of the pid on
// the inode counts; waiters, shared, POSIX/OFD locks, other pids, other
// inodes and lines that do not parse never do.
func TestProcLocks(t *testing.T) {
	const fixture = `1: FLOCK  ADVISORY  WRITE 4242 00:2a:1234 0 EOF
1: -> FLOCK  ADVISORY  WRITE 5555 00:2a:1234 0 EOF
2: FLOCK  ADVISORY  READ  4343 00:2a:2345 0 EOF
3: POSIX  ADVISORY  WRITE 4444 fd:01:3456 0 EOF
4: OFDLCK ADVISORY  WRITE -1 fd:01:4567 0 EOF
5: LEASE  ACTIVE    READ  4545 00:2a:5678 0 EOF
6: FLOCK  ADVISORY  WRITE 4646 <none>:0 0 EOF
7: FLOCK  ADVISORY  WRITE 4747 zz:01:6789 0 EOF
garbage line
8: FLOCK  ADVISORY  WRITE 4848 103:0a:987654321 0 EOF
`
	locks := parseProcLocks([]byte(fixture))
	for _, tc := range []struct {
		pid  int
		ino  uint64
		want bool
	}{
		{4242, 1234, true},
		{4242, 2345, false},         // another inode
		{5555, 1234, false},         // a blocked waiter holds nothing
		{4343, 2345, false},         // shared
		{4444, 3456, false},         // POSIX record lock
		{-1, 4567, false},           // OFD lock: no pid
		{4545, 5678, false},         // lease
		{4646, 0, false},            // no inode
		{4747, 6789, false},         // unparsable device
		{4848, 987654321, true},     // hex major ≥ 0x100
		{1, 1234, false},            // never init
		{4243, 1234, false},         // another pid
		{4848, 987654322, false},    // another inode
		{0, 987654321, false},       // pid 0
		{4242, 1234 + 1<<40, false}, // high bits differ
	} {
		if got := holdsFlock(locks, tc.pid, tc.ino); got != tc.want {
			t.Errorf("holdsFlock(%d, %d) = %v, want %v", tc.pid, tc.ino, got, tc.want)
		}
	}
	if l := locks[len(locks)-1]; l.major != 0x103 || l.minor != 0x0a {
		t.Fatalf("device = %x:%x", l.major, l.minor)
	}
	if len(parseProcLocks(nil)) != 0 {
		t.Fatal("empty input")
	}
}
