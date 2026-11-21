//go:build linux

package platform

import "golang.org/x/sys/unix"

// linux peer credentials and executable identity are implemented here by G2.
const peerImpl = "linux"

// sysPeerCred returns the peer's uid and pid of a connected Unix socket
// (SO_PEERCRED: the credentials at connect time).
func sysPeerCred(fd int) (uid, pid int, err error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, 0, err
	}
	return int(cred.Uid), int(cred.Pid), nil
}
