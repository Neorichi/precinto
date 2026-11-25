//go:build darwin

package platform

import "golang.org/x/sys/unix"

// darwin peer credentials and executable identity are implemented here by G2.

// sysPeerCred returns the peer's uid (LOCAL_PEERCRED, the credentials at
// connect time) and pid (LOCAL_PEERPID) of a connected Unix socket.
func sysPeerCred(fd int) (uid, pid int, err error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, 0, err
	}
	pid, err = unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return 0, 0, err
	}
	return int(cred.Uid), pid, nil
}
