//go:build darwin

package platform

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// darwin process identity, process table, open-file holders, waits and signals
// are implemented here by G2 (see doc.go for the mechanisms).
const procImpl = "darwin"

// ioctlReadTermios is tcgetattr's request (isTerminal).
const ioctlReadTermios = unix.TIOCGETA

// sttyFileFlag names the terminal for stty (BSD stty -f).
const sttyFileFlag = "-f"

// Kernel constants of libproc's proc_info(2) interface (sys/proc_info.h),
// which proc_pidpath, proc_pidinfo and proc_pidfdinfo wrap. They are reached
// through syscall(2) because this package is cgo-free.
const (
	procInfoCallPIDInfo   = 2  // PROC_INFO_CALL_PIDINFO
	procInfoCallPIDFDInfo = 3  // PROC_INFO_CALL_PIDFDINFO
	procPIDListFDs        = 1  // PROC_PIDLISTFDS: array of struct proc_fdinfo
	procPIDVnodePathInfo  = 9  // PROC_PIDVNODEPATHINFO: struct proc_vnodepathinfo (cwd, root)
	procPIDPathInfo       = 11 // PROC_PIDPATHINFO: executable path (proc_pidpath)
	procPIDFDVnodePath    = 2  // PROC_PIDFDVNODEPATHINFO: struct vnode_fdinfowithpath
	proxFDTypeVnode       = 1  // PROX_FDTYPE_VNODE

	maxPathLen          = 1024                    // MAXPATHLEN
	sizeofVnodeInfo     = 152                     // struct vnode_info
	sizeofVnodeInfoPath = 152 + maxPathLen        // struct vnode_info_path
	sizeofVnodePathInfo = 2 * sizeofVnodeInfoPath // struct proc_vnodepathinfo
	sizeofProcFileInfo  = 24                      // struct proc_fileinfo
	sizeofFDWithPath    = sizeofProcFileInfo + sizeofVnodeInfoPath
	sizeofProcFDInfo    = 8              // struct proc_fdinfo
	procPIDPathMax      = 4 * maxPathLen // PROC_PIDPATHINFO_MAXSIZE

	pControlT = 0x2 // P_CONTROLT: the process has a controlling terminal
	noDev     = -1  // NODEV
)

// Scheduler states of struct extern_proc p_stat.
const (
	sIdl   = 1
	sRun   = 2
	sSleep = 3
	sStop  = 4
	sZomb  = 5
)

// procInfo calls proc_info(2) and returns its result value.
func procInfo(call, pid, flavor int, arg uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, syscall.EINVAL
	}
	r1, _, e := unix.Syscall6(unix.SYS_PROC_INFO, uintptr(call), uintptr(pid), uintptr(flavor),
		uintptr(arg), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if e != 0 {
		return 0, e
	}
	return int(r1), nil
}

// cString returns b up to its first NUL.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// noProcess maps a lookup failure of pid to ErrNoProcess.
func noProcess(pid int, err error) error {
	return fmt.Errorf("platform: pid %d: %w (%v)", pid, ErrNoProcess, err)
}

// kinfo returns the kinfo_proc of pid. A missing pid makes the sysctl
// return no record, which x/sys reports as EIO.
func kinfo(pid int) (*unix.KinfoProc, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return nil, noProcess(pid, err)
	}
	if int(kp.Proc.P_pid) != pid {
		return nil, noProcess(pid, syscall.ESRCH)
	}
	return kp, nil
}

// stateOf maps p_stat.
func stateOf(stat int8) ProcState {
	switch stat {
	case sIdl, sRun, sSleep:
		return StateRunning
	case sStop:
		return StateStopped
	case sZomb:
		return StateZombie
	}
	return StateUnknown
}

// idOf returns the ProcID of a kinfo_proc (start time in µs since the epoch).
func idOf(kp *unix.KinfoProc) ProcID {
	st := kp.Proc.P_starttime
	return ProcID{PID: int(kp.Proc.P_pid), StartUS: int64(st.Sec)*1_000_000 + int64(st.Usec)}
}

// basicInfo converts the cheap fields of a kinfo_proc.
func basicInfo(kp *unix.KinfoProc) ProcInfo {
	info := ProcInfo{
		ID:    idOf(kp),
		PPID:  int(kp.Eproc.Ppid),
		UID:   int(kp.Eproc.Ucred.Uid),
		PGID:  int(kp.Eproc.Pgid),
		State: stateOf(kp.Proc.P_stat),
		Comm:  cString(kp.Proc.P_comm[:]),
	}
	if kp.Proc.P_flag&pControlT != 0 && kp.Eproc.Tdev != noDev {
		info.TTY = ttyByDev(uint64(uint32(kp.Eproc.Tdev)))
	}
	return info
}

// fullInfo adds what needs more system calls: session, executable, argv.
func fullInfo(kp *unix.KinfoProc) ProcInfo {
	info := basicInfo(kp)
	pid := info.ID.PID
	if sid, err := unix.Getsid(pid); err == nil {
		info.SID = sid
	}
	if info.State != StateZombie {
		info.Exe, _ = exePath(pid)
		info.Argv = procArgv(pid)
	}
	return info
}

func sysBootID() string { return "" }

func sysIdentifyState(pid int) (ProcID, ProcState, error) {
	kp, err := kinfo(pid)
	if err != nil {
		return ProcID{}, StateUnknown, err
	}
	return idOf(kp), stateOf(kp.Proc.P_stat), nil
}

func sysLookup(pid int) (ProcInfo, error) {
	kp, err := kinfo(pid)
	if err != nil {
		return ProcInfo{}, err
	}
	return fullInfo(kp), nil
}

func sysList() ([]ProcInfo, error) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.uid", os.Geteuid())
	if err != nil {
		return nil, fmt.Errorf("platform: list processes: %w", err)
	}
	out := make([]ProcInfo, 0, len(kps))
	for i := range kps {
		if kps[i].Proc.P_pid <= 0 {
			continue
		}
		out = append(out, fullInfo(&kps[i]))
	}
	return out, nil
}

// exePath returns the absolute path of pid's executable (proc_pidpath).
func exePath(pid int) (string, error) {
	buf := make([]byte, procPIDPathMax)
	if _, err := procInfo(procInfoCallPIDInfo, pid, procPIDPathInfo, 0, buf); err != nil {
		return "", err
	}
	p := cString(buf)
	if p == "" || p[0] != '/' {
		return "", fmt.Errorf("platform: no executable path for pid %d", pid)
	}
	return p, nil
}

// procArgv returns argv from kern.procargs2 (best effort): an int32 argc,
// the exec path, NUL padding, then argc NUL-terminated strings. Nothing
// after argv (the environment, on systems that still expose it) is read.
func procArgv(pid int) []string {
	b, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(b) < 4 {
		return nil
	}
	argc := int(binary.LittleEndian.Uint32(b[:4]))
	if argc <= 0 || argc > 1<<16 {
		return nil
	}
	rest := b[4:]
	i := bytes.IndexByte(rest, 0) // end of the exec path
	if i < 0 {
		return nil
	}
	rest = rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	argv := make([]string, 0, argc)
	for len(argv) < argc && len(rest) > 0 {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			argv = append(argv, string(rest))
			break
		}
		argv = append(argv, string(rest[:j]))
		rest = rest[j+1:]
	}
	return argv
}

func sysSelfExeIdentity(path string) (uint64, uint64, error) {
	return fileIdentity(path)
}

// sysExeIdentity resolves pid's executable vnode path (proc_pidpath) and
// returns the identity of the file at that path. A binary replaced at the
// same path after exec is a documented residual (same-user attacker).
func sysExeIdentity(pid int) (uint64, uint64, error) {
	p, err := exePath(pid)
	if err != nil {
		return 0, 0, fmt.Errorf("platform: executable of pid %d: %w", pid, err)
	}
	return fileIdentity(p)
}

// sysCwd returns the working directory of id (proc_pidinfo
// PROC_PIDVNODEPATHINFO, else lsof -d cwd), or "" if it cannot be read.
func sysCwd(id ProcID) (string, error) {
	buf := make([]byte, sizeofVnodePathInfo)
	if _, err := procInfo(procInfoCallPIDInfo, id.PID, procPIDVnodePathInfo, 0, buf); err == nil {
		p := cString(buf[sizeofVnodeInfo:sizeofVnodeInfoPath])
		if p != "" && p[0] == '/' {
			return p, nil
		}
		return "", nil
	} else if !errors.Is(err, syscall.ENOSYS) {
		return "", nil
	}
	out, _, err := runTool(context.Background(), 10*time.Second, "/usr/sbin/lsof", "-w", "-n", "-P", "-a",
		"-p", fmt.Sprint(id.PID), "-d", "cwd", "-F", "pn0")
	if err != nil && len(out) == 0 {
		return "", nil
	}
	for _, names := range parseLsof(out) {
		if len(names) > 0 && names[0] != "" && names[0][0] == '/' {
			return names[0], nil
		}
	}
	return "", nil
}

// fdPaths returns the paths of pid's open vnode descriptors.
func fdPaths(pid int) ([]string, error) {
	n := 64
	var fds []byte
	for {
		buf := make([]byte, n*sizeofProcFDInfo)
		got, err := procInfo(procInfoCallPIDInfo, pid, procPIDListFDs, 0, buf)
		if err != nil {
			return nil, err
		}
		if got < len(buf) || n >= 1<<20 {
			fds = buf[:got]
			break
		}
		n *= 4
	}
	var out []string
	vbuf := make([]byte, sizeofFDWithPath)
	for off := 0; off+sizeofProcFDInfo <= len(fds); off += sizeofProcFDInfo {
		fd := int32(binary.LittleEndian.Uint32(fds[off:]))
		typ := binary.LittleEndian.Uint32(fds[off+4:])
		if typ != proxFDTypeVnode || fd < 0 {
			continue
		}
		clear(vbuf)
		if _, err := procInfo(procInfoCallPIDFDInfo, pid, procPIDFDVnodePath, uint64(fd), vbuf); err != nil {
			if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.ENOENT) {
				continue // closed since the listing
			}
			return nil, err
		}
		if p := cString(vbuf[sizeofProcFileInfo+sizeofVnodeInfo:]); p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

func sysOpenFilesUnder(ctx context.Context, dirs []string) ([]Holder, error) {
	procs, err := sysList()
	if err != nil {
		return nil, err
	}
	roots := resolvedRoots(dirs)
	hs := []Holder{}
	for _, p := range procs {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("platform: open files: %w", err)
		}
		if p.State == StateZombie {
			continue
		}
		files, err := fdPaths(p.ID.PID)
		if err != nil {
			if errors.Is(err, syscall.ESRCH) || !alive(p.ID) {
				continue // exited: it holds nothing any more
			}
			if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
				// Protected system agents of the same uid (ScreenTimeAgent…)
				// refuse descriptor inspection; lsof skips them too. Harness
				// processes are never protected this way.
				continue
			}
			if errors.Is(err, syscall.ENOSYS) {
				return lsofHolders(ctx, dirs)
			}
			return nil, fmt.Errorf("platform: open files of pid %d: %w", p.ID.PID, err)
		}
		seen := map[string]bool{}
		for _, f := range files {
			if seen[f] || !withinAny(roots, f) {
				continue
			}
			seen[f] = true
			hs = append(hs, Holder{Proc: p, Path: f})
		}
	}
	return sortedHolders(hs), nil
}

// sysSignal verifies the incarnation immediately before kill(2). darwin has
// no process descriptors, so a pid reuse in the microseconds between the
// check and the kill is the residual race (S14).
func sysSignal(id ProcID, sig syscall.Signal) error {
	if err := verifyIncarnation(id); err != nil {
		return err
	}
	if err := unix.Kill(id.PID, sig); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("platform: pid %d: %w", id.PID, ErrNoProcess)
		}
		return fmt.Errorf("platform: signal pid %d: %w", id.PID, err)
	}
	return nil
}

// sysWaitExit waits with kqueue EVFILT_PROC/NOTE_EXIT, which fires when the
// process exits (before it is reaped, so a zombie counts as exited).
func sysWaitExit(ctx context.Context, id ProcID) error {
	kq, err := unix.Kqueue()
	if err != nil {
		return pollExit(ctx, id)
	}
	defer unix.Close(kq)
	ev := unix.Kevent_t{Ident: uint64(id.PID), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ENABLE | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}
	if _, err := unix.Kevent(kq, []unix.Kevent_t{ev}, nil, nil); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return pollExit(ctx, id)
	}
	// Registered on the pid: if it is no longer our incarnation, ours has
	// exited already (the event would belong to a newer process).
	if !alive(id) {
		return nil
	}
	events := make([]unix.Kevent_t, 1)
	for {
		ts := unix.NsecToTimespec(int64(200 * time.Millisecond))
		n, err := unix.Kevent(kq, nil, events, &ts)
		if err != nil && !errors.Is(err, syscall.EINTR) {
			return pollExit(ctx, id)
		}
		if n > 0 || !alive(id) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}
