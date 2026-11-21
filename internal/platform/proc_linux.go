//go:build linux

package platform

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// linux process identity, process table, open-file holders, waits and signals
// are implemented here by G2 (see doc.go for the mechanisms).
const procImpl = "linux"

// ioctlReadTermios is tcgetattr's request (isTerminal).
const ioctlReadTermios = unix.TCGETS

// sttyFileFlag names the terminal for stty (GNU stty -F).
const sttyFileFlag = "-F"

// atClkTck is the auxv tag of the clock tick rate (AT_CLKTCK).
const atClkTck = 17

// boot holds the per-boot constants.
var boot struct {
	once  sync.Once
	id    string
	clock int64 // clock ticks per second of /proc/<pid>/stat
}

func bootInit() {
	boot.once.Do(func() {
		if b, err := readSmall("/proc/sys/kernel/random/boot_id"); err == nil {
			boot.id = strings.TrimSpace(string(b))
		}
		boot.clock = clockTicks()
	})
}

// clockTicks reads AT_CLKTCK from the auxiliary vector (sysconf(_SC_CLK_TCK)
// without cgo); USER_HZ is 100 on every mainstream architecture.
func clockTicks() int64 {
	b, err := readSmall("/proc/self/auxv")
	if err == nil {
		w := int(unsafe.Sizeof(uintptr(0)))
		for off := 0; off+2*w <= len(b); off += 2 * w {
			var tag, val uint64
			if w == 8 {
				tag, val = binary.NativeEndian.Uint64(b[off:]), binary.NativeEndian.Uint64(b[off+w:])
			} else {
				tag, val = uint64(binary.NativeEndian.Uint32(b[off:])), uint64(binary.NativeEndian.Uint32(b[off+w:]))
			}
			if tag == atClkTck && val > 0 && val <= 1_000_000 {
				return int64(val)
			}
			if tag == 0 {
				break
			}
		}
	}
	return 100
}

func sysBootID() string {
	bootInit()
	return boot.id
}

// bootTimeUS returns the boot time in µs since the epoch (/proc/stat
// btime). It is read on every measurement, so every precinto process
// computes the same start time at a given moment; a wall-clock step can
// shift btime by a second (documented residual; BootID guards reboots).
func bootTimeUS() (int64, error) {
	b, err := readSmall("/proc/stat")
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			s, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return 0, err
			}
			return s * 1_000_000, nil
		}
	}
	return 0, errors.New("platform: /proc/stat has no btime")
}

// procStat is the part of /proc/<pid>/stat precinto reads.
type procStat struct {
	comm      string
	state     byte
	ppid      int
	pgrp      int
	session   int
	ttyNr     int64
	startTick int64
}

// parseStat parses /proc/<pid>/stat. comm may contain spaces and
// parentheses, so fields are counted after the last ')'.
func parseStat(b []byte) (procStat, error) {
	open := bytes.IndexByte(b, '(')
	end := bytes.LastIndexByte(b, ')')
	if open < 0 || end < open {
		return procStat{}, errors.New("platform: malformed /proc stat")
	}
	f := strings.Fields(string(b[end+1:]))
	if len(f) < 20 {
		return procStat{}, errors.New("platform: short /proc stat")
	}
	var s procStat
	s.comm = string(b[open+1 : end])
	s.state = f[0][0]
	var err error
	ints := []*int{&s.ppid, &s.pgrp, &s.session}
	for i, p := range ints {
		if *p, err = strconv.Atoi(f[1+i]); err != nil {
			return procStat{}, err
		}
	}
	if s.ttyNr, err = strconv.ParseInt(f[4], 10, 64); err != nil {
		return procStat{}, err
	}
	if s.startTick, err = strconv.ParseInt(f[19], 10, 64); err != nil {
		return procStat{}, err
	}
	return s, nil
}

func linuxState(c byte) ProcState {
	switch c {
	case 'R', 'S', 'D', 'I', 'W', 'P', 'K':
		return StateRunning
	case 'T', 't':
		return StateStopped
	case 'Z', 'X', 'x':
		return StateZombie
	}
	return StateUnknown
}

func procPath(pid int, name string) string {
	return "/proc/" + strconv.Itoa(pid) + "/" + name
}

// readStat reads and parses /proc/<pid>/stat.
func readStat(pid int) (procStat, error) {
	b, err := readSmall(procPath(pid, "stat"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return procStat{}, fmt.Errorf("platform: pid %d: %w", pid, ErrNoProcess)
		}
		return procStat{}, fmt.Errorf("platform: pid %d: %w", pid, err)
	}
	return parseStat(b)
}

func idFrom(pid int, s procStat, btime int64) ProcID {
	bootInit()
	return ProcID{PID: pid, StartUS: btime + s.startTick*1_000_000/boot.clock, BootID: boot.id}
}

func sysIdentifyState(pid int) (ProcID, ProcState, error) {
	s, err := readStat(pid)
	if err != nil {
		return ProcID{}, StateUnknown, err
	}
	bt, err := bootTimeUS()
	if err != nil {
		return ProcID{}, StateUnknown, err
	}
	return idFrom(pid, s, bt), linuxState(s.state), nil
}

// statusUID reads the effective uid from /proc/<pid>/status (readable even
// for non-dumpable processes, whose /proc entries are owned by root).
func statusUID(pid int) (int, bool) {
	b, err := readSmall(procPath(pid, "status"))
	if err != nil {
		return 0, false
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "Uid:"); ok {
			f := strings.Fields(v)
			if len(f) >= 2 {
				if n, err := strconv.Atoi(f[1]); err == nil {
					return n, true
				}
			}
		}
	}
	return 0, false
}

// ttyName maps tty_nr to a device path: /dev/pts/N directly, else by device
// number.
func ttyName(nr int64) string {
	if nr <= 0 {
		return ""
	}
	major := (nr >> 8) & 0xfff
	minor := (nr & 0xff) | ((nr >> 12) & 0xfff00)
	if major >= 136 && major <= 143 {
		return "/dev/pts/" + strconv.FormatInt((major-136)*256+minor, 10)
	}
	return ttyByDev(unix.Mkdev(uint32(major), uint32(minor)))
}

func lookupWith(pid int, btime int64) (ProcInfo, error) {
	s, err := readStat(pid)
	if err != nil {
		return ProcInfo{}, err
	}
	info := ProcInfo{
		ID:    idFrom(pid, s, btime),
		PPID:  s.ppid,
		PGID:  s.pgrp,
		SID:   s.session,
		State: linuxState(s.state),
		Comm:  s.comm,
		TTY:   ttyName(s.ttyNr),
	}
	if uid, ok := statusUID(pid); ok {
		info.UID = uid
	} else {
		info.UID = -1
	}
	if info.State != StateZombie {
		if p, err := os.Readlink(procPath(pid, "exe")); err == nil {
			info.Exe = strings.TrimSuffix(p, " (deleted)")
		}
		if b, err := readSmall(procPath(pid, "cmdline")); err == nil && len(b) > 0 {
			b = bytes.TrimSuffix(b, []byte{0})
			for _, a := range bytes.Split(b, []byte{0}) {
				info.Argv = append(info.Argv, string(a))
			}
		}
	}
	return info, nil
}

func sysLookup(pid int) (ProcInfo, error) {
	bt, err := bootTimeUS()
	if err != nil {
		return ProcInfo{}, err
	}
	return lookupWith(pid, bt)
}

func sysList() ([]ProcInfo, error) {
	bt, err := bootTimeUS()
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("platform: list processes: %w", err)
	}
	uid := os.Geteuid()
	var out []ProcInfo
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		info, err := lookupWith(pid, bt)
		if err != nil || info.UID != uid {
			continue // exited while listing, or another user's
		}
		out = append(out, info)
	}
	return out, nil
}

func sysSelfExeIdentity(string) (uint64, uint64, error) {
	return fileIdentity("/proc/self/exe")
}

// sysExeIdentity stats /proc/<pid>/exe, which names the inode the process
// executes even if the path was replaced. A non-dumpable process (every
// hardened precinto process) denies it with EACCES to non-root peers: then
// the identity cannot be proven and the result is an error (callers fail
// closed).
func sysExeIdentity(pid int) (uint64, uint64, error) {
	dev, ino, err := fileIdentity(procPath(pid, "exe"))
	if err != nil {
		return 0, 0, fmt.Errorf("platform: executable of pid %d: %w", pid, err)
	}
	return dev, ino, nil
}

func sysCwd(id ProcID) (string, error) {
	p, err := os.Readlink(procPath(id.PID, "cwd"))
	if err != nil || !filepath.IsAbs(p) {
		return "", nil
	}
	return strings.TrimSuffix(p, " (deleted)"), nil
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
		fdDir := procPath(p.ID.PID, "fd")
		ents, err := os.ReadDir(fdDir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || !alive(p.ID) {
				continue
			}
			if errors.Is(err, os.ErrPermission) {
				// Non-dumpable processes (ssh-agent, hardened precinto)
				// cannot be inspected by the same uid; like lsof, skip them.
				continue
			}
			return nil, fmt.Errorf("platform: open files of pid %d: %w", p.ID.PID, err)
		}
		seen := map[string]bool{}
		for _, e := range ents {
			t, err := os.Readlink(filepath.Join(fdDir, e.Name()))
			if err != nil || !filepath.IsAbs(t) {
				continue
			}
			t = strings.TrimSuffix(t, " (deleted)")
			if seen[t] || !withinAny(roots, t) {
				continue
			}
			seen[t] = true
			hs = append(hs, Holder{Proc: p, Path: t})
		}
	}
	return sortedHolders(hs), nil
}

// sysSignal opens a pidfd first, then verifies the incarnation, then
// signals through the pidfd: the descriptor pins the process, so a reused
// pid can never receive the signal. Kernels without pidfds fall back to
// verify-then-kill.
func sysSignal(id ProcID, sig syscall.Signal) error {
	fd, err := unix.PidfdOpen(id.PID, 0)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("platform: pid %d: %w", id.PID, ErrNoProcess)
		}
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
	defer unix.Close(fd)
	if err := verifyIncarnation(id); err != nil {
		return err
	}
	if err := unix.PidfdSendSignal(fd, sig, nil, 0); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("platform: pid %d: %w", id.PID, ErrNoProcess)
		}
		return fmt.Errorf("platform: signal pid %d: %w", id.PID, err)
	}
	return nil
}

// sysWaitExit polls a pidfd, which becomes readable when the process exits
// (a zombie counts as exited).
func sysWaitExit(ctx context.Context, id ProcID) error {
	fd, err := unix.PidfdOpen(id.PID, 0)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return pollExit(ctx, id)
	}
	defer unix.Close(fd)
	if !alive(id) {
		return nil // the pidfd may name a newer incarnation
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, int((200 * time.Millisecond).Milliseconds()))
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
