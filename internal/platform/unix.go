//go:build darwin || linux

package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// signalProc implements Signal: refuse anything that is not a verifiable
// incarnation (pid ≤ 1 would address init, a process group or every
// process), then re-verify and signal (sysSignal).
func signalProc(id ProcID, sig syscall.Signal) error {
	if id.PID <= 1 || id.StartUS == 0 {
		return fmt.Errorf("platform: refusing to signal pid %d without a verifiable identity: %w", id.PID, ErrNotSame)
	}
	return sysSignal(id, sig)
}

// verifyIncarnation re-measures pid and requires it to be exactly id and
// not a zombie (a zombie has exited: ErrNoProcess).
func verifyIncarnation(id ProcID) error {
	cur, state, err := sysIdentifyState(id.PID)
	if err != nil {
		return err
	}
	if cur != id {
		return fmt.Errorf("platform: pid %d: %w", id.PID, ErrNotSame)
	}
	if state == StateZombie {
		return fmt.Errorf("platform: pid %d has exited: %w", id.PID, ErrNoProcess)
	}
	return nil
}

// signalGroup implements SignalGroup. Besides the documented contract it
// refuses the caller's own session (that is the user's terminal session for
// a wrapper or CLI, R11, D57), sid ≤ 1, and never signals the caller.
func signalGroup(sid int, sig syscall.Signal) error {
	if sid <= 1 {
		return fmt.Errorf("platform: refusing to signal session %d", sid)
	}
	if own, err := unix.Getsid(0); err != nil {
		return fmt.Errorf("platform: own session: %w", err)
	} else if own == sid {
		return fmt.Errorf("platform: refusing to signal the caller's own session %d", sid)
	}
	procs, err := sysList()
	if err != nil {
		return err
	}
	me := os.Getpid()
	var firstErr error
	for _, p := range procs {
		if p.SID != sid || p.ID.PID == me || p.State == StateZombie {
			continue
		}
		if err := signalProc(p.ID, sig); err != nil && !errors.Is(err, ErrNotSame) && !errors.Is(err, ErrNoProcess) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// waitExit implements WaitExit.
func waitExit(ctx context.Context, id ProcID) error {
	if ctx == nil {
		return fmt.Errorf("platform: wait: nil context")
	}
	if !alive(id) {
		return nil
	}
	return sysWaitExit(ctx, id)
}

// pollExit waits for id to stop being alive, polling with back-off (10 ms
// to 250 ms). It is the fallback of every wait mechanism.
func pollExit(ctx context.Context, id ProcID) error {
	d := 10 * time.Millisecond
	for alive(id) {
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		if d < 250*time.Millisecond {
			d *= 2
		}
	}
	return nil
}

// spawn implements Spawn.
func spawn(argv []string, o SpawnOptions) (ProcID, error) {
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return ProcID{}, fmt.Errorf("platform: spawn: argv[0] must be an absolute path")
	}
	env := o.Env
	if env == nil {
		env = []string{} // never inherit this process's environment
	}
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		return ProcID{}, fmt.Errorf("platform: spawn: %w", err)
	}
	defer stdin.Close()
	var out *os.File
	if o.LogPath != "" {
		out, err = os.OpenFile(o.LogPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	} else {
		out, err = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	}
	if err != nil {
		return ProcID{}, fmt.Errorf("platform: spawn: open output: %w", err)
	}
	defer out.Close()
	cmd := &exec.Cmd{
		Path:        argv[0],
		Args:        append([]string(nil), argv...),
		Env:         env,
		Dir:         o.Dir,
		Stdin:       stdin,
		Stdout:      out,
		Stderr:      out,
		SysProcAttr: &syscall.SysProcAttr{Setsid: true},
	}
	if err := cmd.Start(); err != nil {
		return ProcID{}, fmt.Errorf("platform: spawn: %w", err)
	}
	pid := cmd.Process.Pid
	// Measure before reaping: until Wait returns, the pid cannot be reused
	// (an exited child stays a zombie), so the identity is the child's.
	id, _, ierr := sysIdentifyState(pid)
	// Reap the child when it exits so a long-running daemon never
	// accumulates zombies; "does not wait" means the call does not block.
	go func() { _ = cmd.Wait() }()
	if ierr != nil {
		return ProcID{PID: pid}, nil
	}
	return id, nil
}

// exe caches the identity of the running binary.
var exe struct {
	once     sync.Once
	path     string
	dev, ino uint64
	err      error
}

// executable implements Executable.
func executable() (string, uint64, uint64, error) {
	exe.once.Do(func() {
		p, err := os.Executable()
		if err == nil {
			p, err = filepath.EvalSymlinks(p)
		}
		if err != nil {
			exe.err = fmt.Errorf("platform: executable: %w", err)
			return
		}
		exe.path = filepath.Clean(p)
		exe.dev, exe.ino, exe.err = sysSelfExeIdentity(exe.path)
	})
	return exe.path, exe.dev, exe.ino, exe.err
}

// fileIdentity returns (dev, ino) of path, following symlinks.
func fileIdentity(path string) (uint64, uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, 0, err
	}
	return uint64(st.Dev), uint64(st.Ino), nil
}

// sameExecutable implements SameExecutable.
func sameExecutable(pid int) (bool, error) {
	if pid == os.Getpid() {
		return true, nil
	}
	if pid <= 0 {
		return false, fmt.Errorf("platform: pid %d: %w", pid, ErrNoProcess)
	}
	_, dev, ino, err := executable()
	if err != nil {
		return false, err
	}
	pdev, pino, err := sysExeIdentity(pid)
	if err != nil {
		return false, err
	}
	return pdev == dev && pino == ino, nil
}

// peerOf implements PeerOf.
func peerOf(c *net.UnixConn) (Peer, error) {
	if c == nil {
		return Peer{}, fmt.Errorf("platform: peer of a nil connection")
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return Peer{}, fmt.Errorf("platform: peer credentials: %w", err)
	}
	var uid, pid int
	var cerr error
	if err := rc.Control(func(fd uintptr) { uid, pid, cerr = sysPeerCred(int(fd)) }); err != nil {
		return Peer{}, fmt.Errorf("platform: peer credentials: %w", err)
	}
	if cerr != nil {
		return Peer{}, fmt.Errorf("platform: peer credentials: %w", cerr)
	}
	if pid <= 0 {
		return Peer{}, fmt.Errorf("platform: peer credentials: no peer pid")
	}
	info, err := sysLookup(pid)
	if err != nil {
		return Peer{}, fmt.Errorf("platform: peer process: %w", err)
	}
	return Peer{UID: uid, PID: pid, Proc: info}, nil
}

// harden implements Harden.
func harden() error {
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return ErrRoot
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("platform: disable core dumps: %w", err)
	}
	return sysHarden()
}

// isTerminal reports whether f is a terminal (tcgetattr succeeds), without
// switching f to blocking mode as File.Fd would.
func isTerminal(f *os.File) bool {
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	_ = rc.Control(func(fd uintptr) {
		_, err := unix.IoctlGetTermios(int(fd), ioctlReadTermios)
		ok = err == nil
	})
	return ok
}

// readScreen implements ReadScreen.
func readScreen(ctx context.Context) (ScreenState, error) {
	if ctx == nil {
		return ScreenState{}, fmt.Errorf("platform: read screen: nil context")
	}
	s, err := sysReadScreen(ctx)
	if s.At.IsZero() {
		s.At = time.Now().Round(0)
	}
	return s, err
}

// toolEnv is the environment of every system tool precinto runs (ioreg,
// lsof, loginctl, stty, fdesetup, tmutil, mdfind): no inherited variable
// can redirect or instrument them.
var toolEnv = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "LANG=C"}

// maxToolOutput bounds what runTool keeps of a tool's stdout.
const maxToolOutput = 16 << 20

// errToolOutput reports a tool whose output exceeded maxToolOutput.
var errToolOutput = errors.New("platform: tool output too large")

// runTool runs an absolute system tool with toolEnv, stdin /dev/null and a
// timeout, and returns its stdout and stderr (bounded).
func runTool(ctx context.Context, timeout time.Duration, path string, args ...string) (stdout, stderr []byte, err error) {
	if !filepath.IsAbs(path) {
		return nil, nil, fmt.Errorf("platform: tool path must be absolute")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = toolEnv
	cmd.Dir = "/"
	var out, errb limitedBuffer
	out.max, errb.max = maxToolOutput, 64<<10
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.WaitDelay = time.Second
	err = cmd.Run()
	if out.over {
		return nil, errb.Bytes(), errToolOutput
	}
	if err != nil && ctx.Err() != nil {
		err = fmt.Errorf("platform: %s: %w", filepath.Base(path), ctx.Err())
	}
	return out.Bytes(), errb.Bytes(), err
}

// limitedBuffer keeps at most max bytes and records an overflow.
type limitedBuffer struct {
	bytes.Buffer
	max  int
	over bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		b.over = true
		return len(p), nil // keep draining the pipe; the result is discarded
	}
	return b.Buffer.Write(p)
}

// ttys maps terminal device numbers to their /dev paths (darwin devname(3)
// without cgo; linux for terminals other than /dev/pts).
var ttys struct {
	sync.Mutex
	byDev   map[uint64]string
	scanned time.Time
}

// ttyByDev returns the /dev path of the terminal device dev, or "".
func ttyByDev(dev uint64) string {
	ttys.Lock()
	defer ttys.Unlock()
	if p, ok := ttys.byDev[dev]; ok {
		return p
	}
	if time.Since(ttys.scanned) < time.Second {
		return "" // a scan just ran: do not rescan /dev for every process
	}
	ttys.byDev = scanTTYs()
	ttys.scanned = time.Now()
	return ttys.byDev[dev]
}

// scanTTYs lists the character devices of /dev and /dev/pts that are
// terminals by name.
func scanTTYs() map[uint64]string {
	m := map[uint64]string{}
	add := func(dir string, keep func(string) bool) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range ents {
			if !keep(e.Name()) {
				continue
			}
			p := filepath.Join(dir, e.Name())
			var st unix.Stat_t
			if unix.Lstat(p, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
				continue
			}
			m[uint64(st.Rdev)] = p
		}
	}
	add("/dev", func(n string) bool { return strings.HasPrefix(n, "tty") || n == "console" })
	add("/dev/pts", func(n string) bool { return n != "ptmx" })
	return m
}

// resetSequence is the terminal reset of SPEC §15.4 (without stty and the
// banner), optionally followed by clear screen + scrollback (and the
// iTerm2 scrollback clear).
func resetSequence(clear, iterm bool) []byte {
	var b bytes.Buffer
	b.WriteString("\x1b[?1049l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1004l\x1b[<99u\x1b[>4;0m\x1b[?25h\x1b[r\x1b[0m")
	if clear {
		b.WriteString("\x1b[H\x1b[2J\x1b[3J")
		if iterm {
			b.WriteString("\x1b]1337;ClearScrollback\x1b\\")
		}
	}
	return b.Bytes()
}

// bannerLine renders a banner as one printable line: control characters
// (C0, C1, DEL, line breaks) are dropped so a banner can never inject
// terminal sequences.
func bannerLine(s string) []byte {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() == 0 {
		return nil
	}
	return []byte(b.String() + "\r\n")
}

// scrubTTY implements ScrubTTY.
func scrubTTY(tty string, o ScrubOptions) error {
	if !strings.HasPrefix(tty, "/dev/") || filepath.Clean(tty) != tty {
		return fmt.Errorf("platform: scrub: not a terminal device path")
	}
	fd, err := unix.Open(tty, unix.O_WRONLY|unix.O_NOCTTY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("platform: scrub: open terminal: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return fmt.Errorf("platform: scrub: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFCHR || int(st.Uid) != os.Getuid() {
		unix.Close(fd)
		return fmt.Errorf("platform: scrub: terminal is not a character device owned by the current user")
	}
	f := os.NewFile(uintptr(fd), tty)
	defer f.Close()
	if err := writeTTY(f, resetSequence(o.Clear, o.ITerm)); err != nil {
		return err
	}
	if _, _, err := runTool(context.Background(), 3*time.Second, "/bin/stty", sttyFileFlag, tty, "sane"); err != nil {
		return fmt.Errorf("platform: scrub: stty sane: %w", err)
	}
	if line := bannerLine(o.Banner); line != nil {
		return writeTTY(f, line)
	}
	return nil
}

// writeTTY writes b within a bounded time: a terminal that stopped reading
// (flow control, a frozen emulator) must not hang the daemon.
func writeTTY(f *os.File, b []byte) error {
	_ = f.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("platform: write terminal: %w", err)
	}
	return nil
}

// sortedHolders orders holders by pid then path (deterministic results).
func sortedHolders(h []Holder) []Holder {
	sort.Slice(h, func(i, j int) bool {
		if h[i].Proc.ID.PID != h[j].Proc.ID.PID {
			return h[i].Proc.ID.PID < h[j].Proc.ID.PID
		}
		return h[i].Path < h[j].Path
	})
	return h
}

// parseLsof reads `lsof -F pn0` output: NUL-terminated fields, each set
// terminated by a newline, 'p' starting a process and 'n' naming a file.
func parseLsof(out []byte) map[int][]string {
	res := map[int][]string{}
	pid := 0
	for _, tok := range bytes.Split(out, []byte{0}) {
		tok = bytes.TrimLeft(tok, "\n")
		if len(tok) == 0 {
			continue
		}
		switch tok[0] {
		case 'p':
			n := 0
			for _, c := range tok[1:] {
				if c < '0' || c > '9' {
					n = 0
					break
				}
				n = n*10 + int(c-'0')
			}
			pid = n
		case 'n':
			if pid > 0 {
				res[pid] = append(res[pid], string(tok[1:]))
			}
		}
	}
	return res
}

// lsofHolders lists open files below dirs with lsof (the fallback when the
// kernel interface is unavailable). lsof exits 1 whenever one of its search
// names is not open, so success is judged by stderr, not the exit status.
func lsofHolders(ctx context.Context, dirs []string) ([]Holder, error) {
	args := []string{"-w", "-n", "-P", "-F", "pn0"}
	for _, d := range dirs {
		if _, err := os.Lstat(d); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // nothing can be open below a missing directory
			}
			return nil, fmt.Errorf("platform: open files: %w", err)
		}
		args = append(args, "+D", d)
	}
	if len(args) == 5 {
		return []Holder{}, nil
	}
	out, stderr, err := runTool(ctx, 60*time.Second, "/usr/sbin/lsof", args...)
	var exitErr *exec.ExitError
	if err != nil && !(errors.As(err, &exitErr) && exitErr.ExitCode() == 1 && len(bytes.TrimSpace(stderr)) == 0) {
		return nil, fmt.Errorf("platform: lsof: %w", err)
	}
	roots := resolvedRoots(dirs)
	var hs []Holder
	for pid, names := range parseLsof(out) {
		info, err := sysLookup(pid)
		if err != nil {
			continue // exited since lsof saw it: holds nothing any more
		}
		seen := map[string]bool{}
		for _, n := range names {
			if seen[n] || !withinAny(roots, n) {
				continue
			}
			seen[n] = true
			hs = append(hs, Holder{Proc: info, Path: n})
		}
	}
	return sortedHolders(append([]Holder{}, hs...)), nil
}

// readSmall reads a small /proc or /sys file (bounded).
func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}
