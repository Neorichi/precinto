//go:build darwin || linux

package platform_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
)

func TestPeerOfSocketpair(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "sock")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c.(*net.UnixConn)
		defer c.Close()
	}
	p, err := platform.PeerOf(conns[0])
	if err != nil {
		t.Fatal(err)
	}
	if p.UID != os.Getuid() || p.PID != os.Getpid() || p.Proc.ID != platform.Self() {
		t.Fatalf("peer = %+v, self %+v", p, platform.Self())
	}
	if _, err := platform.PeerOf(nil); err == nil {
		t.Fatal("nil connection accepted")
	}
}

// TestHardenInChild runs Harden in a re-executed copy of the test binary:
// the go test process itself is never hardened.
func TestHardenInChild(t *testing.T) {
	if os.Getenv("PRECINTO_PLATFORM_HARDEN_CHILD") == "1" {
		hardenChild()
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestHardenInChild$", "-test.count=1")
	cmd.Env = []string{"PRECINTO_PLATFORM_HARDEN_CHILD=1", "HOME=/nonexistent"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("harden ok core=0/0")) {
		t.Fatalf("child output:\n%s", out)
	}
}

func hardenChild() {
	if err := platform.Harden(); err != nil {
		os.Stdout.WriteString("harden error: " + err.Error() + "\n")
		os.Exit(3)
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		os.Exit(4)
	}
	if lim.Cur != 0 || lim.Max != 0 {
		os.Stdout.WriteString("core limit not zero\n")
		os.Exit(5)
	}
	if extra := hardenedExtra(); extra != "" {
		os.Stdout.WriteString(extra + "\n")
		os.Exit(6)
	}
	os.Stdout.WriteString("harden ok core=0/0\n")
	os.Exit(0)
}

func TestCheckLoaderEnv(t *testing.T) {
	if err := platform.CheckLoaderEnv([]string{"HOME=/h", "PATH=/bin"}); err != nil {
		t.Fatal(err)
	}
	if err := platform.CheckLoaderEnv([]string{"DYLD_INSERT_LIBRARIES=/tmp/x.dylib"}); !errors.Is(err, platform.ErrUnsafeEnv) {
		t.Fatalf("DYLD_* = %v", err)
	}
	if err := platform.CheckLoaderEnv([]string{"LD_PRELOAD=/tmp/x.so"}); !errors.Is(err, platform.ErrUnsafeEnv) {
		t.Fatalf("LD_* = %v", err)
	}
}

func TestWatchJumpsFakeClock(t *testing.T) {
	c := fakeplatform.NewClock(time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC))
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan platform.Jump, 4)
	done := make(chan struct{})
	go func() { platform.WatchJumps(ctx, c, time.Millisecond, 30*time.Second, out); close(done) }()
	time.Sleep(10 * time.Millisecond)
	c.Advance(time.Hour) // both clocks: no jump
	c.StepWall(-time.Hour)
	time.Sleep(30 * time.Millisecond)
	select {
	case j := <-out:
		t.Fatalf("unexpected jump %+v", j)
	default:
	}
	c.Sleep(2 * time.Hour) // wall only: the machine slept
	select {
	case j := <-out:
		if j.Wall < 2*time.Hour || j.Mono != 0 || j.At.IsZero() {
			t.Fatalf("jump = %+v", j)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sleep not detected")
	}
	c.StepWall(20 * time.Second) // below the threshold
	time.Sleep(30 * time.Millisecond)
	select {
	case j := <-out:
		t.Fatalf("small step reported: %+v", j)
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WatchJumps did not stop")
	}
}

func TestSystemClock(t *testing.T) {
	c := platform.SystemClock()
	m1 := c.Mono()
	time.Sleep(5 * time.Millisecond)
	if m2 := c.Mono(); m2-m1 < 5*time.Millisecond {
		t.Fatalf("monotonic did not advance: %v → %v", m1, m2)
	}
	now := c.Now()
	if now != now.Round(0) || time.Since(now) > time.Minute {
		t.Fatalf("Now = %v (must carry no monotonic reading)", now)
	}
}

func TestDetectUIContext(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	u := platform.DetectUIContext(paths.FromMap(map[string]string{"TMUX": "/tmp/x,1,0"}), r, w)
	if u.TTY || !u.Tmux || u.SSH || u.GUI {
		t.Fatalf("tmux over pipes: %+v", u)
	}
	u = platform.DetectUIContext(paths.FromMap(map[string]string{"SSH_CONNECTION": "a b c d"}), nil, nil)
	if u.TTY || !u.SSH || u.GUI {
		t.Fatalf("ssh: %+v", u)
	}
	u = platform.DetectUIContext(paths.FromMap(map[string]string{"STY": "1.pts"}), nil, nil)
	if !u.Tmux || u.GUI {
		t.Fatalf("screen: %+v", u)
	}
	m, slave := openPTY(t)
	defer m.Close()
	s, err := os.OpenFile(slave, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if u := platform.DetectUIContext(paths.FromMap(nil), s, s); !u.TTY {
		t.Fatalf("pty not detected as a terminal: %+v", u)
	}
	if u := platform.DetectUIContext(paths.FromMap(nil), s, w); u.TTY {
		t.Fatalf("stdout pipe counted as a terminal: %+v", u)
	}
}

func TestScrubTTY(t *testing.T) {
	m, slave := openPTY(t)
	defer m.Close()
	s, err := os.OpenFile(slave, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got := make(chan []byte, 1)
	go func() {
		var all []byte
		buf := make([]byte, 4096)
		_ = m.SetReadDeadline(time.Now().Add(5 * time.Second))
		for !bytes.Contains(all, []byte("ended-and-sealed")) {
			n, err := m.Read(buf)
			all = append(all, buf[:n]...)
			if err != nil {
				break
			}
		}
		got <- all
	}()
	err = platform.ScrubTTY(slave, platform.ScrubOptions{Clear: true, ITerm: true, Banner: "ended-and-sealed\x1b[31m\x07"})
	if err != nil {
		t.Fatal(err)
	}
	out := <-got
	for _, want := range []string{"\x1b[?1049l", "\x1b[?2004l", "\x1b[<99u", "\x1b[0m", "\x1b[H\x1b[2J\x1b[3J", "\x1b]1337;ClearScrollback", "ended-and-sealed[31m"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Fatalf("scrub output misses %q: %q", want, out)
		}
	}
	if bytes.Contains(out, []byte("\x1b[31m")) || bytes.Contains(out, []byte{7}) {
		t.Fatalf("banner control characters were written: %q", out)
	}
	for _, bad := range []string{"", "relative", "/dev/../etc/passwd", os.DevNull + "x"} {
		if err := platform.ScrubTTY(bad, platform.ScrubOptions{}); err == nil {
			t.Errorf("ScrubTTY(%q) accepted", bad)
		}
	}
	if err := platform.ScrubTTY(os.DevNull, platform.ScrubOptions{}); err == nil || !strings.Contains(err.Error(), "owned") {
		t.Errorf("ScrubTTY(/dev/null) = %v (not owned by the user)", err)
	}
}

func TestReadScreenSmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := platform.ReadScreen(ctx)
	if s.At.IsZero() {
		t.Fatalf("ReadScreen = %+v, %v: At unset", s, err)
	}
}

// TestHardenedProcessStaysIdentifiable checks that a hardened precinto
// process can still be measured and authenticated by its peers (D6): on
// darwin PT_DENY_ATTACH does not hide the executable path. On linux a
// non-dumpable process denies /proc/<pid>/exe to non-root peers, so the
// check fails closed there (reported to the lead).
func TestHardenedProcessStaysIdentifiable(t *testing.T) {
	if os.Getenv("PRECINTO_PLATFORM_HARDEN_SLEEP") == "1" {
		if err := platform.Harden(); err != nil {
			os.Exit(3)
		}
		os.Stdout.WriteString("hardened\n")
		go func() {
			time.Sleep(helperLifetime)
			os.Exit(71)
		}()
		_, _ = io.Copy(io.Discard, os.Stdin) // the lifeline: the test holds the other end
		os.Exit(0)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestHardenedProcessStaysIdentifiable$", "-test.count=1")
	cmd.Env = []string{"PRECINTO_PLATFORM_HARDEN_SLEEP=1", "HOME=/nonexistent"}
	lifeR, lifeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = lifeR
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lifeR.Close()
	t.Cleanup(func() { lifeW.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }) // our own child
	buf := make([]byte, 9)
	if _, err := io.ReadFull(out, buf); err != nil || string(buf) != "hardened\n" {
		t.Fatalf("child did not harden: %q %v", buf, err)
	}
	id, err := platform.Identify(cmd.Process.Pid)
	if err != nil || !platform.System().Alive(id) {
		t.Fatalf("hardened child not identifiable: %v", err)
	}
	same, err := platform.SameExecutable(cmd.Process.Pid)
	if runtime.GOOS == "linux" {
		if same {
			t.Fatal("linux: identity proven for a non-dumpable process")
		}
		t.Skipf("linux: a non-dumpable peer's executable cannot be read (%v); reported", err)
	}
	if err != nil || !same {
		t.Fatalf("SameExecutable(hardened child) = %v, %v", same, err)
	}
}
