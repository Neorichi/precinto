//go:build darwin || linux

package platform_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/platform"
)

// Every process these tests signal is a child the test started itself
// (startChild); nothing else is ever signalled.

// child is a process started by the test, killed at cleanup.
type child struct {
	cmd *exec.Cmd
	id  platform.ProcID
}

// startChild starts argv (absolute) with an empty environment in dir and
// waits until the kernel shows it with exec done (exe path changed from the
// test binary), so identity measurements are stable.
func startChild(t *testing.T, dir string, setsid bool, argv ...string) *child {
	t.Helper()
	cmd := &exec.Cmd{Path: argv[0], Args: argv, Env: []string{}, Dir: dir}
	if setsid {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &child{cmd: cmd}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill() // our own child only
			_, _ = cmd.Process.Wait()
		}
	})
	self, _ := os.Executable()
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, err := platform.System().Lookup(cmd.Process.Pid)
		if err == nil && info.Exe != "" && info.Exe != self && len(info.Argv) > 0 {
			c.id = info.ID
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("child %v never showed up exec'd: %+v %v", argv, info, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (c *child) wait(t *testing.T) {
	t.Helper()
	if c.cmd.ProcessState == nil {
		_ = c.cmd.Wait()
	}
}

func realDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSelfAndIdentify(t *testing.T) {
	self := platform.Self()
	if self.PID != os.Getpid() || self.StartUS <= 0 {
		t.Fatalf("Self = %+v", self)
	}
	id, err := platform.Identify(os.Getpid())
	if err != nil || id != self {
		t.Fatalf("Identify(self) = %+v, %v; Self = %+v", id, err, self)
	}
	if !platform.System().Alive(self) {
		t.Fatal("self not alive")
	}
	back, err := platform.ParseProcID(self.String())
	if err != nil || back != self {
		t.Fatalf("ParseProcID(String()) = %+v, %v, want %+v", back, err, self)
	}
	if _, err := platform.Identify(0); !errors.Is(err, platform.ErrNoProcess) {
		t.Fatalf("Identify(0) = %v", err)
	}
	if _, err := platform.Identify(1 << 30); !errors.Is(err, platform.ErrNoProcess) {
		t.Fatalf("Identify(huge) = %v", err)
	}
	if platform.System().Alive(platform.ProcID{}) {
		t.Fatal("zero id alive")
	}
}

func TestLookupChildAndReuse(t *testing.T) {
	dir := realDir(t)
	c := startChild(t, dir, false, "/bin/sleep", "30")
	tbl := platform.System()
	info, err := tbl.Lookup(c.id.PID)
	if err != nil {
		t.Fatal(err)
	}
	if info.PPID != os.Getpid() || info.UID != os.Geteuid() || info.State != platform.StateRunning {
		t.Fatalf("info = %+v", info)
	}
	if filepath.Base(info.Exe) != "sleep" || len(info.Argv) != 2 || info.Argv[1] != "30" {
		t.Fatalf("exe/argv = %q %q", info.Exe, info.Argv)
	}
	mySID := mustLookup(t, os.Getpid()).SID
	if info.SID == 0 || info.SID != mySID {
		t.Fatalf("child SID %d, want ours %d", info.SID, mySID)
	}
	if !tbl.Alive(c.id) {
		t.Fatal("child not alive")
	}
	// Same pid, another start time: another incarnation (R9).
	other := c.id
	other.StartUS++
	if tbl.Alive(other) {
		t.Fatal("a different start time counted as the same process")
	}
	list, err := tbl.List()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range list {
		if p.UID != os.Geteuid() {
			t.Fatalf("List returned another uid: %+v", p)
		}
		if p.ID == c.id || p.ID == platform.Self() {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("List misses self or child (%d)", found)
	}
}

func mustLookup(t *testing.T, pid int) platform.ProcInfo {
	t.Helper()
	p, err := platform.System().Lookup(pid)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestZombieCountsAsExited(t *testing.T) {
	c := startChild(t, "/", false, "/bin/sh", "-c", "exec /bin/sleep 0.2")
	deadline := time.Now().Add(10 * time.Second)
	for {
		info, err := platform.System().Lookup(c.id.PID)
		if err == nil && info.State == platform.StateZombie {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child never became a zombie: %+v %v", info, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if platform.System().Alive(c.id) {
		t.Fatal("zombie counted as alive")
	}
	if _, err := platform.Identify(c.id.PID); !errors.Is(err, platform.ErrNoProcess) {
		t.Fatalf("Identify(zombie) = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := platform.WaitExit(ctx, c.id); err != nil {
		t.Fatalf("WaitExit(zombie) = %v (LIVE-4: --wait-pid returns)", err)
	}
	if _, err := platform.System().Cwd(c.id); !errors.Is(err, platform.ErrNotSame) {
		t.Fatalf("Cwd(zombie) = %v", err)
	}
	c.wait(t)
}

func TestWaitExit(t *testing.T) {
	c := startChild(t, "/", false, "/bin/sleep", "0.3")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := platform.WaitExit(ctx, c.id); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Fatal("WaitExit returned before the child exited")
	}
	c.wait(t)

	long := startChild(t, "/", false, "/bin/sleep", "30")
	ctx2, cancel2 := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel2()
	if err := platform.WaitExit(ctx2, long.id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitExit on a live process = %v, want deadline", err)
	}
	// A stale identity of a live pid is "exited" (that incarnation is gone).
	stale := long.id
	stale.StartUS--
	if err := platform.WaitExit(context.Background(), stale); err != nil {
		t.Fatalf("WaitExit(stale id) = %v", err)
	}
}

func TestSignalReverifies(t *testing.T) {
	c := startChild(t, "/", false, "/bin/sleep", "30")
	wrong := c.id
	wrong.StartUS++
	if err := platform.Signal(wrong, syscall.SIGKILL); !errors.Is(err, platform.ErrNotSame) {
		t.Fatalf("Signal(wrong start) = %v, want ErrNotSame", err)
	}
	if !platform.System().Alive(c.id) {
		t.Fatal("a mismatched identity was signalled")
	}
	for _, bad := range []platform.ProcID{{}, {PID: 1, StartUS: 5}, {PID: 0, StartUS: 5}, {PID: -1, StartUS: 5}, {PID: c.id.PID}} {
		if err := platform.Signal(bad, 0); err == nil {
			t.Fatalf("Signal(%+v) accepted", bad)
		}
	}
	if err := platform.Signal(c.id, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err := c.cmd.Wait()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
		t.Fatalf("child did not die of SIGTERM: %v", err)
	}
	if err := platform.Signal(c.id, syscall.SIGTERM); !errors.Is(err, platform.ErrNoProcess) && !errors.Is(err, platform.ErrNotSame) {
		t.Fatalf("Signal(exited) = %v", err)
	}
}

func TestSignalGroupOnlyTheSetsidSession(t *testing.T) {
	// leader (Setsid) with a background member, and a sibling in our session.
	leader := startChild(t, "/", true, "/bin/sh", "-c", "/bin/sleep 30 & exec /bin/sleep 31")
	sibling := startChild(t, "/", false, "/bin/sleep", "32")
	var member platform.ProcInfo
	deadline := time.Now().Add(5 * time.Second)
	for member.ID.IsZero() {
		list, err := platform.System().List()
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range list {
			if p.SID == leader.id.PID && p.ID.PID != leader.id.PID && filepath.Base(p.Exe) == "sleep" {
				member = p
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("background member of the child's session not found")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if mustLookup(t, leader.id.PID).SID != leader.id.PID {
		t.Fatal("Setsid child is not a session leader")
	}
	mySID := mustLookup(t, os.Getpid()).SID
	if err := platform.SignalGroup(mySID, 0); err == nil {
		t.Fatal("SignalGroup accepted the caller's own session (the user's terminal session)")
	}
	if err := platform.SignalGroup(1, 0); err == nil {
		t.Fatal("SignalGroup accepted session 1")
	}
	if err := platform.SignalGroup(leader.id.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	leader.wait(t)
	deadline = time.Now().Add(10 * time.Second)
	for platform.System().Alive(member.ID) {
		if time.Now().After(deadline) {
			t.Fatal("session member survived SignalGroup")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !platform.System().Alive(sibling.id) || !platform.System().Alive(platform.Self()) {
		t.Fatal("SignalGroup reached a process outside the child's session (SEC-30)")
	}
}

func TestCwdAndOpenFiles(t *testing.T) {
	dir := realDir(t)
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(sub, "held.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := startChild(t, sub, false, "/bin/sh", "-c", `exec 3< "$0"; exec /bin/sleep 30`, file)
	tbl := platform.System()
	cwd, err := tbl.Cwd(c.id)
	if err != nil || cwd != sub {
		t.Fatalf("Cwd = %q, %v, want %q", cwd, err, sub)
	}
	stale := c.id
	stale.StartUS++
	if _, err := tbl.Cwd(stale); !errors.Is(err, platform.ErrNotSame) {
		t.Fatalf("Cwd(stale) = %v", err)
	}
	ctx := context.Background()
	var hs []platform.Holder
	deadline := time.Now().Add(5 * time.Second)
	for {
		hs, err = tbl.OpenFilesUnder(ctx, []string{dir})
		if err != nil {
			t.Fatal(err)
		}
		if holds(hs, c.id.PID, file) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("holder of %s not found: %+v", file, hs)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, h := range hs {
		if !strings.HasPrefix(h.Path, dir+"/") && h.Path != dir {
			t.Fatalf("holder outside the directory: %+v", h)
		}
	}
	// The directory is given unresolved (darwin /var → /private/var).
	if alias := strings.TrimPrefix(dir, "/private"); alias != dir {
		hs2, err := tbl.OpenFilesUnder(ctx, []string{alias})
		if err != nil || !holds(hs2, c.id.PID, file) {
			t.Fatalf("unresolved directory: %+v %v", hs2, err)
		}
	}
	none, err := tbl.OpenFilesUnder(ctx, []string{filepath.Join(dir, "missing")})
	if err != nil || len(none) != 0 {
		t.Fatalf("missing dir: %+v %v", none, err)
	}
	if _, err := tbl.OpenFilesUnder(ctx, []string{"relative"}); err == nil {
		t.Fatal("relative directory accepted")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := tbl.OpenFilesUnder(cctx, []string{dir}); err == nil {
		t.Fatal("cancelled context accepted")
	}
}

func holds(hs []platform.Holder, pid int, path string) bool {
	for _, h := range hs {
		if h.Proc.ID.PID == pid && h.Path == path {
			return true
		}
	}
	return false
}

func TestSpawnDetached(t *testing.T) {
	dir := realDir(t)
	log := filepath.Join(dir, "out.log")
	id, err := platform.Spawn([]string{"/bin/sh", "-c", `echo "x=$X home=${HOME-unset}"; pwd`},
		platform.SpawnOptions{Dir: dir, Env: []string{"X=1"}, LogPath: log})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := platform.WaitExit(ctx, id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		b, _ := os.ReadFile(log)
		return strings.Contains(string(b), dir)
	})
	b, _ := os.ReadFile(log)
	if !strings.Contains(string(b), "x=1 home=unset") {
		t.Fatalf("log = %q (the child must see exactly the given environment)", b)
	}
	if st, err := os.Stat(log); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("log mode: %v %v", st, err)
	}

	sl, err := platform.Spawn([]string{"/bin/sleep", "30"}, platform.SpawnOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = platform.Signal(sl, syscall.SIGKILL) }) // our own spawned child
	if info := mustLookup(t, sl.PID); info.SID != sl.PID || info.ID != sl {
		t.Fatalf("spawned child is not detached in its own session: %+v vs %+v", info, sl)
	}
	if err := platform.Signal(sl, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := platform.WaitExit(ctx, sl); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.Spawn([]string{"sleep", "1"}, platform.SpawnOptions{}); err == nil {
		t.Fatal("relative argv[0] accepted")
	}
	if _, err := platform.Spawn(nil, platform.SpawnOptions{}); err == nil {
		t.Fatal("empty argv accepted")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition never became true")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestExecutableIdentity(t *testing.T) {
	p, dev, ino, err := platform.Executable()
	if err != nil || !filepath.IsAbs(p) || ino == 0 {
		t.Fatalf("Executable = %q %d %d %v", p, dev, ino, err)
	}
	same, err := platform.SameExecutable(os.Getpid())
	if err != nil || !same {
		t.Fatalf("SameExecutable(self) = %v %v", same, err)
	}
	c := startChild(t, "/", false, "/bin/sleep", "30")
	same, err = platform.SameExecutable(c.id.PID)
	if err != nil || same {
		t.Fatalf("SameExecutable(sleep) = %v %v", same, err)
	}
	if _, err := platform.SameExecutable(1 << 30); err == nil {
		t.Fatal("SameExecutable(missing pid) without error")
	}
	// A copy of the test binary is another file (D6 compares dev+inode).
	cp := filepath.Join(realDir(t), "copy.test")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, b, 0o700); err != nil {
		t.Fatal(err)
	}
	other := startChild(t, "/", false, cp, "-test.run=^TestHelperSleep$", "--", "helper-sleep")
	if !platform.System().Alive(other.id) {
		t.Fatal("helper copy exited early")
	}
	if same, err := platform.SameExecutable(other.id.PID); same || err != nil {
		t.Fatalf("a copy of the binary: same=%v err=%v (D6 compares dev+inode)", same, err)
	}
}

// TestHelperSleep is the body of helper processes: it sleeps only when the
// test binary runs with the "helper-sleep" argument (it is a no-op test
// otherwise).
func TestHelperSleep(t *testing.T) {
	for i, a := range os.Args {
		if a == "--" && i+1 < len(os.Args) && os.Args[i+1] == "helper-sleep" {
			time.Sleep(30 * time.Second)
			os.Exit(0)
		}
	}
}
