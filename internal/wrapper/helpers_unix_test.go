//go:build darwin || linux

package wrapper_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/awnumar/memguard"
	"github.com/creack/pty"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/wrapper"
)

// waitTimeout bounds every wait, so a broken wrapper fails instead of
// hanging the test binary.
const waitTimeout = 10 * time.Second

// startEnv is the test process environment, read once through paths.
var startEnv = paths.FromOS()

// ---------------------------------------------------------------------------
// Helper binaries (testdata main packages), built once per test binary.

var (
	helpersOnce sync.Once
	helpersDir  string
	helpersErr  error
)

type helperBins struct {
	tui      string // testdata/tuichild
	jobshell string // testdata/jobshell
}

func helpers(t *testing.T) helperBins {
	t.Helper()
	helpersOnce.Do(func() {
		dir, err := os.MkdirTemp("", "precinto-wrapper-helpers-")
		if err != nil {
			helpersErr = err
			return
		}
		helpersDir = dir
		gotool, err := goTool()
		if err != nil {
			helpersErr = err
			return
		}
		cmd := exec.Command(gotool, "build", "-o", dir+string(os.PathSeparator), "./testdata/tuichild", "./testdata/jobshell")
		cmd.Env = buildEnv()
		out, err := cmd.CombinedOutput()
		if err != nil {
			helpersErr = fmt.Errorf("go build helpers: %v\n%s", err, out)
		}
	})
	if helpersErr != nil {
		t.Fatal(helpersErr)
	}
	return helperBins{tui: filepath.Join(helpersDir, "tuichild"), jobshell: filepath.Join(helpersDir, "jobshell")}
}

// goTool returns the first go command that runs: the toolchain of `go
// test` (GOROOT), else the first on PATH (a broken one is skipped).
func goTool() (string, error) {
	var candidates []string
	if r := startEnv.Get("GOROOT"); filepath.IsAbs(r) {
		candidates = append(candidates, filepath.Join(r, "bin", "go"))
	}
	for _, dir := range filepath.SplitList(startEnv.Get("PATH")) {
		if filepath.IsAbs(dir) {
			candidates = append(candidates, filepath.Join(dir, "go"))
		}
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		v := exec.Command(c, "version")
		v.Env = buildEnv()
		if v.Run() == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("no working go command (GOROOT %q)", startEnv.Get("GOROOT"))
}

// buildEnv keeps the toolchain configuration of the test process only.
func buildEnv() []string {
	keep := map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "USER": true, "LOGNAME": true, "XDG_CACHE_HOME": true}
	var env []string
	for _, kv := range startEnv.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "GOOS" || k == "GOARCH" || k == "GOTOOLCHAIN" {
			continue
		}
		if keep[k] || strings.HasPrefix(k, "GO") || strings.HasPrefix(k, "CGO_") {
			env = append(env, kv)
		}
	}
	return append(env, "GOTOOLCHAIN=local", "CGO_ENABLED=0")
}

// childEnv is the minimal environment of a scripted child.
func childEnv(t *testing.T) paths.Env {
	return paths.FromMap(map[string]string{
		"TERM": "xterm-256color",
		"HOME": t.TempDir(),
		"PATH": "/usr/bin:/bin",
	})
}

// ---------------------------------------------------------------------------
// A pseudo-terminal pair standing in for the user's terminal: the test reads
// what the wrapper writes from the master and types into it.

type termPair struct {
	t      *testing.T
	master *os.File
	slave  *os.File
	mfd    int

	mu  sync.Mutex
	out bytes.Buffer

	stop atomic.Bool
	done chan struct{}
}

func newTerm(t *testing.T, cols, rows int) *termPair {
	t.Helper()
	m, s, err := pty.Open()
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	if err := pty.Setsize(m, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}); err != nil {
		t.Fatal(err)
	}
	tp := &termPair{t: t, master: m, slave: s, mfd: int(m.Fd()), done: make(chan struct{})}
	go tp.readLoop()
	t.Cleanup(tp.close)
	return tp
}

func (tp *termPair) readLoop() {
	defer close(tp.done)
	buf := make([]byte, 64<<10)
	for !tp.stop.Load() {
		ready, err := wrapper.WaitReadable(tp.mfd, 20*time.Millisecond)
		if err != nil {
			return
		}
		if !ready {
			continue
		}
		n, err := syscall.Read(tp.mfd, buf)
		if n > 0 {
			tp.mu.Lock()
			tp.out.Write(buf[:n])
			tp.mu.Unlock()
		}
		if err != nil && err != syscall.EINTR && err != syscall.EAGAIN {
			return
		}
		if n == 0 && err == nil {
			return
		}
	}
}

func (tp *termPair) close() {
	tp.stop.Store(true)
	<-tp.done
	_ = tp.slave.Close()
	_ = tp.master.Close()
}

// output returns everything written so far.
func (tp *termPair) output() string {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.out.String()
}

// mark returns the current output length (a position for since).
func (tp *termPair) mark() int {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.out.Len()
}

// since returns the output written after mark.
func (tp *termPair) since(mark int) string {
	s := tp.output()
	if mark > len(s) {
		return ""
	}
	return s[mark:]
}

// waitFor waits until sub appears after from and returns the position just
// past it.
func (tp *termPair) waitFor(sub string, from int) int {
	tp.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if i := strings.Index(tp.since(from), sub); i >= 0 {
			return from + i + len(sub)
		}
		time.Sleep(10 * time.Millisecond)
	}
	tp.t.Fatalf("timed out waiting for %q; output after mark:\n%q", sub, tail(tp.since(from), 3000))
	return 0
}

// waitForRe waits for a regular expression and returns its submatches.
func (tp *termPair) waitForRe(re *regexp.Regexp, from int) []string {
	tp.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(tp.since(from)); m != nil {
			return m
		}
		time.Sleep(10 * time.Millisecond)
	}
	tp.t.Fatalf("timed out waiting for %v; output:\n%q", re, tail(tp.since(from), 3000))
	return nil
}

// quiet waits d and asserts sub did not appear after from.
func (tp *termPair) never(sub string, from int, d time.Duration) {
	tp.t.Helper()
	time.Sleep(d)
	if strings.Contains(tp.since(from), sub) {
		tp.t.Fatalf("unexpected %q in output:\n%q", sub, tail(tp.since(from), 3000))
	}
}

func (tp *termPair) typeKeys(s string) {
	tp.t.Helper()
	if _, err := tp.master.Write([]byte(s)); err != nil {
		tp.t.Fatal(err)
	}
}

func (tp *termPair) resize(cols, rows int) {
	tp.t.Helper()
	if err := pty.Setsize(tp.master, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}); err != nil {
		tp.t.Fatal(err)
	}
}

var inRe = regexp.MustCompile(`IN:([0-9a-f]+)`)

// received returns every input byte the scripted child reported after mark
// (it prints one IN:<hex> line per read).
func (tp *termPair) received(mark int) string {
	var all []byte
	for _, m := range inRe.FindAllStringSubmatch(tp.since(mark), -1) {
		b, err := hex.DecodeString(m[1])
		if err == nil {
			all = append(all, b...)
		}
	}
	return string(all)
}

// waitReceived waits until the child reported receiving want after mark.
func (tp *termPair) waitReceived(want string, mark int) {
	tp.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if strings.Contains(tp.received(mark), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	tp.t.Fatalf("the child did not receive %q; it got %q", want, tp.received(mark))
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

var readyRe = regexp.MustCompile(`READY pid=(\d+) pgid=(\d+) sid=(\d+) tty=(\w+) active=(\S*)`)

type ready struct {
	pid, pgid, sid int
	tty            bool
	active         string
}

func parseReady(m []string) ready {
	atoi := func(s string) int { v, _ := strconv.Atoi(s); return v }
	return ready{pid: atoi(m[1]), pgid: atoi(m[2]), sid: atoi(m[3]), tty: m[4] == "true", active: m[5]}
}

// ---------------------------------------------------------------------------
// Liveness pipes: a process holding the write end keeps the read end open,
// so EOF on the read end proves every holder exited (no signal is sent to
// check).

type lifeline struct {
	r, w *os.File
	eof  chan struct{}
}

func newLifeline(t *testing.T) *lifeline {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	l := &lifeline{r: r, w: w, eof: make(chan struct{})}
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := r.Read(buf); err != nil {
				close(l.eof)
				return
			}
		}
	}()
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return l
}

// testSibling starts a process in the test's own session (a stand-in for
// the user's shell job) holding life.
func testSibling(t *testing.T, tui string, life *lifeline) *exec.Cmd {
	t.Helper()
	sib := exec.Command(tui, "sleep")
	sib.Env = []string{}
	sib.ExtraFiles = []*os.File{life.w}
	if err := sib.Start(); err != nil {
		t.Fatal(err)
	}
	life.handOff()
	return sib
}

// handOff closes the test's write end once a child holds its own copy.
func (l *lifeline) handOff() { _ = l.w.Close() }

func (l *lifeline) closedWithin(d time.Duration) bool {
	select {
	case <-l.eof:
		return true
	case <-time.After(d):
		return false
	}
}

// ---------------------------------------------------------------------------
// Fakes of the wrapper's seams (docs/OWNERSHIP.md §4: G6 tests fake
// Backend, Daemon and Lease).

type fakeServer struct {
	mu          sync.Mutex
	subs        []*fakeSub
	subReqs     []ipc.SubscribeReq
	registers   []ipc.RegisterReq
	unregisters []ipc.UnregisterReq
	activity    []ipc.ActivityReq
	unlocks     []ipc.UnlockReq
	dials       int
	heartbeats  atomic.Bool
	unlockFn    func(ctx context.Context, r ipc.UnlockReq, ui ipc.UIHandler) (ipc.UnlockResp, error)
}

type fakeSub struct {
	ch     chan ipc.Event
	once   sync.Once
	closed chan struct{}
}

func (s *fakeSub) close() { s.once.Do(func() { close(s.closed) }) }

func newFakeServer() *fakeServer {
	s := &fakeServer{}
	s.heartbeats.Store(true)
	return s
}

// publish sends ev to every live subscription.
func (s *fakeServer) publish(ev ipc.Event) {
	s.mu.Lock()
	subs := append([]*fakeSub(nil), s.subs...)
	s.mu.Unlock()
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	for _, sub := range subs {
		select {
		case sub.ch <- ev:
		case <-sub.closed:
		case <-time.After(time.Second):
		}
	}
}

func (s *fakeServer) activities() []ipc.ActivityReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ipc.ActivityReq(nil), s.activity...)
}

func (s *fakeServer) registrations() []ipc.RegisterReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ipc.RegisterReq(nil), s.registers...)
}

// dropSubscriptions closes every stream (a daemon restart).
func (s *fakeServer) dropSubscriptions() {
	s.mu.Lock()
	subs := s.subs
	s.subs = nil
	s.mu.Unlock()
	for _, sub := range subs {
		sub.close()
	}
}

type fakeDaemon struct {
	srv    *fakeServer
	mu     sync.Mutex
	closed bool
	subs   []*fakeSub
}

var _ wrapper.Daemon = (*fakeDaemon)(nil)

func (d *fakeDaemon) Register(ctx context.Context, r ipc.RegisterReq) error {
	d.srv.mu.Lock()
	defer d.srv.mu.Unlock()
	d.srv.registers = append(d.srv.registers, r)
	return nil
}

func (d *fakeDaemon) Unregister(ctx context.Context, r ipc.UnregisterReq) error {
	d.srv.mu.Lock()
	defer d.srv.mu.Unlock()
	d.srv.unregisters = append(d.srv.unregisters, r)
	return nil
}

func (d *fakeDaemon) Activity(ctx context.Context, r ipc.ActivityReq) error {
	d.srv.mu.Lock()
	defer d.srv.mu.Unlock()
	d.srv.activity = append(d.srv.activity, r)
	return nil
}

func (d *fakeDaemon) Unlock(ctx context.Context, r ipc.UnlockReq, ui ipc.UIHandler) (ipc.UnlockResp, error) {
	d.srv.mu.Lock()
	d.srv.unlocks = append(d.srv.unlocks, r)
	fn := d.srv.unlockFn
	d.srv.mu.Unlock()
	if fn == nil {
		return ipc.UnlockResp{}, &ipc.Error{Code: ipc.CodeCancelled, Msg: "cancelled"}
	}
	return fn(ctx, r, ui)
}

// Subscribe streams published events plus a heartbeat every 50 ms (while
// heartbeats are on); the stream closes with the connection.
func (d *fakeDaemon) Subscribe(ctx context.Context, r ipc.SubscribeReq) (<-chan ipc.Event, error) {
	sub := &fakeSub{ch: make(chan ipc.Event, 64), closed: make(chan struct{})}
	d.srv.mu.Lock()
	d.srv.subs = append(d.srv.subs, sub)
	d.srv.subReqs = append(d.srv.subReqs, r)
	d.srv.mu.Unlock()
	d.mu.Lock()
	d.subs = append(d.subs, sub)
	d.mu.Unlock()
	out := make(chan ipc.Event)
	go func() {
		defer close(out)
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case ev := <-sub.ch:
				select {
				case out <- ev:
				case <-sub.closed:
					return
				case <-ctx.Done():
					return
				}
			case <-tick.C:
				if !d.srv.heartbeats.Load() {
					continue
				}
				select {
				case out <- ipc.Event{Kind: ipc.EventHeartbeat, At: time.Now()}:
				case <-sub.closed:
					return
				case <-ctx.Done():
					return
				}
			case <-sub.closed:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func (d *fakeDaemon) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for _, s := range d.subs {
		s.close()
	}
	return nil
}

type fakeLease struct {
	mu       sync.Mutex
	files    []*os.File
	added    []string
	child    platform.ProcID
	released bool
}

var _ wrapper.Lease = (*fakeLease)(nil)

func (l *fakeLease) Add(keys ...string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.added = append(l.added, keys...)
	return nil
}

func (l *fakeLease) SetChild(child platform.ProcID) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.child = child
	return nil
}

func (l *fakeLease) Inheritable() []*os.File { return l.files }

func (l *fakeLease) Release() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.released = true
	return nil
}

func (l *fakeLease) state() (platform.ProcID, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.child, l.released
}

type fakeBackend struct {
	mu    sync.Mutex
	calls []string

	plan        harness.LaunchPlan
	planErr     error
	ensureErr   error
	ensureFn    func(ui ipc.UIHandler) error
	lease       *fakeLease
	restoreSync func(ctx context.Context, abort <-chan struct{}) (wrapper.RestoreSummary, error)
	restoreBG   func(ctx context.Context, abort <-chan struct{})
	srv         *fakeServer
	daemonErr   error
	seal        wrapper.SealSummary
	sealErr     error
	hooksSeen   bool
	launched    platform.ProcID
	sealed      platform.ProcID
	finishCode  atomic.Int64
}

var _ wrapper.Backend = (*fakeBackend)(nil)

func (b *fakeBackend) record(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, name)
}

func (b *fakeBackend) callList() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.calls...)
}

func (b *fakeBackend) called(name string) bool {
	for _, c := range b.callList() {
		if c == name {
			return true
		}
	}
	return false
}

func (b *fakeBackend) Plan(ctx context.Context, h harness.ID, cwd string, argv []string) (harness.LaunchPlan, error) {
	b.record("Plan")
	return b.plan, b.planErr
}

func (b *fakeBackend) EnsureUnlocked(ctx context.Context, roots []config.Root, ui ipc.UIHandler) error {
	b.record("EnsureUnlocked")
	if b.ensureFn != nil {
		return b.ensureFn(ui)
	}
	return b.ensureErr
}

func (b *fakeBackend) AcquireLease(ctx context.Context, plan harness.LaunchPlan) (wrapper.Lease, error) {
	b.record("AcquireLease")
	if b.lease == nil {
		b.lease = &fakeLease{}
	}
	return b.lease, nil
}

func (b *fakeBackend) RestoreSync(ctx context.Context, plan harness.LaunchPlan, abort <-chan struct{}) (wrapper.RestoreSummary, error) {
	b.record("RestoreSync")
	if b.restoreSync != nil {
		return b.restoreSync(ctx, abort)
	}
	return wrapper.RestoreSummary{}, nil
}

func (b *fakeBackend) RestoreBackground(ctx context.Context, plan harness.LaunchPlan, abort <-chan struct{}) {
	b.record("RestoreBackground")
	if b.restoreBG != nil {
		b.restoreBG(ctx, abort)
	}
}

func (b *fakeBackend) Daemon(ctx context.Context) (wrapper.Daemon, error) {
	b.record("Daemon")
	if b.daemonErr != nil {
		return nil, b.daemonErr
	}
	b.srv.mu.Lock()
	b.srv.dials++
	b.srv.mu.Unlock()
	return &fakeDaemon{srv: b.srv}, nil
}

func (b *fakeBackend) RecordLaunch(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) error {
	b.record("RecordLaunch")
	b.mu.Lock()
	b.launched = child
	b.mu.Unlock()
	return nil
}

// waitLaunched waits until Run reported the started child: everything Run
// did before (exec.Cmd.Start among it) happens before the return.
func (b *fakeBackend) waitLaunched(t *testing.T) platform.ProcID {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		id := b.launched
		b.mu.Unlock()
		if !id.IsZero() {
			return id
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("Run never recorded the launch")
	return platform.ProcID{}
}

func (b *fakeBackend) SealAfterExit(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) (wrapper.SealSummary, error) {
	b.record("SealAfterExit")
	b.mu.Lock()
	b.sealed = child
	b.mu.Unlock()
	return b.seal, b.sealErr
}

func (b *fakeBackend) HooksSeen(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) (bool, error) {
	b.record("HooksSeen")
	return b.hooksSeen, nil
}

// managedPlan is an interactive launch of the scripted child in the
// fixture folder.
func managedPlan(h harness.ID, argv ...string) harness.LaunchPlan {
	return harness.LaunchPlan{
		Harness:   h,
		Mode:      harness.LaunchInteractive,
		Roots:     []config.Root{{ID: "root-acme", Path: "/nonexistent/fixture/work/acme"}},
		Argv:      argv,
		HookCheck: harness.HookCheck{Event: "SessionStart", Within: 10 * time.Second},
	}
}

func newFakeBackend(plan harness.LaunchPlan) *fakeBackend {
	return &fakeBackend{plan: plan, srv: newFakeServer(), hooksSeen: true}
}

// syncBuffer is a goroutine-safe io.Writer for Options.Stderr.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fakePrompt answers pre-launch prompts.
type fakePrompt struct {
	yes      bool
	asked    []string
	closed   bool
	secret   string
	displays []string
}

var _ wrapper.PromptUI = (*fakePrompt)(nil)

func (f *fakePrompt) Display(msg string) error { f.displays = append(f.displays, msg); return nil }
func (f *fakePrompt) Secret(prompt string) (*memguard.LockedBuffer, error) {
	f.asked = append(f.asked, prompt)
	return memguard.NewBufferFromBytes([]byte(f.secret)), nil
}
func (f *fakePrompt) Confirm(prompt, yes, no string) (bool, error) {
	f.asked = append(f.asked, prompt)
	return f.yes, nil
}
func (f *fakePrompt) YesNo(prompt string, def bool) (bool, error) {
	f.asked = append(f.asked, prompt)
	return f.yes, nil
}
func (f *fakePrompt) Close() error { f.closed = true; return nil }

// runResult is Run's outcome, delivered asynchronously.
type runResult struct {
	code int
	err  error
}

func startRun(ctx context.Context, o wrapper.Options) <-chan runResult {
	ch := make(chan runResult, 1)
	go func() {
		code, err := wrapper.Run(ctx, o)
		ch <- runResult{code, err}
	}()
	return ch
}

func waitRun(t *testing.T, ch <-chan runResult) runResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * waitTimeout):
		t.Fatal("Run did not return")
		return runResult{}
	}
}
