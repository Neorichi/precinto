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
	helpersOnce   sync.Once
	helpersDir    string
	helpersShared bool // a probe run uses its parent's binaries (helpersEnv)
	helpersErr    error
)

type helperBins struct {
	tui      string // testdata/tuichild
	jobshell string // testdata/jobshell
}

func helpers(t *testing.T) helperBins {
	t.Helper()
	helpersOnce.Do(func() {
		if dir := startEnv.Get(helpersEnv); filepath.IsAbs(dir) {
			helpersDir, helpersShared = dir, true
			return
		}
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

// child is the argv of a scripted child (testdata/tuichild) that gets the
// test's lifeline as fd 3 (the first ExtraFiles entry, or the first of the
// fake lease's descriptors) and carries the token, then args.
func (b helperBins) child(args ...string) []string {
	return append([]string{b.tui, "-lifeline", "3", "-test-token", testToken}, args...)
}

// childWithProbe is child for a scripted child that also gets a liveness
// probe as fd 4 and hands it to every grandchild it spawns.
func (b helperBins) childWithProbe(args ...string) []string {
	return b.child(append([]string{"-probe", "4"}, args...)...)
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
// Lifelines, probes and process cleanup (TESTPLAN §1 rule 8): no helper
// outlives its test.

// lifeline is a pipe whose write end only this test process holds: it is
// never written and never inherited (close-on-exec). Every helper gets the
// read end and exits with exitLifeline at EOF, which comes when the test's
// cleanup closes the write end or when the test process dies however it
// dies, whatever the helper does with signals.
type lifeline struct{ r, w *os.File }

func newLifeline(t *testing.T) *lifeline {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close(); _ = r.Close() })
	return &lifeline{r: r, w: w}
}

// probe is the reverse: helpers hold the write end, so EOF on the test's
// read end proves that every holder exited (no signal is sent to check).
type probe struct {
	r, w *os.File
	eof  chan struct{}
}

func newProbe(t *testing.T) *probe {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &probe{r: r, w: w, eof: make(chan struct{})}
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := r.Read(buf); err != nil {
				close(p.eof)
				return
			}
		}
	}()
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return p
}

// handOff closes the test's write end once a helper holds its own copy.
func (p *probe) handOff() { _ = p.w.Close() }

func (p *probe) closedWithin(d time.Duration) bool {
	select {
	case <-p.eof:
		return true
	case <-time.After(d):
		return false
	}
}

// snapshot is one platform.System().List() as a ProcTable, so a walk sees a
// process and its children at the same instant.
type snapshot []platform.ProcInfo

func (s snapshot) Lookup(pid int) (platform.ProcInfo, error) {
	for _, p := range s {
		if p.ID.PID == pid {
			return p, nil
		}
	}
	return platform.ProcInfo{}, platform.ErrNoProcess
}

func (s snapshot) Alive(id platform.ProcID) bool {
	for _, p := range s {
		if p.ID == id {
			return p.State != platform.StateZombie
		}
	}
	return false
}

func (s snapshot) List() ([]platform.ProcInfo, error)  { return s, nil }
func (s snapshot) Cwd(platform.ProcID) (string, error) { return "", nil }
func (s snapshot) OpenFilesUnder(context.Context, []string) ([]platform.Holder, error) {
	return nil, nil
}

// killTree SIGKILLs a process this test started and what it left: its
// descendants (platform.Descendants in one snapshot that still holds it:
// once it is gone they are reparented, and its pid may name another
// process), the sessions it and they lead (the wrapper's PTY and
// direct-mode children lead sessions of their own: platform.SignalGroup)
// and the processes themselves. Every signal is ProcID-verified, so a pid
// that names another process by now is never signalled.
func killTree(id platform.ProcID) {
	if id.PID <= 1 || id.StartUS == 0 {
		return
	}
	var desc []platform.ProcInfo
	if all, err := platform.System().List(); err == nil && snapshot(all).Alive(id) {
		desc, _ = platform.Descendants(snapshot(all), id)
	}
	_ = platform.SignalGroup(id, syscall.SIGKILL)
	_ = platform.Signal(id, syscall.SIGKILL)
	for _, d := range desc {
		if d.SID == d.ID.PID {
			_ = platform.SignalGroup(d.ID, syscall.SIGKILL)
		}
		_ = platform.Signal(d.ID, syscall.SIGKILL)
	}
}

// withToken lists the live processes whose argv carries token: helpers of
// the test binary that made it (nothing else knows it).
func withToken(token string) []platform.ProcInfo {
	all, err := platform.System().List()
	if err != nil {
		return nil
	}
	var out []platform.ProcInfo
	for _, p := range all {
		if p.ID.PID == os.Getpid() || p.State == platform.StateZombie {
			continue
		}
		for _, a := range p.Argv {
			if strings.Contains(a, token) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// sweepToken gives the processes carrying token up to grace to exit (their
// lifelines are closed by now), then kills those left with killTree and
// returns them.
func sweepToken(token string, grace time.Duration) []platform.ProcInfo {
	deadline := time.Now().Add(grace)
	for {
		left := withToken(token)
		if len(left) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			for _, p := range left {
				killTree(p.ID)
			}
			return left
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// helperProc is a helper process the test started itself.
type helperProc struct {
	cmd  *exec.Cmd
	id   platform.ProcID
	done chan struct{}
	code int
}

// startHelper starts cmd; the test's cleanup then kills it with everything
// it left (killTree; once it exited, only the session it led, which may
// still have members) and reaps it.
func startHelper(t *testing.T, cmd *exec.Cmd) *helperProc {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &helperProc{cmd: cmd, done: make(chan struct{})}
	// Measured before the reap below can run: until then the pid is ours.
	h.id, _ = platform.Identify(cmd.Process.Pid)
	go func() {
		_ = cmd.Wait()
		h.code = exitCode(cmd.ProcessState)
		close(h.done)
	}()
	t.Cleanup(func() {
		select {
		case <-h.done:
			// Reaped: its pid may name another process now; only the
			// session it led, if any, is still its own.
			_ = platform.SignalGroup(h.id, syscall.SIGKILL)
		default:
			killTree(h.id)
		}
		select {
		case <-h.done:
		case <-time.After(waitTimeout):
			t.Errorf("helper %d was not reaped after SIGKILL", h.id.PID)
		}
	})
	return h
}

// wait waits for the helper's exit and returns its code (128+signal when
// a signal ended it).
func (h *helperProc) wait(t *testing.T) int {
	t.Helper()
	select {
	case <-h.done:
		return h.code
	case <-time.After(3 * waitTimeout):
		t.Fatal("helper process did not exit")
		return -1
	}
}

func exitCode(ps *os.ProcessState) int {
	if ps == nil {
		return -1
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}

// testSibling starts a process in the test's own session (a stand-in for
// the user's shell job) holding the probe p.
func testSibling(t *testing.T, bins helperBins, p *probe) *helperProc {
	t.Helper()
	life := newLifeline(t)
	sib := exec.Command(bins.tui, "sleep", "-lifeline", "3", "-test-token", testToken)
	sib.Env = []string{}
	sib.ExtraFiles = []*os.File{life.r, p.w}
	h := startHelper(t, sib)
	p.handOff()
	return h
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

// never waits d and asserts sub did not appear after from.
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
	// What a new subscription starts with (D71): one event per subscribed
	// folder, unlocked unless the folder is in lockedAt (with its reason),
	// with the folder's factors.
	lockedAt map[string]string
	factors  map[string][]string
}

type fakeSub struct {
	ch     chan ipc.Event
	once   sync.Once
	closed chan struct{}
}

func (s *fakeSub) close() { s.once.Do(func() { close(s.closed) }) }

func newFakeServer() *fakeServer {
	s := &fakeServer{lockedAt: map[string]string{}, factors: map[string][]string{}}
	s.heartbeats.Store(true)
	return s
}

// setState sets what later subscriptions report for root first: locked
// with reason, or unlocked when reason is "".
func (s *fakeServer) setState(root, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if reason == "" {
		delete(s.lockedAt, root)
	} else {
		s.lockedAt[root] = reason
	}
}

// setFactors sets the factor kinds the initial events of root carry.
func (s *fakeServer) setFactors(root string, kinds ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.factors[root] = kinds
}

// initial returns the events a subscription to roots starts with (D71).
func (s *fakeServer) initial(roots []string) []ipc.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ipc.Event
	for _, id := range roots {
		ev := ipc.Event{Kind: ipc.EventUnlocked, RootIDs: []string{id}, At: time.Now(), Factors: s.factors[id]}
		if reason, ok := s.lockedAt[id]; ok {
			ev.Kind, ev.Reason = ipc.EventLocked, reason
		}
		out = append(out, ev)
	}
	return out
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

func (s *fakeServer) unlockRequests() []ipc.UnlockReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ipc.UnlockReq(nil), s.unlocks...)
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

// Subscribe streams the folders' state first (D71), then published events
// plus a heartbeat every 50 ms (while heartbeats are on); the stream closes
// with the connection.
func (d *fakeDaemon) Subscribe(ctx context.Context, r ipc.SubscribeReq) (<-chan ipc.Event, error) {
	sub := &fakeSub{ch: make(chan ipc.Event, 64), closed: make(chan struct{})}
	for _, ev := range d.srv.initial(r.RootIDs) {
		sub.ch <- ev
	}
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

// fakeLease hands the child the run's lifeline as its first descriptor
// (fd 3), then files.
type fakeLease struct {
	mu       sync.Mutex
	life     *os.File
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

func (l *fakeLease) Inheritable() []*os.File {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.life == nil {
		return l.files
	}
	return append([]*os.File{l.life}, l.files...)
}

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
	life        *os.File // the run's lifeline, the child's fd 3
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

// takeLifeline gives the run's child life as its fd 3 (startRun; the
// helper process's own lifeline in helperMain).
func (b *fakeBackend) takeLifeline(life *os.File) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.life = life
}

// launchedChild is the child Run reported (zero before RecordLaunch).
func (b *fakeBackend) launchedChild() platform.ProcID {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.launched
}

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
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lease == nil {
		b.lease = &fakeLease{}
	}
	b.lease.mu.Lock()
	b.lease.life = b.life
	b.lease.mu.Unlock()
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
		if id := b.launchedChild(); !id.IsZero() {
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

// startRun runs wrapper.Run in a goroutine with a context the test's
// cleanup cancels. The cleanup then waits up to 5 s for Run, SIGKILLs what
// is left of the child (its session and descendants, killTree) when Run is
// still running, and waits for Run again. The child gets a lifeline of the
// test as its fd 3 (through the fake lease). No goroutine of it calls
// t.Fatal.
func startRun(t *testing.T, o wrapper.Options) <-chan runResult {
	t.Helper()
	return startRunCtx(t, context.Background(), o)
}

func startRunCtx(t *testing.T, parent context.Context, o wrapper.Options) <-chan runResult {
	t.Helper()
	life := newLifeline(t)
	type lifelineTaker interface{ takeLifeline(*os.File) }
	if b, ok := o.Backend.(lifelineTaker); ok {
		b.takeLifeline(life.r)
	}
	ctx, cancel := context.WithCancel(parent)
	ch := make(chan runResult, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		code, err := wrapper.Run(ctx, o)
		ch <- runResult{code, err}
	}()
	t.Cleanup(func() {
		cancel()
		if waitDone(done, 5*time.Second) {
			return
		}
		type launched interface{ launchedChild() platform.ProcID }
		if b, ok := o.Backend.(launched); ok {
			killTree(b.launchedChild())
		}
		if !waitDone(done, 3*waitTimeout) {
			t.Error("Run did not return after its child was killed")
		}
	})
	return ch
}

func waitDone(c <-chan struct{}, d time.Duration) bool {
	select {
	case <-c:
		return true
	case <-time.After(d):
		return false
	}
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
