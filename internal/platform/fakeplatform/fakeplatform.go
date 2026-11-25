package fakeplatform

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/Neorichi/precinto/internal/platform"
)

// Compile-time checks of the seams (docs/API.md §4).
var (
	_ platform.ProcTable = (*Procs)(nil)
	_ platform.Clock     = (*Clock)(nil)
)

// Semantics of the fakes, beyond the doc comments (which are the contract):
//
// Procs models the process table the kernel would report for the test's
// own uid, so that every query answers exactly as platform.ProcTable
// promises for real processes:
//   - Identity is the whole ProcID (pid, start time, boot id), compared by
//     equality; a zombie is listed and looked up (State zombie) but is never
//     Alive and has no cwd or descriptors.
//   - Only positive pids exist: Add, Reuse, SetCwd and SetOpenFiles ignore
//     pid <= 0 (most likely an unset ProcInfo), and lookups of such pids fail.
//   - Exit and Reuse are lifecycle events with kernel semantics: the
//     process's working directory and descriptors are released and its
//     children are reparented to pid 1, so platform.Descendants no longer
//     finds them once their parent has exited (as it documents).
//   - Add is a raw table write: it never touches other processes, but a
//     process with another ProcID at the same pid is another incarnation and
//     does not inherit the replaced one's cwd or descriptors. Cwd and open
//     files set while no process holds a pid apply to the next one added.
//   - Every process in the table counts as the current uid's (List does not
//     filter on ProcInfo.UID, which is reported as given).
//   - OpenFilesUnder matches held paths with paths.Within semantics (the
//     directory itself included; component-wise, never by string prefix;
//     ASCII case folding on darwin) and reports each (pid, path) once.
//   - Errors wrap the platform sentinels (check them with errors.Is).
//     OpenFilesUnder fails on a nil or done context and on a relative
//     directory; callers must read any failure as "live" (HA9, R11).
//   - List and OpenFilesUnder are deterministic (sorted by pid, then path),
//     and every result is a deep copy.
//
// Clock never blocks: Sleep is the machine sleeping, not a goroutine. Advance
// and Sleep never move time backwards (d <= 0 is a no-op, so the monotonic
// reading can never decrease); only StepWall moves the wall clock back.

// reaperPID adopts the children of an exited process (launchd on darwin,
// init on linux; linux child subreapers are not modelled).
const reaperPID = 1

// Procs is a mutable fake process table.
type Procs struct {
	mu    sync.Mutex
	procs map[int]platform.ProcInfo // the process holding each pid, zombies included
	cwds  map[int]string            // cwd of the process holding pid (absent = unknown)
	open  map[int][]string          // paths the process holding pid holds open
	errs  map[string]error          // injected failures by operation (SetErr)
}

// NewProcs returns an empty table.
func NewProcs() *Procs {
	p := &Procs{}
	p.initLocked()
	return p
}

// initLocked allocates the maps, so a zero-value Procs works too. p.mu must
// be held unless p is not shared yet.
func (p *Procs) initLocked() {
	if p.procs == nil {
		p.procs = make(map[int]platform.ProcInfo)
	}
	if p.cwds == nil {
		p.cwds = make(map[int]string)
	}
	if p.open == nil {
		p.open = make(map[int][]string)
	}
}

// Add inserts or replaces a process (state running unless set).
func (p *Procs) Add(info platform.ProcInfo) {
	if info.ID.PID <= 0 {
		return
	}
	info = cloneInfo(info)
	if info.State == "" {
		info.State = platform.StateRunning
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	if old, ok := p.procs[info.ID.PID]; ok && old.ID != info.ID {
		// Another incarnation: nothing of the replaced process carries over.
		p.releaseLocked(info.ID.PID)
	}
	p.procs[info.ID.PID] = info
}

// Exit marks pid as exited (removed) or, with zombie, as a zombie.
func (p *Procs) Exit(pid int, zombie bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur, ok := p.procs[pid]
	if !ok {
		return
	}
	if zombie {
		cur.State = platform.StateZombie
		p.procs[pid] = cur
	} else {
		delete(p.procs, pid)
	}
	p.exitedLocked(pid)
}

// Reuse replaces pid with a new incarnation that has a different start time.
func (p *Procs) Reuse(pid int, startUS int64, exe string) {
	if pid <= 0 {
		return
	}
	// The new incarnation is an unrelated program: only the pid, the boot
	// and the owner are shared with the old one; its parent is unknown, so
	// it is never adopted as a descendant of the old process's parent.
	next := platform.ProcInfo{
		ID:    platform.ProcID{PID: pid, StartUS: startUS},
		PPID:  reaperPID,
		State: platform.StateRunning,
		Exe:   exe,
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	if old, ok := p.procs[pid]; ok {
		next.ID.BootID = old.ID.BootID
		next.UID = old.UID
		if next.ID.StartUS == old.ID.StartUS {
			// The contract promises a different start time; never hand
			// out a ProcID equal to the old incarnation's.
			next.ID.StartUS = otherStart(old.ID.StartUS)
		}
		// The old incarnation has exited (a pid is reused only after that).
		delete(p.procs, pid)
		p.exitedLocked(pid)
	}
	p.procs[pid] = next
}

// otherStart returns a start time that differs from s.
func otherStart(s int64) int64 {
	if s == math.MaxInt64 {
		return s - 1
	}
	return s + 1
}

// exitedLocked applies what the kernel does when the process holding pid
// exits: its descriptors and cwd are released and its children are
// reparented to the reaper.
func (p *Procs) exitedLocked(pid int) {
	p.releaseLocked(pid)
	if pid == reaperPID {
		return
	}
	for cpid, c := range p.procs {
		if cpid != pid && c.PPID == pid {
			c.PPID = reaperPID
			p.procs[cpid] = c
		}
	}
}

// releaseLocked forgets the cwd and open files of the process holding pid.
func (p *Procs) releaseLocked(pid int) {
	delete(p.cwds, pid)
	delete(p.open, pid)
}

// SetCwd sets the working directory Cwd reports for pid ("" = unknown).
func (p *Procs) SetCwd(pid int, cwd string) {
	if pid <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	if cwd == "" {
		delete(p.cwds, pid)
		return
	}
	p.cwds[pid] = cwd
}

// SetOpenFiles sets the absolute paths pid holds open (OpenFilesUnder).
func (p *Procs) SetOpenFiles(pid int, paths ...string) {
	if pid <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	if len(paths) == 0 {
		delete(p.open, pid)
		return
	}
	p.open[pid] = slices.Clone(paths)
}

// Operations accepted by SetErr.
const (
	OpLookup         = "Lookup"
	OpList           = "List"
	OpCwd            = "Cwd"
	OpOpenFilesUnder = "OpenFilesUnder"
)

// SetErr makes every later call of op (OpLookup, OpList, OpCwd or
// OpOpenFilesUnder) fail with an error wrapping err, until SetErr(op, nil).
// It models an unreadable process table, a TCC denial or a missing lsof, so
// tests can check that callers read such failures as "live" (HA9, R11). Any
// other op panics: a misspelt op would silently inject nothing.
func (p *Procs) SetErr(op string, err error) {
	switch op {
	case OpLookup, OpList, OpCwd, OpOpenFilesUnder:
	default:
		panic("fakeplatform: SetErr: unknown operation " + op)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil {
		delete(p.errs, op)
		return
	}
	if p.errs == nil {
		p.errs = make(map[string]error)
	}
	p.errs[op] = err
}

// injectedLocked returns the failure set for op, wrapped with context, or
// nil. p.mu must be held.
func (p *Procs) injectedLocked(op string) error {
	if err := p.errs[op]; err != nil {
		return fmt.Errorf("fakeplatform: %s (injected): %w", op, err)
	}
	return nil
}

// Lookup implements platform.ProcTable.
func (p *Procs) Lookup(pid int) (platform.ProcInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.injectedLocked(OpLookup); err != nil {
		return platform.ProcInfo{}, err
	}
	info, ok := p.procs[pid]
	if !ok {
		return platform.ProcInfo{}, fmt.Errorf("fakeplatform: pid %d: %w", pid, platform.ErrNoProcess)
	}
	return cloneInfo(info), nil
}

// Alive implements platform.ProcTable.
func (p *Procs) Alive(id platform.ProcID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.aliveLocked(id)
}

// aliveLocked reports whether the process holding id.PID is exactly id and
// not a zombie.
func (p *Procs) aliveLocked(id platform.ProcID) bool {
	if id.PID <= 0 {
		return false
	}
	cur, ok := p.procs[id.PID]
	return ok && cur.ID == id && cur.State != platform.StateZombie
}

// List implements platform.ProcTable.
func (p *Procs) List() ([]platform.ProcInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.injectedLocked(OpList); err != nil {
		return nil, err
	}
	out := make([]platform.ProcInfo, 0, len(p.procs))
	for _, info := range p.procs {
		out = append(out, cloneInfo(info))
	}
	slices.SortFunc(out, func(a, b platform.ProcInfo) int { return cmp.Compare(a.ID.PID, b.ID.PID) })
	return out, nil
}

// Cwd implements platform.ProcTable.
func (p *Procs) Cwd(id platform.ProcID) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.injectedLocked(OpCwd); err != nil {
		return "", err
	}
	if !p.aliveLocked(id) {
		return "", fmt.Errorf("fakeplatform: cwd of pid %d (start %d): %w", id.PID, id.StartUS, platform.ErrNotSame)
	}
	return p.cwds[id.PID], nil
}

// OpenFilesUnder implements platform.ProcTable.
func (p *Procs) OpenFilesUnder(ctx context.Context, dirs []string) ([]platform.Holder, error) {
	// Every failure is an error, which callers must read as "live".
	if ctx == nil {
		return nil, errors.New("fakeplatform: open files: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fakeplatform: open files: %w", err)
	}
	for _, d := range dirs {
		if !filepath.IsAbs(d) {
			return nil, fmt.Errorf("fakeplatform: open files: directory %q is not absolute", d)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.injectedLocked(OpOpenFilesUnder); err != nil {
		return nil, err
	}
	out := []platform.Holder{}
	for pid, held := range p.open {
		info, ok := p.procs[pid]
		if !ok || info.State == platform.StateZombie {
			continue // exited processes hold no descriptors
		}
		seen := make(map[string]bool, len(held))
		for _, f := range held {
			if seen[f] || !withinAny(dirs, f) {
				continue
			}
			seen[f] = true
			out = append(out, platform.Holder{Proc: cloneInfo(info), Path: f})
		}
	}
	slices.SortFunc(out, func(a, b platform.Holder) int {
		if c := cmp.Compare(a.Proc.ID.PID, b.Proc.ID.PID); c != 0 {
			return c
		}
		return cmp.Compare(a.Path, b.Path)
	})
	return out, nil
}

// cloneInfo returns a copy of info that shares no memory with it.
func cloneInfo(info platform.ProcInfo) platform.ProcInfo {
	info.Argv = slices.Clone(info.Argv)
	return info
}

// Clock is a settable clock with independent wall and monotonic readings.
// A clock from NewClock is frozen: it moves only when the test moves it. A
// clock from NewRealClock follows the real clock and adds what the test
// moved it by.
type Clock struct {
	mu   sync.Mutex
	wall time.Time     // frozen mode: the reading (never a monotonic one)
	mono time.Duration // frozen mode: the reading; real mode: what Advance added; never decreases
	// real is set by NewRealClock: origin is the real time (with its
	// monotonic reading) at creation and ahead the wall offset.
	real   bool
	origin time.Time
	ahead  time.Duration
}

// NewClock starts at wall with monotonic reading 0.
func NewClock(wall time.Time) *Clock { return &Clock{wall: wall.Round(0)} }

// NewRealClock returns a Clock that follows the real clock: Now is the
// system wall time plus everything Advance, Sleep and StepWall added, and
// Mono the real time elapsed since NewRealClock plus everything Advance
// added; Now is in UTC. Without StepWall it is never behind the real clock,
// so the code under test never sees a time the kernel stamped during the
// test (a file mtime the test did not set, a real process's start time) as
// "in the future", and Advance makes the waits a test skips (a quiet
// window) pass at once.
//
// Use it where the code under test compares the clock with such kernel
// times; state-machine tests whose every time input is fake keep a frozen
// NewClock(testkit.Epoch). A deadline sent to another process (an ipc
// deadline) is real time whatever the clock (TESTPLAN §1.4, D77).
func NewRealClock() *Clock { return &Clock{real: true, origin: time.Now()} }

// Now implements platform.Clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.real {
		return time.Now().Add(c.ahead).Round(0).UTC()
	}
	return c.wall.Round(0)
}

// Mono implements platform.Clock.
func (c *Clock) Mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.real {
		return addSaturating(time.Since(c.origin), c.mono)
	}
	return c.mono
}

// Advance moves both readings forward by d.
func (c *Clock) Advance(d time.Duration) {
	if d <= 0 {
		return // forward only: a decreasing Mono would break platform.Clock
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stepLocked(d)
	c.mono = addSaturating(c.mono, d)
}

// StepWall moves only the wall clock (NTP step; may be negative).
func (c *Clock) StepWall(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stepLocked(d)
}

// Sleep simulates system sleep: wall advances by d, monotonic does not.
func (c *Clock) Sleep(d time.Duration) {
	// The machine sleeps, not the caller: Sleep returns at once, so a test
	// that only calls Sleep can never block. A machine cannot sleep for a
	// negative time, so d <= 0 is a no-op (StepWall moves the wall back).
	if d <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stepLocked(d)
}

// stepLocked moves the wall reading by d.
func (c *Clock) stepLocked(d time.Duration) {
	if c.real {
		c.ahead += d
		return
	}
	c.wall = c.wall.Add(d)
}

// addSaturating returns a+b for b > 0, clamped at the largest Duration
// instead of wrapping around (a wrapped Mono would run backwards).
func addSaturating(a, b time.Duration) time.Duration {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}
