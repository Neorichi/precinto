package fakeplatform

import (
	"context"
	"sync"
	"time"

	"github.com/precinto/precinto/internal/platform"
)

// Compile-time checks of the seams (docs/API.md §4).
var (
	_ platform.ProcTable = (*Procs)(nil)
	_ platform.Clock     = (*Clock)(nil)
)

// Procs is a mutable fake process table.
type Procs struct {
	mu    sync.Mutex
	procs map[int]platform.ProcInfo
	cwds  map[int]string
	open  map[int][]string
}

// NewProcs returns an empty table.
func NewProcs() *Procs { panic("unimplemented: fakeplatform.NewProcs") }

// Add inserts or replaces a process (state running unless set).
func (p *Procs) Add(info platform.ProcInfo) { panic("unimplemented: fakeplatform.Procs.Add") }

// Exit marks pid as exited (removed) or, with zombie, as a zombie.
func (p *Procs) Exit(pid int, zombie bool) { panic("unimplemented: fakeplatform.Procs.Exit") }

// Reuse replaces pid with a new incarnation that has a different start time.
func (p *Procs) Reuse(pid int, startUS int64, exe string) {
	panic("unimplemented: fakeplatform.Procs.Reuse")
}

// SetCwd sets the working directory Cwd reports for pid ("" = unknown).
func (p *Procs) SetCwd(pid int, cwd string) { panic("unimplemented: fakeplatform.Procs.SetCwd") }

// SetOpenFiles sets the absolute paths pid holds open (OpenFilesUnder).
func (p *Procs) SetOpenFiles(pid int, paths ...string) {
	panic("unimplemented: fakeplatform.Procs.SetOpenFiles")
}

// Lookup implements platform.ProcTable.
func (p *Procs) Lookup(pid int) (platform.ProcInfo, error) {
	panic("unimplemented: fakeplatform.Procs.Lookup")
}

// Alive implements platform.ProcTable.
func (p *Procs) Alive(id platform.ProcID) bool { panic("unimplemented: fakeplatform.Procs.Alive") }

// List implements platform.ProcTable.
func (p *Procs) List() ([]platform.ProcInfo, error) { panic("unimplemented: fakeplatform.Procs.List") }

// Cwd implements platform.ProcTable.
func (p *Procs) Cwd(id platform.ProcID) (string, error) {
	panic("unimplemented: fakeplatform.Procs.Cwd")
}

// OpenFilesUnder implements platform.ProcTable.
func (p *Procs) OpenFilesUnder(ctx context.Context, dirs []string) ([]platform.Holder, error) {
	panic("unimplemented: fakeplatform.Procs.OpenFilesUnder")
}

// Clock is a settable clock with independent wall and monotonic readings.
type Clock struct {
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

// NewClock starts at wall with monotonic reading 0.
func NewClock(wall time.Time) *Clock { panic("unimplemented: fakeplatform.NewClock") }

// Now implements platform.Clock.
func (c *Clock) Now() time.Time { panic("unimplemented: fakeplatform.Clock.Now") }

// Mono implements platform.Clock.
func (c *Clock) Mono() time.Duration { panic("unimplemented: fakeplatform.Clock.Mono") }

// Advance moves both readings forward by d.
func (c *Clock) Advance(d time.Duration) { panic("unimplemented: fakeplatform.Clock.Advance") }

// StepWall moves only the wall clock (NTP step; may be negative).
func (c *Clock) StepWall(d time.Duration) { panic("unimplemented: fakeplatform.Clock.StepWall") }

// Sleep simulates system sleep: wall advances by d, monotonic does not.
func (c *Clock) Sleep(d time.Duration) { panic("unimplemented: fakeplatform.Clock.Sleep") }
