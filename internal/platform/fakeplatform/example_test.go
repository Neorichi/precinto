package fakeplatform_test

import (
	"fmt"
	"time"

	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/platform/fakeplatform"
)

// A system sleep moves the wall clock but not the monotonic one, which is
// the jump platform.WatchJumps reports (D24).
func ExampleClock_Sleep() {
	c := fakeplatform.NewClock(time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC))
	wall, mono := c.Now(), c.Mono()
	c.Sleep(2 * time.Hour) // the lid was closed for two hours
	fmt.Println("wall", c.Now().Sub(wall), "mono", c.Mono()-mono)
	c.Advance(time.Minute)
	fmt.Println("wall", c.Now().Sub(wall), "mono", c.Mono()-mono)
	// Output:
	// wall 2h0m0s mono 0s
	// wall 2h1m0s mono 1m0s
}

// A zombie is still in the table but counts as exited; once a parent exits
// its children are reparented to pid 1.
func ExampleProcs_Exit() {
	procs := fakeplatform.NewProcs()
	claude := platform.ProcInfo{ID: platform.ProcID{PID: 4242, StartUS: 1_000}, PPID: 300, Exe: "/opt/claude/bin/claude"}
	mcp := platform.ProcInfo{ID: platform.ProcID{PID: 4250, StartUS: 2_000}, PPID: 4242, Exe: "/usr/local/bin/node"}
	procs.Add(claude)
	procs.Add(mcp)

	procs.Exit(4242, true)
	z, _ := procs.Lookup(4242)
	m, _ := procs.Lookup(4250)
	fmt.Println(z.State, procs.Alive(claude.ID), m.PPID)
	// Output: zombie false 1
}

// A reused pid is another process: the old ProcID is no longer alive.
func ExampleProcs_Reuse() {
	procs := fakeplatform.NewProcs()
	claude := platform.ProcInfo{ID: platform.ProcID{PID: 4242, StartUS: 1_000}, Exe: "/opt/claude/bin/claude"}
	procs.Add(claude)
	procs.Reuse(4242, 9_000, "/usr/bin/true")
	now, _ := procs.Lookup(4242)
	fmt.Println(procs.Alive(claude.ID), now.ID.StartUS, now.Exe)
	// Output: false 9000 /usr/bin/true
}
