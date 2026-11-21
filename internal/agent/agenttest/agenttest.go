package agenttest

import (
	"testing"

	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
)

// Agent is a running in-process daemon.
type Agent struct {
	Layout paths.Layout
	Clock  *fakeplatform.Clock
	Procs  *fakeplatform.Procs
	stop   func()
}

// Start runs agent.Run on l in a goroutine and waits until it listens. It
// sets every agent.Options seam: Harden is a no-op (the go test binary is
// never hardened), Spawn records worker argv without executing anything
// (see Spawned), Screen returns the state set with SetScreen (unlocked,
// HID idle unknown by default), and Pinentry fails with vault.ErrNoUI.
func Start(t testing.TB, l paths.Layout, clock *fakeplatform.Clock, procs *fakeplatform.Procs) *Agent {
	panic("unimplemented: agenttest.Start")
}

// Dial returns a client connected to the agent.
func (a *Agent) Dial(t testing.TB) *ipc.Client { panic("unimplemented: agenttest.Agent.Dial") }

// Spawned returns the argv of every worker the agent asked to spawn, in
// order (`<Exe> sweep --lock --root …`, `<Exe> restore --background …`).
func (a *Agent) Spawned() [][]string { panic("unimplemented: agenttest.Agent.Spawned") }

// SetScreen sets what the agent's next console poll observes.
func (a *Agent) SetScreen(s platform.ScreenState) { panic("unimplemented: agenttest.Agent.SetScreen") }

// Stop stops the agent and waits for it.
func (a *Agent) Stop() { panic("unimplemented: agenttest.Agent.Stop") }
