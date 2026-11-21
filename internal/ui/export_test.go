package ui

// Test-only access to unexported seams (compiled into the test binary only;
// the external tests in package ui_test use these).

import (
	"os"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// NewTestTTY returns a TTY over in and out that Close does not close. With
// terminal false it skips terminal-mode changes, so prompts run over pipes.
func NewTestTTY(in, out *os.File, terminal bool) *TTY {
	t := &TTY{in: in, out: out}
	if !terminal {
		t.modes = pipeModes{}
	}
	return t
}

type pipeModes struct{}

func (pipeModes) raw(int) (func() error, error) { return func() error { return nil }, nil }
func (pipeModes) reraw(int) error               { return nil }
func (pipeModes) terminal(int) bool             { return true }

// OpenTTYAt runs OpenTTY's code path on an explicit device path (a pty slave).
func OpenTTYAt(path string) (*TTY, error) { return openTTY(path) }

// AgentContextWith runs AgentContext with explicit probes instead of
// paths.AgentMarkers, os.Getpid and the /dev/tty probe.
func AgentContextWith(e paths.Env, t platform.ProcTable, markers func(paths.Env) []string, pid int, ctty func() bool) (bool, string) {
	return agentContext(e, t, agentProbe{markers: markers, pid: pid, ctty: ctty})
}

// HasControllingTerminal is the real controlling-terminal probe.
func HasControllingTerminal() bool { return hasControllingTerminal() }

// Limits of the prompts and of the ancestry walk.
const (
	MaxSecret    = maxSecret
	MaxLine      = maxLine
	MaxAncestors = maxAncestors
)
