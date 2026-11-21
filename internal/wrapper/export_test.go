package wrapper

// Test-only access to unexported seams and helpers (compiled into the test
// binary only; the external tests in package wrapper_test use these).

import (
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
)

func init() {
	// Tests never prompt on the real controlling terminal: a test that
	// needs pre-launch prompts installs a fake with SetPromptUI.
	openPromptUI = func() (promptUI, error) { return nil, errNotTerminal }
}

// PromptUI is the pre-launch prompt terminal.
type PromptUI = promptUI

// SetPromptUI replaces the pre-launch terminal opener.
func SetPromptUI(f func() (PromptUI, error)) (restore func()) {
	old := openPromptUI
	openPromptUI = f
	return func() { openPromptUI = old }
}

// SetProcSeams replaces process identification and session signalling.
func SetProcSeams(identify func(int) (platform.ProcID, error), session func(platform.ProcID, syscall.Signal) error) (restore func()) {
	oldID, oldSess := identifyProc, signalSession
	identifyProc, signalSession = identify, session
	return func() { identifyProc, signalSession = oldID, oldSess }
}

// SetTimings shortens the subscription and activity timings.
func SetTimings(heartbeat, backoff, input time.Duration) (restore func()) {
	oldHB, oldBO, oldMax, oldIn := heartbeatTimeout, reconnectBackoff, reconnectMax, inputEvery
	heartbeatTimeout, reconnectBackoff, reconnectMax, inputEvery = heartbeat, backoff, 4*backoff, input
	return func() {
		heartbeatTimeout, reconnectBackoff, reconnectMax, inputEvery = oldHB, oldBO, oldMax, oldIn
	}
}

// StartProxyIO is StartProxy with separate input and output terminals.
func StartProxyIO(cmd *exec.Cmd, in, out *os.File, o ProxyOptions) (*Proxy, error) {
	return startProxy(cmd, in, out, o)
}

// PID returns the child's pid.
func (p *Proxy) PID() int { return p.s.pid }

// Resize runs the SIGWINCH path.
func (p *Proxy) Resize() { p.s.resize() }

// Status returns the overlay's status line.
func (p *Proxy) Status() string {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()
	return p.s.ov.status
}

// SetStatus sets the overlay's status line.
func (p *Proxy) SetStatus(text string) { p.s.setStatus(text) }

// Prompt reads a line on the lock screen.
func (p *Proxy) Prompt(text string, secret bool, cancel <-chan struct{}) (*memguard.LockedBuffer, string, error) {
	return p.s.prompt(text, secret, cancel)
}

// WaitReadable is the select(2) wait the loops use.
func WaitReadable(fd int, d time.Duration) (bool, error) { return waitReadable(fd, d) }

// FilterReplay is the replay filter of Unlock.
func FilterReplay(b []byte) []byte { return filterReplay(b) }

// OverlayLines renders the lock screen's lines.
func OverlayLines(o Overlay, harnessName, status string, ending bool) []string {
	return overlayText{o: o, harness: harnessName, status: status, ending: ending}.lines()
}

// TerminateOptionsFor returns the termination parameters Run uses for plan.
func TerminateOptionsFor(plan harness.LaunchPlan) TerminateOptions { return terminateOptions(plan) }

// PlanVars maps LaunchPlan.MsgVars to ui.Vars.
func PlanVars(m map[string]string) ui.Vars { return planVars(m) }

// ClaudeSettings is the D32 settings JSON.
const ClaudeSettings = claudeSettings

// DefaultScrollbackBytes is the ring size used when ProxyOptions leaves it 0.
const DefaultScrollbackBytes = defaultScrollbackBytes
