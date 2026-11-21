package wrapper

import (
	"time"

	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
)

// Seams: package-level indirections that tests replace (export_test.go) so
// they run without another group's implementation and with short timings.
var (
	// identifyProc measures the ProcID of a child the wrapper started.
	identifyProc = platform.Identify
	// signalSession signals every remaining process of a session a wrapper
	// child leads (D57).
	signalSession = platform.SignalGroup
	// detectUI tells whether a GUI dialog can reach this terminal, which
	// decides how the lock screen names a Secure Enclave factor (CC-40).
	detectUI = platform.DetectUIContext
	// openPromptUI opens the terminal for prompts before the launch
	// (plan.Confirm, EnsureUnlocked's relayed UI).
	openPromptUI = func() (promptUI, error) {
		t, err := ui.OpenTTY()
		if err != nil {
			return nil, err
		}
		return t, nil
	}
	// heartbeatTimeout is how long the wrapper waits for a subscription
	// event before it shows its lock screen locally (SPEC §15.3).
	heartbeatTimeout = 2 * time.Second
	// reconnectBackoff and reconnectMax bound the subscription redial.
	reconnectBackoff = 250 * time.Millisecond
	reconnectMax     = 8 * time.Second
	// inputEvery rate-limits Input activity (Enter is reported at once).
	inputEvery = time.Second
)
