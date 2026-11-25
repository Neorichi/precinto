package hook

import (
	"errors"

	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/ipc"
)

// errNoTTY answers relayed prompts that need a terminal: hooks run without
// one (HOOKS-IO §2.1), so the daemon must use a GUI factor or pinentry
// itself (SPEC §12.8, D27).
var errNoTTY = errors.New("hook: no terminal for a relayed prompt")

// headlessUI is the hook's ipc.UIHandler during a hook-raised unlock. It
// shows nothing (there is no terminal; the daemon notifies the session's
// TTY itself, D60), never reads a secret and never confirms.
type headlessUI struct{}

var _ ipc.UIHandler = headlessUI{}

// Display drops informational lines.
func (headlessUI) Display(string) error { return nil }

// Secret refuses: secrets are never typed into a hook.
func (headlessUI) Secret(string) (*memguard.LockedBuffer, error) { return nil, errNoTTY }

// Confirm refuses: a hook cannot obtain a typed confirmation.
func (headlessUI) Confirm(string, string, string) (bool, error) { return false, errNoTTY }
