//go:build darwin

package platform

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/precinto/precinto/internal/paths"
)

// darwin screen-lock, HID-idle and UI-context detection are implemented here by G2.

// ioregPath is the fixed system location of ioreg (never looked up in PATH).
const ioregPath = "/usr/sbin/ioreg"

// sysReadScreen polls ioreg twice: the Root entry for IOConsoleLocked and
// the console sessions, and the entries carrying HIDIdleTime (IOHIDSystem).
func sysReadScreen(ctx context.Context) (ScreenState, error) {
	s := ScreenState{At: time.Now().Round(0)}
	root, _, rerr := runTool(ctx, 2*time.Second, ioregPath, "-n", "Root", "-d1")
	if rerr == nil {
		s.Locked, s.LockKnown, _ = parseIoregRoot(root).screenFor(os.Getuid())
	}
	hid, _, herr := runTool(ctx, 2*time.Second, ioregPath, "-r", "-k", "HIDIdleTime", "-d", "1")
	if herr == nil {
		s.HIDIdle, s.IdleKnown = parseHIDIdle(hid)
	}
	if rerr != nil && herr != nil {
		return s, errors.Join(rerr, herr)
	}
	return s, nil
}

// sysGUI reports whether the current user's session is on the console, so
// a Secure Enclave or pinentry-mac dialog can appear.
func sysGUI(paths.Env) bool {
	root, _, err := runTool(context.Background(), 2*time.Second, ioregPath, "-n", "Root", "-d1")
	if err != nil {
		return false
	}
	_, _, on := parseIoregRoot(root).screenFor(os.Getuid())
	return on
}
