//go:build linux

package platform

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Neorichi/precinto/internal/paths"
)

// linux screen-lock, HID-idle and UI-context detection are implemented here by G2.

// loginctlPath returns the first system loginctl, or "".
func loginctlPath() string {
	for _, p := range []string{"/usr/bin/loginctl", "/bin/loginctl"} {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// sysReadScreen reads logind's hints for the user's display session
// (`loginctl show-user <uid> -p Display`, then show-session). Without
// logind (headless, containers) both facts are unknown.
func sysReadScreen(ctx context.Context) (ScreenState, error) {
	now := time.Now().Round(0)
	// D156: inside WSL logind sees no Windows desktop. Neither the Windows
	// lock screen nor its keyboard and mouse reach it, and a WSL terminal
	// session it may elect as the display reports a constant "not locked"
	// and an idle time of its own: both stay unknown, so no screen-lock
	// watch is claimed and no prompt counts as human by its idle time
	// (D37, D54).
	if detectWSL().Version != 0 {
		return ScreenState{At: now}, nil
	}
	lc := loginctlPath()
	if lc == "" {
		return ScreenState{At: now}, nil
	}
	out, _, err := runTool(ctx, 2*time.Second, lc, "show-user", strconv.Itoa(os.Getuid()), "-p", "Display")
	if err != nil {
		return ScreenState{At: now}, fmt.Errorf("platform: loginctl show-user: %w", err)
	}
	sess := parseProps(out)["Display"]
	if sess == "" || !validSessionID(sess) {
		return ScreenState{At: now}, nil
	}
	out, _, err = runTool(ctx, 2*time.Second, lc, "show-session", sess, "-p", "LockedHint", "-p", "IdleHint", "-p", "IdleSinceHint")
	if err != nil {
		return ScreenState{At: now}, fmt.Errorf("platform: loginctl show-session: %w", err)
	}
	return screenFromLoginctl(parseProps(out), now), nil
}

// validSessionID accepts logind session ids (letters, digits, '_', '-').
func validSessionID(s string) bool {
	if len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// sysGUI reports whether a graphical session is reachable (pinentry-gnome3
// needs DISPLAY or WAYLAND_DISPLAY).
func sysGUI(e paths.Env) bool {
	return e.Get("DISPLAY") != "" || e.Get("WAYLAND_DISPLAY") != ""
}
