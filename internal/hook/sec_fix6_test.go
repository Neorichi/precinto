package hook_test

import (
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/paths"
)

// D139 (S6-5, SEC-45): a hook runs in an agent context whose environment
// Claude's settings `env` can set (D56), so the workers and the daemon it
// starts get no dialog endpoint: a daemon would hand DISPLAY,
// WAYLAND_DISPLAY or DBUS_SESSION_BUS_ADDRESS to the pinentry that
// receives the passphrase. XDG_RUNTIME_DIR stays (precinto's runtime
// layout).
func TestWorkerEnvCarriesNoDialogEndpoint(t *testing.T) {
	env := paths.FromMap(map[string]string{
		"HOME": "/u", "PATH": "/usr/bin:/bin", "XDG_RUNTIME_DIR": "/run/user/1000",
		"DISPLAY": ":9", "WAYLAND_DISPLAY": "agent-0", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/agent-bus",
	})
	got := strings.Join(hook.WorkerEnv(env), "\n")
	for _, bad := range []string{"DISPLAY=", "WAYLAND_DISPLAY=", "DBUS_SESSION_BUS_ADDRESS="} {
		if strings.Contains(got, bad) {
			t.Errorf("worker env carries %s:\n%s", bad, got)
		}
	}
	if !strings.Contains(got, "XDG_RUNTIME_DIR=/run/user/1000") {
		t.Errorf("worker env lacks XDG_RUNTIME_DIR:\n%s", got)
	}
}
