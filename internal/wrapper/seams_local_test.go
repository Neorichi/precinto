//go:build !crossgroup && (darwin || linux)

package wrapper

import (
	"syscall"

	"github.com/precinto/precinto/internal/platform"
)

// Until internal/platform is complete (G2), the tests identify children by
// pid alone and end a child's session through its process group, which
// holds every helper the scripted child spawns (crossgroup builds use the
// real platform.Identify and platform.SignalGroup).
func init() {
	identifyProc = func(pid int) (platform.ProcID, error) { return platform.ProcID{PID: pid, StartUS: 1}, nil }
	signalSession = func(leader platform.ProcID, sig syscall.Signal) error { return killGroup(leader.PID, sig) }
}
