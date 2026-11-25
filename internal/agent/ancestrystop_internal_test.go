package agent

import (
	"context"
	"os"
	"testing"

	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
)

// D64: a -tags testing daemon ends the peer-ancestry walk at the process
// named by PRECINTO_TEST_ANCESTRY_STOP in its own environment; a
// production daemon never reads it.
func TestPeerAncestryStopsAtTheTestProcess(t *testing.T) {
	stop := platform.ProcID{PID: 7200, StartUS: 7}
	x := startTD(t, func(x *td, o *Options) {
		o.Env = o.Env.With(paths.EnvTestAncestryStop, stop.String())
	})
	ctx := context.Background()
	x.addProc(7000, 1, 7000, "/bin/zsh", "-zsh")
	x.addProc(7100, 7000, 7000, "/opt/homebrew/bin/claude", "claude")
	x.h.Procs.Add(platform.ProcInfo{ID: stop, PPID: 7100, SID: 7000, Exe: "/tmp/go-build/integration.test", Argv: []string{"integration.test"}})
	peer := platform.Peer{UID: os.Getuid(), PID: 7300, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 7300, StartUS: 8}, PPID: stop.PID, TTY: "/dev/ttys009"}}
	x.h.Procs.Add(peer.Proc)
	x.setPeer(&peer, true)
	c := x.dial()
	_, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-beta"}, TTY: true}, nil)
	if paths.TestingBuild() {
		if ipcCode(err) == ipc.CodeAgentContext {
			t.Fatalf("testing daemon: claude above the stop refused the unlock: %v", err)
		}
	} else if ipcCode(err) != ipc.CodeAgentContext {
		t.Fatalf("production daemon honoured PRECINTO_TEST_ANCESTRY_STOP: %v", err)
	}

	// A harness below the stop is still an agent context.
	x.addProc(7400, stop.PID, 7000, "/opt/homebrew/bin/codex", "codex")
	below := platform.Peer{UID: os.Getuid(), PID: 7500, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 7500, StartUS: 9}, PPID: 7400, TTY: "/dev/ttys010"}}
	x.h.Procs.Add(below.Proc)
	x.setPeer(&below, true)
	c2 := x.dial()
	if _, err := c2.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true}, nil); ipcCode(err) != ipc.CodeAgentContext {
		t.Fatalf("codex below the stop: %v, want C12.agent", err)
	}
}
