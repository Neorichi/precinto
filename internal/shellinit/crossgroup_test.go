//go:build crossgroup

package shellinit_test

// Cross-group test: OnEnter asks the real (in-process) daemon over the real
// ipc client. Run with -tags testing,crossgroup once the tree is integrated.

import (
	"testing"

	"github.com/precinto/precinto/internal/agent/agenttest"
	"github.com/precinto/precinto/internal/shellinit"
	"github.com/precinto/precinto/internal/testkit"
)

// TestCrossgroupOnEnterAgent: a fresh daemon holds no key, so entering the
// protected folder of a testkit home offers to unlock it.
func TestCrossgroupOnEnterAgent(t *testing.T) {
	h := testkit.NewHome(t)
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	defer a.Stop()
	got, err := shellinit.OnEnter(t.Context(), h.Cfg, h.Layout, shellinit.EnterRequest{PWD: h.Root, PrevPWD: h.HomeDir, Shell: shellinit.Zsh})
	if err != nil {
		t.Fatal(err)
	}
	if got.Action != shellinit.EnterPrompt || got.RootID != "root-acme" {
		t.Errorf("OnEnter with a running daemon = %+v", got)
	}
}
