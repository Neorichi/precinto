//go:build crossgroup

package shellinit_test

// Cross-group test: OnEnter asks the real (in-process) daemon over the real
// ipc client. Run with -tags testing,crossgroup once the tree is integrated.

import (
	"testing"

	"github.com/Neorichi/precinto/internal/agent/agenttest"
	"github.com/Neorichi/precinto/internal/shellinit"
	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/internal/ui"
)

// TestCrossgroupOnEnterAgent: a fresh daemon holds no key, so entering the
// protected folder of a testkit home offers to unlock it: the result names
// the folder ~-shortened with the caller's HOME and carries its path for
// `precinto unlock --root` (CC-31); the prompt names the first factor the
// daemon reports as usable for this terminal, or is the plain prompt when
// it reports none (CC-40); the skip epoch is the daemon's lock time.
func TestCrossgroupOnEnterAgent(t *testing.T) {
	h := testkit.NewHome(t)
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	defer a.Stop()
	c, err := a.Client(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	st, err := c.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	since, factors := st.Started, []string(nil) // no vault known: locked since the daemon started
	for _, vs := range st.Vaults {
		if vs.VaultID == "root-acme" {
			since, factors = vs.Since, vs.Factors
		}
	}
	for _, gui := range []bool{false, true} {
		got, err := shellinit.OnEnter(t.Context(), h.Cfg, h.Layout, shellinit.EnterRequest{PWD: h.Root, PrevPWD: h.HomeDir, Shell: shellinit.Zsh,
			Home: h.HomeDir, GUI: gui})
		if err != nil {
			t.Fatal(err)
		}
		if got.Action != shellinit.EnterPrompt || got.RootID != "root-acme" || got.Path != h.Root || got.Folder != "~/work/acme" {
			t.Errorf("gui=%v: OnEnter with a running daemon = %+v", gui, got)
		}
		want := ui.Format(ui.MsgEnterPromptPlain, ui.Vars{Folder: "~/work/acme"})
		if f := ui.FactorName(factors, gui); f != "" {
			want = ui.Format(ui.MsgEnterPrompt, ui.Vars{Folder: "~/work/acme", Factor: f})
		}
		if got.Message != want {
			t.Errorf("gui=%v: message %q, want %q (factors %v)", gui, got.Message, want, factors)
		}
		if !since.IsZero() && got.Epoch != uint64(since.Unix()) {
			t.Errorf("gui=%v: epoch %d, want the lock time %d", gui, got.Epoch, since.Unix())
		}
	}
}
