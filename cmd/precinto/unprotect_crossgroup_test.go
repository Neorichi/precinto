//go:build crossgroup

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/agent/agenttest"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

// D146 (U6-1), with the real agent over ipc: `precinto unprotect DIR` in a
// terminal reviews the removal it just saved — the agent re-reads
// config.toml first — and confirms it over the connection of its own
// terminal unlock, signed with the global vault's key since no folder
// stays protected (D145): afterwards nothing waits for a confirmation and
// the agent no longer protects the folder. When the user declines to
// unlock the signer, nothing is confirmed: unprotect says the folder stays
// protected and exits 3, and the removal still waits.
func TestCrossgroupUnprotectConfirmsTheRemoval(t *testing.T) {
	for _, tc := range []struct {
		name       string
		globalOpen bool
		yesno      []bool
		confirmed  bool
	}{
		{"the global vault is open", true, []bool{true}, true},
		{"the signer is not unlocked", false, []bool{true, false}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := realHome(t)
			fx := vaulttest.New(t, h.Layout.Base, lifecycleRoot)
			ag := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
			defer ag.Stop()
			ids := []string{lifecycleRoot}
			if tc.globalOpen {
				ids = append(ids, vault.GlobalID)
			}
			ag.UnlockForTest(t, ids, fx.Recovery.String())

			a, e, _ := lifecycleApp(t, h)
			a.sys.agentContext = func(paths.Env, platform.ProcTable) (bool, string) { return false, "" }
			e.tty.lines = []string{wordUnprotect}
			e.tty.yesno = tc.yesno
			want := exitOK
			if !tc.confirmed {
				want = exitLocked
			}
			if code := a.run([]string{"unprotect", h.Root}); code != want {
				t.Fatalf("unprotect: exit %d, want %d (stdout %q stderr %q)", code, want, e.stdout(), e.stderr())
			}
			if !strings.Contains(e.stderr(), ui.Format(ui.MsgPolicyReview, ui.Vars{N: 1})) {
				t.Fatalf("no review of the removal: %q", e.stderr())
			}
			c := ag.Dial(t)
			defer c.Close()
			ctx := context.Background()
			p, err := c.Policy(ctx, ipc.PolicyReq{})
			if err != nil {
				t.Fatal(err)
			}
			st, err := c.Status(ctx)
			if err != nil {
				t.Fatal(err)
			}
			still := false
			for _, v := range st.Vaults {
				still = still || v.VaultID == lifecycleRoot
			}
			switch {
			case tc.confirmed && (len(p.Pending) > 0 || still):
				t.Fatalf("the removal was not confirmed: pending %q, agent still protects it %v (stderr %q)", p.Pending, still, e.stderr())
			case !tc.confirmed && (len(p.Pending) == 0 || !still):
				t.Fatalf("a declined signer unlock confirmed the removal: pending %q, protected %v", p.Pending, still)
			case !tc.confirmed && (!strings.Contains(e.stderr(), "stays protected until you confirm its removal") || strings.Contains(e.stderr(), "is no longer protected")):
				t.Fatalf("unprotect does not say the removal waits: %q", e.stderr())
			}
		})
	}
}
