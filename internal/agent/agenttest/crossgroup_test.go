//go:build crossgroup

package agenttest_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/agent/agenttest"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/internal/vault/vaulttest"
)

// recoveryUI answers the vault's secret prompt with the recovery key.
type recoveryUI struct{ key string }

func (u recoveryUI) Display(string) error { return nil }
func (u recoveryUI) Secret(string) (*memguard.LockedBuffer, error) {
	return memguard.NewBufferFromBytes([]byte(u.key)), nil
}
func (u recoveryUI) Confirm(string, string, string) (bool, error) { return true, nil }

// TestUnlockIdleLockWithRealVaults needs G1's vault: an unlock through the
// in-process daemon, then the idle lock on the fake clock (D23) and the
// workers it asks for (SPEC §11.6, §12.7).
func TestUnlockIdleLockWithRealVaults(t *testing.T) {
	h := testkit.NewHome(t)
	fx := vaulttest.New(t, h.Layout.Base, "root-acme")
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	c := a.Dial(t)
	ctx := context.Background()
	r, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true, Factor: "recovery"}, recoveryUI{key: fx.Recovery.String()})
	if err != nil || !slices.Contains(r.Unlocked, "root-acme") {
		t.Fatalf("Unlock = %+v %v", r, err)
	}
	g, err := c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "PreToolUse", SID: "00000000-0000-4000-8000-000000000004", Cwd: h.Root})
	if err != nil || g.Verdict != ipc.VerdictAllow {
		t.Fatalf("gate after unlock = %+v %v", g, err)
	}
	h.Clock.Advance(16 * time.Minute)
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, _ := c.Status(ctx)
		i := slices.IndexFunc(st.Vaults, func(v ipc.VaultStatus) bool { return v.VaultID == "root-acme" })
		if i >= 0 && st.Vaults[i].State == "locked" && st.Vaults[i].Reason == "idle" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not locked at idle_soft")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The lock is visible (the state is published first) a moment before
	// its keyless seal worker is asked for.
	deadline = time.Now().Add(5 * time.Second)
	for {
		var restore, seal bool
		for _, argv := range a.Spawned() {
			restore = restore || (len(argv) > 2 && argv[1] == "restore" && slices.Contains(argv, "--background"))
			seal = seal || (len(argv) > 2 && argv[1] == "sweep" && slices.Contains(argv, "--lock"))
		}
		if restore && seal {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("spawned = %q", a.Spawned())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
