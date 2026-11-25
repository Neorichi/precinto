package agent

import (
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/vault"
)

// D152: a fix command the agent builds names the global vault with
// --global, never the invalid `--root global`; a folder keeps --root.
func TestFixCommandsNameTheGlobalVaultWithGlobal(t *testing.T) {
	name := func(id string) string {
		if id == vault.GlobalID {
			return "global"
		}
		return "~/work/acme"
	}
	if got := targetArg(vault.GlobalID, name); got != "--global" {
		t.Errorf("targetArg(global) = %q", got)
	}
	if got := targetArg("r1", name); got != "--root ~/work/acme" {
		t.Errorf("targetArg(folder) = %q", got)
	}
	agentPeer := peerFacts{agent: true}
	for _, tc := range []struct {
		op   ipc.Op
		want string
	}{
		{ipc.OpUnlock, "precinto unlock --global"},
		{ipc.OpKeys, "precinto restore --global"},
		{ipc.OpVaultRepair, "precinto vault repair --global"},
	} {
		e := authorizeFacts(agentPeer, tc.op, "", []string{vault.GlobalID}, nil, name)
		if e == nil {
			t.Fatalf("%s from an agent context was allowed", tc.op)
		}
		if !strings.Contains(e.Msg, tc.want) || strings.Contains(e.Msg, "--root") {
			t.Errorf("%s: %q, want %q and no --root", tc.op, e.Msg, tc.want)
		}
	}
}
