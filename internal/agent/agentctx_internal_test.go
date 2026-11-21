package agent

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// markerPeer is a precinto client with a terminal and no harness among its
// ancestors (a login shell's child), working in cwd.
func (x *td) markerPeer(pid int, cwd string) platform.Peer {
	x.addProc(pid-100, 1, pid-100, "/bin/zsh", "-zsh")
	p := platform.Peer{UID: os.Getuid(), PID: pid, Proc: platform.ProcInfo{ID: platform.ProcID{PID: pid, StartUS: int64(pid)}, PPID: pid - 100, TTY: "/dev/ttys011"}}
	x.h.Procs.Add(p.Proc)
	x.h.Procs.SetCwd(pid, cwd)
	return p
}

// CC-11: the client's own AgentMarkers make a same-executable peer an agent
// context (D28/D59) whatever its ancestry shows: unlocking another folder
// is refused without a dialog, and content key releases need fresh
// presence; an empty list changes nothing.
func TestAgentMarkersRestrictTheClient(t *testing.T) {
	x := startTD(t)
	ctx := context.Background()
	x.caps.add("md/aaaa/g000001.pcap", "root-acme", "root-acme")
	x.caps.add("md/bbbb/g000001.pcap", "root-beta", "root-beta")
	markers := []string{"CLAUDECODE"}

	// Without markers this peer is the user at a terminal.
	human := x.markerPeer(7700, x.h.Root)
	x.setPeer(&human, true)
	ch := x.dial()
	if _, err := ch.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-beta"}, TTY: true}, nil); err != nil {
		t.Fatalf("empty markers changed the rules: %v", err)
	}
	if _, err := ch.Lock(ctx, ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}

	x.d.mu.Lock()
	pinnedAt := x.d.pol.pinned.ConfirmedAt
	x.d.mu.Unlock()
	x.h.Clock.Advance(time.Minute)

	// With markers: another folder is refused before any prompt …
	before := x.vaults.count("root-beta")
	_, err := ch.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-beta"}, TTY: true, AgentMarkers: markers}, nil)
	if ipcCode(err) != ipc.CodeAgentContext || x.vaults.count("root-beta") != before {
		t.Fatalf("marked client unlocking another folder = %v (C12.agent, no dialog)", err)
	}
	// … and its own folder (its working directory) stays possible.
	if _, err := ch.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true, AgentMarkers: markers}, nil); err != nil {
		t.Fatalf("marked client unlocking its own folder = %v", err)
	}
	// A TTY unlock by a marked client is not a human confirmation.
	x.d.mu.Lock()
	repinned := !x.d.pol.pinned.ConfirmedAt.Equal(pinnedAt)
	x.d.mu.Unlock()
	if repinned {
		t.Fatal("an agent-context unlock re-pinned the policy (D68: non-agent peers only)")
	}

	// Key releases: every purpose needs fresh presence for a marked client;
	// another folder's keys are refused.
	self := x.dial() // the in-process peer unlocks both folders
	x.setPeer(nil, true)
	if _, err := self.Unlock(ctx, ipc.UnlockReq{All: true, TTY: true, Confirmed: true}, nil); err != nil {
		t.Fatal(err)
	}
	x.setPeer(&human, true)
	cm := x.dial()
	refs := []ipc.CapsuleRef{{Path: "md/aaaa/g000001.pcap"}, {Path: "md/bbbb/g000001.pcap"}}
	for _, purpose := range []string{ipc.PurposeCat, ipc.PurposeOpen, ipc.PurposeRestoreAll, ipc.PurposeList, ipc.PurposeRestore} {
		n := x.vaults.count("root-acme")
		ks, resp, err := cm.Keys(ctx, ipc.KeysReq{Capsules: refs, Purpose: purpose, AgentMarkers: markers})
		if err != nil {
			t.Fatal(err)
		}
		ks.Destroy()
		if resp.Denied["md/bbbb/g000001.pcap"] != ipc.CodeAgentContext {
			t.Fatalf("%s: marked client got another folder's key: %+v", purpose, resp)
		}
		if len(resp.Granted) != 1 || x.vaults.count("root-acme") != n+1 {
			t.Fatalf("%s: own folder without fresh presence: %+v (prompts %d)", purpose, resp, x.vaults.count("root-acme")-n)
		}
	}
	// The same requests without markers: no presence prompt for a user at
	// a terminal, both folders granted.
	n := x.vaults.count("root-acme")
	ks, resp, err := cm.Keys(ctx, ipc.KeysReq{Capsules: refs, Purpose: ipc.PurposeCat})
	if err != nil {
		t.Fatal(err)
	}
	ks.Destroy()
	if len(resp.Granted) != 2 || x.vaults.count("root-acme") != n {
		t.Fatalf("unmarked user at a terminal: %+v (prompts %d)", resp, x.vaults.count("root-acme")-n)
	}
}

// CC-11: markers are a self-restricting claim even for an in-process
// client, which the ancestry rules otherwise trust.
func TestAgentMarkersFromTheDaemonItself(t *testing.T) {
	x := startTD(t)
	c := x.dial() // the in-process peer
	if _, err := c.Unlock(context.Background(), ipc.UnlockReq{RootIDs: []string{"root-beta"}, TTY: true, AgentMarkers: []string{"CODEX_THREAD_ID"}}, nil); ipcCode(err) != ipc.CodeAgentContext {
		t.Fatalf("in-process client with markers = %v", err)
	}
	f := factsOf(platform.Peer{PID: platform.Self().PID}, nil, false).withMarkers([]string{"X"})
	if f.self || !f.agent || !f.needsPresence(ipc.PurposeRestore) {
		t.Fatalf("facts = %+v", f)
	}
	if g := factsOf(platform.Peer{PID: platform.Self().PID}, nil, false).withMarkers(nil); !g.self || g.agent {
		t.Fatalf("empty markers = %+v", g)
	}
}

// D64: the stop also covers the peer itself (the test process dialling
// the daemon directly), and a test stop never hides the no-controlling-
// terminal rule or the markers.
func TestAncestryStopKeepsMarkersAndTerminalRule(t *testing.T) {
	if !paths.TestingBuild() {
		t.Skip("PRECINTO_TEST_ANCESTRY_STOP is read in -tags testing builds only")
	}
	stop := platform.ProcID{PID: 7210, StartUS: 7}
	x := startTD(t, func(x *td, o *Options) {
		o.Env = o.Env.With(paths.EnvTestAncestryStop, stop.String())
	})
	ctx := context.Background()
	// The stop process itself runs claude's executable (a fake that would
	// otherwise be an agent): ignored like its ancestors.
	x.addProc(7000, 1, 7000, "/bin/zsh", "-zsh")
	peer := platform.Peer{UID: os.Getuid(), PID: stop.PID, Proc: platform.ProcInfo{ID: stop, PPID: 7000, Exe: "/opt/homebrew/bin/claude", Argv: []string{"claude"}, TTY: "/dev/ttys012"}}
	x.h.Procs.Add(peer.Proc)
	x.setPeer(&peer, true)
	c := x.dial()
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-beta"}, TTY: true}, nil); ipcCode(err) == ipc.CodeAgentContext {
		t.Fatalf("the stop process itself counted as an agent: %v", err)
	}
	if _, err := c.Lock(ctx, ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	// Markers still apply below (and at) the stop.
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-beta"}, TTY: true, AgentMarkers: []string{"CLAUDECODE"}}, nil); ipcCode(err) != ipc.CodeAgentContext {
		t.Fatalf("markers with the stop set = %v", err)
	}
	// So does the no-controlling-terminal rule (D59).
	nt := platform.Peer{UID: os.Getuid(), PID: 7320, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 7320, StartUS: 9}, PPID: stop.PID}}
	x.h.Procs.Add(nt.Proc)
	x.h.Procs.SetCwd(7320, x.h.HomeDir)
	x.setPeer(&nt, true)
	c2 := x.dial()
	if _, err := c2.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-beta"}}, nil); ipcCode(err) != ipc.CodeAgentContext {
		t.Fatalf("no controlling terminal below the stop = %v", err)
	}
}
