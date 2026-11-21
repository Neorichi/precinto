package agent

import (
	"slices"

	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
)

// maxAncestry bounds the ancestry walk of a peer.
const maxAncestry = 64

// peerFacts is what the daemon knows about who asks.
type peerFacts struct {
	self        bool   // the daemon's own process (in-process clients)
	worker      bool   // a descendant of the daemon: one of its workers
	agent       bool   // a known harness among the ancestors (D28), or claimed agent markers (CC-11)
	markers     bool   // the client sent its own paths.AgentMarkers (a self-restricting claim)
	noCTTY      bool   // no controlling terminal and not a worker (D59)
	harness     string // the harness ancestor, if any
	harnessProc platform.ProcInfo
}

// factsOf classifies a peer from its ancestry (nearest first). The walk
// stops at the daemon: its workers are never agent contexts. The caller
// has already cut the ancestry at the D64 test stop (daemon.ancestry);
// peerIsStop says the peer itself is that process, which is then ignored
// like its ancestors.
func factsOf(peer platform.Peer, ancestry []platform.ProcInfo, peerIsStop bool) peerFacts {
	self := platform.Self()
	if peer.PID == self.PID {
		return peerFacts{self: true}
	}
	var f peerFacts
	for _, a := range ancestry {
		if a.ID.PID == self.PID {
			f.worker = true
			break
		}
		if h, ok := agentProgram(a); ok && !f.agent {
			f.agent, f.harness, f.harnessProc = true, h, a
		}
	}
	if f.worker {
		return peerFacts{worker: true}
	}
	if !peerIsStop {
		if h, ok := agentProgram(peer.Proc); ok {
			// A harness process talking to the daemon itself is an agent too.
			f.agent, f.harness, f.harnessProc = true, h, peer.Proc
		}
	}
	f.noCTTY = peer.Proc.TTY == ""
	return f
}

// withMarkers applies the client's own agent markers (CC-11, D28, D59): a
// non-empty list is a self-restricting claim, so it makes the peer an
// agent context whatever the ancestry shows (an in-process client or a
// worker included); an empty list proves nothing and changes nothing.
func (f peerFacts) withMarkers(markers []string) peerFacts {
	if len(markers) == 0 {
		return f
	}
	f.markers, f.agent = true, true
	f.self, f.worker = false, false
	return f
}

// contentPurpose reports the explicit content-revealing purposes for which
// a peer without a controlling terminal counts as an agent context (D59).
func contentPurpose(purpose string) bool {
	switch purpose {
	case ipc.PurposeRestoreAll, ipc.PurposeOpen, ipc.PurposeCat, ipc.PurposeList:
		return true
	}
	return false
}

// needsPresence reports whether a key release for purpose must first get
// fresh user presence (D28, D59).
func (f peerFacts) needsPresence(purpose string) bool {
	if f.self || f.worker {
		return false
	}
	return f.agent || (f.noCTTY && contentPurpose(purpose))
}

// refuse builds the C12.agent refusal.
func refuse(action, folder, command string) *ipc.Error {
	return &ipc.Error{Code: ipc.CodeAgentContext, Msg: ui.Format(ui.MsgRefuseAgent, ui.Vars{Action: action, Folder: folder, Command: command})}
}

// authorize implements Authorize with folder names for messages.
func authorize(peer platform.Peer, ancestry []platform.ProcInfo, op ipc.Op, purpose string, rootIDs, sessionRoots []string, name folderName) *ipc.Error {
	return authorizeFacts(factsOf(peer, ancestry, false), op, purpose, rootIDs, sessionRoots, name)
}

// authorizeFacts applies the D28/D59 rules to measured facts.
func authorizeFacts(f peerFacts, op ipc.Op, purpose string, rootIDs, sessionRoots []string, name folderName) *ipc.Error {
	if name == nil {
		name = idFolder
	}
	if f.self || f.worker {
		return nil
	}
	refused := f.agent || f.noCTTY // D28 refusals, extended to TTY-less peers by D59
	switch op {
	case ipc.OpFactorAdd:
		if refused {
			return refuse("add a factor to", "your folders", "factor add")
		}
	case ipc.OpVaultRepair:
		if refused {
			folder := "the vault of"
			if len(rootIDs) > 0 {
				folder = name(rootIDs[0])
			}
			return refuse("repair", folder, "vault repair --root "+folder)
		}
	case ipc.OpPolicy:
		if refused {
			return refuse("confirm the settings of", "your folders", "unlock")
		}
	case ipc.OpUnlock:
		if f.agent {
			for _, id := range rootIDs {
				if !slices.Contains(sessionRoots, id) {
					return refuse("unlock", name(id), "unlock --root "+name(id))
				}
			}
		}
	case ipc.OpKeys:
		if f.agent {
			// An agent working in one folder never gets another folder's
			// keys (D1, D28); its own folder's need fresh presence.
			for _, id := range rootIDs {
				if !slices.Contains(sessionRoots, id) {
					return refuse("open", name(id), "restore --root "+name(id))
				}
			}
		}
	}
	return nil
}
