package agent

import (
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/ui"
)

// Gate states reported in ipc.GateResp.State.
const (
	gateStateUnlocked = "unlocked"
	gateStateLocked   = "locked"
	gateStatePaused   = "paused"
)

// gateView is everything a gate decision reads: a snapshot at a moment and
// the console state (unknown to a plain Snapshot).
type gateView struct {
	now          time.Time
	vaults       map[string]VaultSnapshot
	sessions     map[string]SessionSnapshot
	screenLocked bool
	screenKnown  bool
}

// folderName renders a vault id for messages ({folder}).
type folderName func(vaultID string) string

func idFolder(id string) string { return id }

// decide is the gate (SPEC §12.6, §13.4). Unknown folders are locked; with
// no folder at all the session is unmanaged and allowed. Every locked case
// blocks or denies, except the in-turn grace of a session that was busy
// when its folder locked by a trigger or by `lock --let-finish` (UX2).
func decide(v gateView, p config.Policy, q GateQuery, name folderName) ipc.GateResp {
	if name == nil {
		name = idFolder
	}
	roots := dedupe(q.RootIDs)
	resp := ipc.GateResp{Verdict: ipc.VerdictAllow, State: gateStateUnlocked, RootIDs: roots, Origin: q.Origin}
	if len(roots) == 0 {
		return resp
	}
	var locked []string
	for _, id := range roots {
		if vs, ok := v.vaults[id]; !ok || vs.State != VaultUnlocked {
			locked = append(locked, id)
		}
	}
	if len(locked) == 0 {
		return resp
	}
	first := locked[0]
	reason := ui.ReasonStart
	if vs, ok := v.vaults[first]; ok && vs.Reason != "" {
		reason = ui.Reason(vs.Reason)
	}
	vars := ui.Vars{Folder: name(first), Reason: reason, Idle: idleSoft(p), Limit: ClampTTL(p, 0)}
	resp.State, resp.Reason = gateStateLocked, string(reason)
	ss, known := v.sessions[q.SID]
	if known && ss.State == SessionPaused {
		resp.State = gateStatePaused
	}
	// In-turn grace (UX2): the session was busy when its folder locked,
	// the lock allows it to finish, and it is still in that turn.
	inTurn := known && ss.State == SessionPaused && ss.BusyAtLock && ss.Busy &&
		(p.BusyGrace.D() <= 0 || v.now.Sub(ss.LockedAt) < p.BusyGrace.D())
	blocked := ui.Format(ui.MsgPromptBlocked, vars)
	denied := ui.Format(ui.MsgToolDenied, vars)
	switch q.Event {
	case GateStart:
		// SessionStart never blocks: it only tells the model (and the user).
		resp.ModelMessage = ui.Format(ui.MsgStartLockedModel, vars)
		resp.UserMessage = ui.Format(ui.MsgStartLockedUser, vars)
	case GatePrompt:
		// Automated prompts are blocked like human ones (D26); only a human
		// prompt may lead to a hook-raised unlock (D27, D37).
		resp.Verdict, resp.UserMessage = ipc.VerdictBlock, blocked
		resp.UnlockEligible = p.UnlockOnPrompt && q.Origin == ipc.OriginHuman && v.screenKnown && !v.screenLocked
	case GateTool, GatePermission:
		if !inTurn {
			resp.Verdict, resp.UserMessage, resp.ModelMessage = ipc.VerdictDeny, blocked, denied
		}
	case GateCompact:
		if !inTurn {
			resp.Verdict, resp.UserMessage = ipc.VerdictBlock, ui.Format(ui.MsgCompactPaused, vars)
		}
	default:
		// An event the daemon does not know is gated like a prompt.
		resp.Verdict, resp.UserMessage, resp.ModelMessage = ipc.VerdictBlock, blocked, denied
	}
	return resp
}

// viewOf builds the view of a published snapshot (console state unknown).
func viewOf(s *Snapshot) gateView {
	if s == nil {
		return gateView{}
	}
	return gateView{now: s.At, vaults: s.Vaults, sessions: s.Sessions}
}

// gateFromSnapshot implements GateFromSnapshot.
func gateFromSnapshot(s *Snapshot, p config.Policy, q GateQuery) ipc.GateResp {
	return decide(viewOf(s), p, q, idFolder)
}

// gate implements Machine.Gate on the machine's current state.
func (m *Machine) gate(q GateQuery) ipc.GateResp {
	s := m.snapshot()
	v := viewOf(&s)
	v.screenLocked, v.screenKnown = m.screen.locked, true
	return decide(v, m.policy, q, idFolder)
}
