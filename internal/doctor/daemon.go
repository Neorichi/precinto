package doctor

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
)

// The agent's "needs attention" items speak doctor's vocabulary
// (ipc.Attn*, SPEC §16.4): Run adds each of them as a finding of that
// code, so `doctor` shows everything `status` does, including what only the
// agent can know (MAC checks at unlock, hold times, ungated sessions).

// attnSeverity is the severity of an agent attention item.
var attnSeverity = map[string]Severity{
	ipc.AttnVaultTampered:   Fail,
	ipc.AttnExposed:         Fail,
	ipc.AttnPolicyTampered:  Fail,
	ipc.AttnUnsealed:        Warn,
	ipc.AttnHoldCapped:      Warn,
	ipc.AttnHistoryPending:  Warn,
	ipc.AttnPendingPolicy:   Warn,
	ipc.AttnQuarantine:      Warn,
	ipc.AttnRecoveryTested:  Warn,
	ipc.AttnUnhardenedBuild: Warn,
	ipc.AttnCodexHooksTrust: Warn,
	ipc.AttnCodexWrongHome:  Warn,
	ipc.AttnConflict:        Warn,
	ipc.AttnUngatedSession:  Warn,
}

// attnHarness is the harness an attention code is about, for the harness
// filter of Options.Harness.
var attnHarness = map[string]harness.ID{
	ipc.AttnCodexHooksTrust: harness.Codex,
	ipc.AttnCodexWrongHome:  harness.Codex,
	ipc.AttnHistoryPending:  harness.ClaudeCode,
}

// attnFix is the fix of an attention item that carries none.
var attnFix = map[string]string{
	ipc.AttnUnsealed:        "precinto sweep",
	ipc.AttnHistoryPending:  "quit every Claude session, then run: precinto sweep",
	ipc.AttnPendingPolicy:   "precinto unlock (in a terminal), then confirm the changes",
	ipc.AttnPolicyTampered:  "precinto unlock (in a terminal), then confirm the settings again",
	ipc.AttnRecoveryTested:  "precinto recover --verify",
	ipc.AttnCodexWrongHome:  "precinto run codex",
	ipc.AttnConflict:        "precinto ls --conflicts, then precinto resolve FILE",
	ipc.AttnVaultTampered:   "precinto vault repair",
	ipc.AttnCodexHooksTrust: `in Codex run /hooks and trust "precinto"`,
}

// attentionFindings converts the agent's attention items.
func (e *env) attentionFindings() []Finding {
	st := e.daemon()
	if st == nil {
		return nil
	}
	var out []Finding
	for _, a := range st.Attention {
		if h, ok := attnHarnessOf(a); ok && !e.harnessSelected(h) {
			continue
		}
		out = append(out, e.fromAttention(a))
	}
	return out
}

// attnHarnessOf returns the built-in harness an attention item is about:
// by its code, or for an ungated session by the harness it names.
func attnHarnessOf(a ipc.Attention) (harness.ID, bool) {
	if h, ok := attnHarness[a.Code]; ok {
		return h, true
	}
	if a.Code == ipc.AttnUngatedSession {
		switch harnessCommand(a.Harness) {
		case "claude":
			return harness.ClaudeCode, true
		case string(harness.Codex):
			return harness.Codex, true
		}
	}
	return "", false
}

// fromAttention renders one attention item (texts from the ui catalog
// where it has them; fields are content-free by contract and sanitized
// anyway).
func (e *env) fromAttention(a ipc.Attention) Finding {
	code := oneLine(a.Code)
	sev, ok := attnSeverity[code]
	if !ok {
		sev = Warn // a code this build does not know: never hide it
	}
	folder := oneLine(a.Folder)
	if filepath.IsAbs(a.Folder) {
		folder = e.show(a.Folder)
	}
	where := ""
	if folder != "" {
		where = " in " + folder
	}
	var msg string
	switch code {
	case ipc.AttnVaultTampered:
		msg = catalog(ui.MsgVaultTampered, ui.Vars{Folder: folder})
	case ipc.AttnPolicyTampered:
		msg = catalog(ui.MsgPolicyTampered, ui.Vars{})
	case ipc.AttnPendingPolicy:
		msg = catalog(ui.MsgPolicyPending, ui.Vars{N: a.Count})
	case ipc.AttnCodexWrongHome:
		msg = codexWrongHomeText(a.Count, folder)
	case ipc.AttnUngatedSession:
		name := harnessCommand(a.Harness)
		if name != "" && folder != "" {
			// C9.ungated exactly (CC-48); the text names the fix itself.
			fix := oneLine(a.Fix)
			if fix == "" {
				fix = ungatedFix(name)
			}
			return Finding{Code: code, Severity: sev, Message: catalog(ui.MsgUngatedSession, ui.Vars{Harness: name, PID: a.PID, Folder: folder}), Fix: fix}
		}
		what := "a session"
		if name != "" {
			what = name
			if a.Fix == "" {
				a.Fix = ungatedFix(name)
			}
		}
		msg = fmt.Sprintf("%s (pid %d) runs%s without precinto's hooks, so it cannot be paused when the folder locks (D52)", what, a.PID, where)
	case ipc.AttnUnsealed:
		msg = plural(a.Count, "file", "files") + where + " " + verb(a.Count, "is", "are") + " still unencrypted although the folder is locked"
	case ipc.AttnHoldCapped:
		msg = plural(a.Count, "unit", "units") + where + " " + verb(a.Count, "is", "are") + " kept unsealed only by weak signs of activity (S14)"
	case ipc.AttnHistoryPending:
		msg = plural(a.Count, "line", "lines") + " of Claude's prompt history" + fromWhere(folder) + " " + verb(a.Count, "is", "are") + " still in plaintext"
	case ipc.AttnQuarantine:
		msg = plural(a.Count, "capsule", "capsules") + " without provenance " + verb(a.Count, "is", "are") + " quarantined (D8)"
	case ipc.AttnRecoveryTested:
		msg = "the recovery key has never been tested (D7)"
	case ipc.AttnUnhardenedBuild:
		msg = "this precinto build is not signed with the hardened runtime (S15)"
	case ipc.AttnCodexHooksTrust:
		msg = "Codex has not trusted precinto's hooks" + where
	case ipc.AttnConflict:
		msg = plural(a.Count, "file", "files") + where + " " + verb(a.Count, "has", "have") + " two versions kept side by side (D11)"
	case ipc.AttnExposed:
		msg = plural(a.Count, "capsule", "capsules") + fromWhere(folder) + " " + verb(a.Count, "was", "were") + " sealed to a foreign set of keys (D5)"
	default:
		msg = "the precinto agent reports " + code + where
	}
	if d := oneLine(a.Detail); d != "" {
		msg += " (" + d + ")"
	}
	fix := oneLine(a.Fix)
	if fix == "" {
		fix = attnFix[code]
	}
	return Finding{Code: code, Severity: sev, Message: msg, Fix: fix}
}

func fromWhere(folder string) string {
	if folder == "" {
		return ""
	}
	return " from " + folder
}

// harnessCommand turns the harness of an attention item (ipc.Attention.
// Harness: a harness id or the command name) into the {harness} of
// C9.ungated, the word users type ("precinto run claude"); "" when the
// item names none, or nothing that is a plain command word.
func harnessCommand(h string) string {
	h = oneLine(h)
	if h == string(harness.ClaudeCode) {
		return "claude"
	}
	if !shellSafe(h) || strings.ContainsAny(h, "/~") {
		return ""
	}
	return h
}

// ungatedFix is the fix of an ungated session of harness command name.
func ungatedFix(name string) string { return "quit it, or start it with: precinto run " + name }

// ungatedUnknownCwdText is the finding of a harness process without hooks
// whose working directory cannot be read: it may run in a protected folder
// (unknown counts as inside, D47, D52), but no folder can be named.
func ungatedUnknownCwdText(name string, pid int) string {
	return fmt.Sprintf("%s (pid %d) runs without precinto's hooks and its working folder cannot be read: if it runs in a protected folder, it can't be paused when the folder locks (D52)", name, pid)
}

// hookWindow is the hook-presence window after a harness starts (SPEC
// §14.4: SessionStart within 10 s; Codex: the first prompt).
const hookWindow = 30 * time.Second

func checkUngatedSession(e *env) []Finding {
	if st := e.daemon(); st != nil {
		for _, a := range st.Attention {
			if a.Code == CheckUngatedSession {
				return nil // the agent's own scan (D52) is merged
			}
		}
		return []Finding{ok(CheckUngatedSession, "every running session in a protected folder has precinto's hooks")}
	}
	return e.ungatedScan()
}

// ungatedScan is doctor's own version of the agent's scan (D52) for when
// the agent does not run (then every folder is locked): harness processes
// (by executable, never p_comm) whose cwd lies in a protected folder, or
// cannot be read while some folder protects that harness, and for which no
// hook ever wrote a ledger event. A process whose cwd is unknown is
// reported without a folder. It only reports; nothing is signalled (D57).
func (e *env) ungatedScan() []Finding {
	if e.o.Procs == nil {
		return nil
	}
	ps, err := e.o.Procs.List()
	if err != nil {
		return nil
	}
	type kind struct {
		id    harness.ID
		name  string
		match func(platform.ProcInfo) bool
	}
	kinds := []kind{{harness.ClaudeCode, "claude", isClaudeProcess}, {harness.Codex, "codex", isCodexProcess}}
	var out []Finding
	clean := 0
	for _, k := range kinds {
		if !e.harnessSelected(k.id) {
			continue
		}
		var owners map[platform.ProcID]bool
		loaded := false
		for _, p := range ps {
			if p.State == platform.StateZombie || !k.match(p) {
				continue
			}
			if st := platform.StartTime(p.ID); p.ID.StartUS > 0 && !st.IsZero() && e.now.Sub(st) < hookWindow {
				continue // its first hook may not have run yet
			}
			cwd, err := e.o.Procs.Cwd(p.ID)
			if errors.Is(err, platform.ErrNotSame) || errors.Is(err, platform.ErrNoProcess) {
				continue // it exited meanwhile
			}
			known := err == nil && cwd != ""
			var r config.Root
			if known {
				var inside bool
				if r, inside = e.rootFor(cwd, k.id); !inside {
					continue
				}
			} else if !e.protectsHarness(k.id) {
				continue // no folder protects this harness: it cannot be in one
			}
			if !loaded {
				owners, loaded = e.hookedProcs(k.id), true
			}
			if owners == nil || owners[p.ID] {
				clean++ // hooks reported this process (or the ledger is unreadable: no claim)
				continue
			}
			if !known {
				out = append(out, warn(CheckUngatedSession, ungatedUnknownCwdText(k.name, p.ID.PID), ungatedFix(k.name)))
				continue
			}
			out = append(out, warn(CheckUngatedSession, catalog(ui.MsgUngatedSession, ui.Vars{Harness: k.name, PID: p.ID.PID, Folder: e.folder(r)}),
				ungatedFix(k.name)))
		}
	}
	if len(out) == 0 && clean > 0 {
		out = append(out, ok(CheckUngatedSession, "every running session in a protected folder has precinto's hooks"))
	}
	return out
}

// hookedProcs returns the processes the ledger knows for harness h: hooks
// (or the wrapper) recorded them. nil when the ledger cannot be read.
func (e *env) hookedProcs(h harness.ID) map[platform.ProcID]bool {
	if !isDir(e.o.Layout.SessionsDir) {
		return map[platform.ProcID]bool{}
	}
	ss, err := e.d.Sessions(h)
	if err != nil {
		return nil
	}
	out := map[platform.ProcID]bool{}
	for _, s := range ss {
		addSessionProcs(out, s)
	}
	return out
}

func addSessionProcs(m map[platform.ProcID]bool, s ledger.Session) {
	if !s.CurrentProc.IsZero() {
		m[s.CurrentProc] = true
	}
	for _, p := range s.Procs {
		if !p.IsZero() {
			m[p] = true
		}
	}
}
