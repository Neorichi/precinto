package agent

import (
	"path"
	"slices"
	"strings"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
)

// maxAncestry bounds the ancestry walk of a peer.
const maxAncestry = 64

// knownHarnesses are the programs whose descendants run inside an AI agent
// session (D28); the same list as ui.AgentContext uses.
var knownHarnesses = map[string]bool{
	"claude": true, "codex": true, "droid": true, "cursor-agent": true,
	"copilot": true, "gemini": true, "kimi": true, "opencode": true,
}

// harnessPackages maps npm package directories to the harness they ship.
var harnessPackages = map[string]string{
	"/node_modules/@anthropic-ai/claude-code/": "claude",
	"/node_modules/@openai/codex/":             "codex",
	"/node_modules/@google/gemini-cli/":        "gemini",
	"/node_modules/@github/copilot/":           "copilot",
	"/node_modules/opencode-ai/":               "opencode",
}

// harnessProgram reports which known harness p runs, judging by the
// executable, argv[0] and, for script interpreters, the script; native
// Claude installs run …/claude/versions/<v> (and ~/.claude/local/…). The
// kernel name (Comm) is never used: Claude's is its version string (IM9).
func harnessProgram(p platform.ProcInfo) (string, bool) {
	names := []string{p.Exe}
	if len(p.Argv) > 0 {
		names = append(names, p.Argv[0])
		if isInterpreter(p.Exe) || isInterpreter(p.Argv[0]) {
			for _, a := range p.Argv[1:] {
				if a != "" && !strings.HasPrefix(a, "-") {
					names = append(names, a)
					break
				}
			}
		}
	}
	for _, n := range names {
		if n == "" {
			continue
		}
		if h := programName(n); knownHarnesses[h] {
			return h, true
		}
		for dir, h := range harnessPackages {
			if strings.Contains(n, dir) {
				return h, true
			}
		}
	}
	if p.Exe != "" {
		dir := path.Dir(p.Exe)
		parent := path.Base(path.Dir(dir))
		switch {
		case path.Base(dir) == "versions" && knownHarnesses[strings.ToLower(parent)]:
			return strings.ToLower(parent), true
		case path.Base(dir) == "local" && parent == ".claude":
			return "claude", true
		}
	}
	return "", false
}

// harnessOf maps a process to a built-in harness id (claude-code, codex).
func harnessOf(p platform.ProcInfo) (harness.ID, bool) {
	switch n, _ := harnessProgram(p); n {
	case "claude":
		return harness.ClaudeCode, true
	case "codex":
		return harness.Codex, true
	}
	return "", false
}

// programName returns the lowercased last element of p without a script
// extension ("-zsh" login shells lose the dash).
func programName(p string) string {
	p = strings.TrimRight(p, "/")
	name := strings.ToLower(p[strings.LastIndexByte(p, '/')+1:])
	name = strings.TrimPrefix(name, "-")
	for _, ext := range []string{".js", ".mjs", ".cjs", ".ts", ".py", ".exe"} {
		name = strings.TrimSuffix(name, ext)
	}
	return name
}

func isInterpreter(p string) bool {
	switch n := programName(p); {
	case n == "node" || n == "nodejs" || n == "bun" || n == "deno" || n == "ruby" || n == "perl":
		return true
	case strings.HasPrefix(n, "python"):
		return strings.Trim(strings.TrimPrefix(n, "python"), "0123456789.") == ""
	}
	return false
}

// peerFacts is what the daemon knows about who asks.
type peerFacts struct {
	self        bool   // the daemon's own process (in-process clients)
	worker      bool   // a descendant of the daemon: one of its workers
	agent       bool   // a known harness among the ancestors (D28)
	noCTTY      bool   // no controlling terminal and not a worker (D59)
	harness     string // the harness ancestor, if any
	harnessProc platform.ProcInfo
}

// factsOf classifies a peer from its ancestry (nearest first). The walk
// stops at the daemon: its workers are never agent contexts.
func factsOf(peer platform.Peer, ancestry []platform.ProcInfo) peerFacts {
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
		if h, ok := harnessProgram(a); ok && !f.agent {
			f.agent, f.harness, f.harnessProc = true, h, a
		}
	}
	if f.worker {
		return peerFacts{worker: true}
	}
	if h, ok := harnessProgram(peer.Proc); ok {
		// A harness process talking to the daemon itself is an agent too.
		f.agent, f.harness, f.harnessProc = true, h, peer.Proc
	}
	f.noCTTY = peer.Proc.TTY == ""
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
	if name == nil {
		name = idFolder
	}
	f := factsOf(peer, ancestry)
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
