package agent

import (
	"path"
	"strings"
	"sync"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/inventories"
)

// The daemon recognizes harness processes with the embedded inventories
// (CC-12): `register` verifies the executable with Inventory.MatchProcess
// of the harness it names, and the D52 scan looks for processes that match
// an enabled inventory. Matching is by executable path and argv, never by
// the kernel's short name (Claude's p_comm is its version string, IM9).

// loadInventories parses inventories.FS once per process. A failure (a
// build that embeds a broken inventory; inventories' own tests refuse it)
// leaves the list empty: nothing then registers and the scan finds
// nothing, and the daemon logs why.
var loadInventories = sync.OnceValues(func() ([]harness.Inventory, error) {
	return harness.LoadInventories(inventories.FS)
})

// embeddedInventories returns the parsed inventories (nil on error).
func embeddedInventories() []harness.Inventory {
	invs, err := loadInventories()
	if err != nil {
		return nil
	}
	return invs
}

// builtIn reports the adapters precinto ships natively.
func builtIn(id string) bool {
	return id == string(harness.ClaudeCode) || id == string(harness.Codex)
}

// harnessEnabled reports whether processes of harness id may register and
// are looked for by the scan: the built-in adapters always (their hooks
// and wrapper exist whatever config says), a generic inventory only when
// config enables it as experimental (D33, `precinto integrate`).
func harnessEnabled(c config.Config, id string) bool {
	if builtIn(id) {
		return true
	}
	h, ok := c.Harness[id]
	return ok && h.Enabled && h.Experimental
}

// matchHarness reports whether p is a live process of harness id that is
// enabled in c, by that harness's inventory.
func matchHarness(invs []harness.Inventory, c config.Config, id string, p platform.ProcInfo) bool {
	if id == "" || !harnessEnabled(c, id) {
		return false
	}
	for _, inv := range invs {
		if inv.ID == id {
			return inv.MatchProcess(p)
		}
	}
	return false
}

// harnessOfProc returns the enabled harness whose inventory matches p: the
// built-in adapters first (in that order), then the generic inventories by
// id, so one process is attributed to one harness deterministically.
func harnessOfProc(invs []harness.Inventory, c config.Config, p platform.ProcInfo) (string, bool) {
	for _, id := range []string{string(harness.ClaudeCode), string(harness.Codex)} {
		if matchHarness(invs, c, id, p) {
			return id, true
		}
	}
	for _, inv := range invs {
		if builtIn(inv.ID) || !harnessEnabled(c, inv.ID) {
			continue
		}
		if inv.MatchProcess(p) {
			return inv.ID, true
		}
	}
	return "", false
}

// harnessCommand is the command name a harness id runs as ({harness} of
// C9.ungated and `precinto run {harness}`): claude-code runs as claude.
func harnessCommand(id string) string { return strings.TrimSuffix(id, "-code") }

// Agent-context ancestry (D28) is wider than registration: an ancestor is
// an AI agent when any inventory matches it (enabled or not) or when it is
// one of the agents precinto knows by name, the same list and rules as
// ui.AgentContext (which works on the current process and so cannot be
// reused for a peer). The daemon's check must never be weaker than the
// CLI's.

// knownAgents are the programs whose descendants run inside an AI agent
// session (D28).
var knownAgents = map[string]bool{
	"claude": true, "codex": true, "droid": true, "cursor-agent": true,
	"copilot": true, "gemini": true, "kimi": true, "opencode": true,
}

// agentPackages maps npm package directories to the agent they ship, for
// scripts started by path inside node_modules (node …/cli.js).
var agentPackages = map[string]string{
	"/node_modules/@anthropic-ai/claude-code/": "claude",
	"/node_modules/@openai/codex/":             "codex",
	"/node_modules/@google/gemini-cli/":        "gemini",
	"/node_modules/@github/copilot/":           "copilot",
	"/node_modules/opencode-ai/":               "opencode",
}

// agentProgram reports which AI agent p runs, judging by the executable,
// argv[0] and, for script interpreters, the script; native installs run
// …/<agent>/versions/<v> (and Claude's ~/.claude/local/…). Names compare
// case-insensitively. The kernel name (Comm) is never used.
func agentProgram(p platform.ProcInfo) (string, bool) {
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
		if h := programName(n); knownAgents[h] {
			return h, true
		}
		for dir, h := range agentPackages {
			if strings.Contains(n, dir) {
				return h, true
			}
		}
	}
	if p.Exe != "" {
		dir := path.Dir(p.Exe)
		parent := strings.ToLower(path.Base(path.Dir(dir)))
		switch {
		case path.Base(dir) == "versions" && knownAgents[parent]:
			return parent, true
		case path.Base(dir) == "local" && parent == ".claude":
			return "claude", true
		}
	}
	for _, inv := range embeddedInventories() {
		if inv.MatchProcess(p) {
			return harnessCommand(inv.ID), true
		}
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
