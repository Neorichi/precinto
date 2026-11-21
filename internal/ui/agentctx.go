package ui

import (
	"fmt"
	"path"
	"strings"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// maxAncestors bounds the ancestry walk of AgentContext.
const maxAncestors = 128

// knownHarnesses are the programs whose descendants run inside an AI agent
// session (AgentContext, D28).
var knownHarnesses = map[string]bool{
	"claude": true, "codex": true, "droid": true, "cursor-agent": true,
	"copilot": true, "gemini": true, "kimi": true, "opencode": true,
}

// harnessPackages maps npm package directories to the harness they ship, for
// scripts started by path inside node_modules (node …/cli.js).
var harnessPackages = map[string]string{
	"/node_modules/@anthropic-ai/claude-code/": "claude",
	"/node_modules/@openai/codex/":             "codex",
	"/node_modules/@google/gemini-cli/":        "gemini",
	"/node_modules/@github/copilot/":           "copilot",
	"/node_modules/opencode-ai/":               "opencode",
}

// agentProbe holds the inputs of AgentContext besides the environment and
// the process table, so that tests can substitute them.
type agentProbe struct {
	markers func(paths.Env) []string // paths.AgentMarkers
	pid     int                      // the current process
	ctty    func() bool              // whether the process has a controlling terminal
}

// agentContext implements AgentContext. Checks run from the cheapest to the
// most expensive and the first evidence found is returned. Whatever cannot
// be determined counts as an agent context (fail closed).
func agentContext(e paths.Env, t platform.ProcTable, p agentProbe) (bool, string) {
	if p.markers != nil {
		if m := p.markers(e); len(m) > 0 {
			noun := "environment variable "
			if len(m) > 1 {
				noun = "environment variables "
			}
			return true, noun + strings.Join(m, ", ")
		}
	}
	if found, evidence := harnessAncestor(t, p.pid); found {
		return true, evidence
	}
	if p.ctty == nil || !p.ctty() {
		return true, "no controlling terminal"
	}
	return false, ""
}

// harnessAncestor looks for a known harness among the ancestors of pid.
func harnessAncestor(t platform.ProcTable, pid int) (bool, string) {
	if t == nil {
		return true, "process ancestry unavailable"
	}
	anc, err := platform.Ancestors(t, pid, maxAncestors)
	if err != nil {
		return true, "process ancestry unavailable"
	}
	for _, a := range anc {
		if name, ok := harnessName(a); ok {
			return true, fmt.Sprintf("ancestor process %s (pid %d)", name, a.ID.PID)
		}
	}
	if len(anc) == maxAncestors && anc[len(anc)-1].PPID > 1 {
		return true, "process ancestry too deep"
	}
	return false, ""
}

// harnessName reports which known harness p runs. It looks at the
// executable, argv[0] and, for script interpreters (node, bun, deno, python,
// ruby, perl), the script; Claude Code's native installs run a versioned
// file (…/claude/versions/<version>). Names compare case-insensitively
// (darwin file names do; the desktop apps run …/Claude.app/…/Claude).
// Comm is never used: for Claude Code it is the version string.
func harnessName(p platform.ProcInfo) (string, bool) {
	names := []string{p.Exe}
	if len(p.Argv) > 0 {
		names = append(names, p.Argv[0])
		if isInterpreter(p.Exe) || isInterpreter(p.Argv[0]) {
			if s := scriptOf(p.Argv[1:]); s != "" {
				names = append(names, s)
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
	if h, ok := versionedInstall(p.Exe); ok {
		return h, true
	}
	return "", false
}

// programName returns the lowercased last element of a path without a
// script or executable extension ("-zsh" login shells lose the dash).
func programName(p string) string {
	p = strings.TrimRight(p, "/")
	name := strings.ToLower(p[strings.LastIndexByte(p, '/')+1:])
	name = strings.TrimPrefix(name, "-")
	for _, ext := range []string{".js", ".mjs", ".cjs", ".ts", ".py", ".exe"} {
		if strings.HasSuffix(name, ext) {
			return strings.TrimSuffix(name, ext)
		}
	}
	return name
}

// isInterpreter reports whether p names a script interpreter whose first
// non-flag argument is the program it runs.
func isInterpreter(p string) bool {
	n := programName(p)
	switch n {
	case "node", "nodejs", "bun", "deno", "ruby", "perl":
		return true
	}
	for _, prefix := range []string{"python", "pypy"} {
		if v, ok := strings.CutPrefix(n, prefix); ok {
			return strings.Trim(v, "0123456789.") == ""
		}
	}
	return false
}

// scriptOf returns the first argument that is not a flag.
func scriptOf(args []string) string {
	for _, a := range args {
		if a != "" && !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// versionedInstall recognizes …/<harness>/versions/<version> executables.
func versionedInstall(exe string) (string, bool) {
	if exe == "" {
		return "", false
	}
	dir := path.Dir(exe)
	if path.Base(dir) != "versions" {
		return "", false
	}
	h := programName(path.Dir(dir))
	return h, knownHarnesses[h]
}
