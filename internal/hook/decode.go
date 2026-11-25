package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// Decode errors. They never carry payload bytes: a json error can quote
// the input, so it is never wrapped (S11, S13).
var (
	errTooLarge  = errors.New("hook: payload larger than MaxPayload")
	errMalformed = errors.New("hook: payload is not a JSON object of the expected shape")
)

// maxPaths bounds the tool paths kept from one payload.
const maxPaths = 4096

// maxAncestors bounds the ancestry walk that finds the harness process.
const maxAncestors = 64

// Environment variables read for harness facts (HOOKS-IO §2.3, §3.3). The
// session-id and messaging variables are deliberately not read.
const (
	envClaudeEntrypoint = "CLAUDE_CODE_ENTRYPOINT"
	envClaudeExecPath   = "CLAUDE_CODE_EXECPATH"
	envCodexVersion     = "CODEX_VERSION"
)

// applyPatchPaths extracts the header paths of an apply_patch command (G3,
// HA25). A variable so that tests can substitute it.
var applyPatchPaths = codex.ApplyPatchPaths

// selfPID is the hook process, where the ancestry walk to the harness
// starts, and parentPID its parent (the last fallback for Claude's pid).
// Variables so that tests can root them in a fake process table.
var (
	selfPID   = os.Getpid
	parentPID = os.Getppid
)

// wirePayload holds the payload fields any host may send that precinto
// reads (HOOKS-IO §2.3, §3.3, §4). Everything else, in particular prompt,
// tool output, summaries and file content, is skipped by the decoder and
// never retained. tool_input is kept raw so that only its path keys are
// read from it.
type wirePayload struct {
	SessionID        *string         `json:"session_id"`
	PromptID         *string         `json:"prompt_id"`
	TurnID           *string         `json:"turn_id"`
	TranscriptPath   *string         `json:"transcript_path"`
	Cwd              *string         `json:"cwd"`
	ScratchpadDir    *string         `json:"scratchpad_dir"`
	AgentID          *string         `json:"agent_id"`
	Source           *string         `json:"source"`
	Reason           *string         `json:"reason"`
	Trigger          *string         `json:"trigger"`
	ToolName         *string         `json:"tool_name"`
	ToolInput        json.RawMessage `json:"tool_input"`
	NotificationType *string         `json:"notification_type"`
	OldCwd           *string         `json:"old_cwd"`
	NewCwd           *string         `json:"new_cwd"`
	Directory        *string         `json:"directory"`

	// Cursor (UNVERIFIED, HOOKS-IO §4).
	ConversationID *string  `json:"conversation_id"`
	WorkspaceRoots []string `json:"workspace_roots"`
	FilePath       *string  `json:"file_path"`

	// Copilot CLI (UNVERIFIED, camelCase).
	SessionIDCamel *string         `json:"sessionId"`
	ToolNameCamel  *string         `json:"toolName"`
	ToolArgs       json.RawMessage `json:"toolArgs"`
}

// toolPathKeys are the only tool_input keys read (HOOKS-IO §2.3).
var toolPathKeys = []string{"file_path", "notebook_path", "path"}

// markdownWriters are the tools whose paths are agent-written files
// (Payload.MarkdownPaths): Claude's file-editing tools and Codex's
// apply_patch (and its Edit/Write hooks matcher).
var markdownWriters = map[string]bool{
	"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true, "apply_patch": true,
}

// decode implements Decode.
func decode(host Host, label string, ev Event, raw []byte, env paths.Env, procs platform.ProcTable) (Payload, error) {
	p := Payload{Host: host, Label: label, Event: ev}
	if len(raw) > MaxPayload {
		return p, errTooLarge
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return p, errMalformed
	}
	var w wirePayload
	if err := json.Unmarshal(trimmed, &w); err != nil {
		return p, errMalformed
	}

	p.SID = firstString(w.SessionID, w.ConversationID, w.SessionIDCamel)
	p.PromptID = str(w.PromptID)
	p.TurnID = str(w.TurnID)
	p.TranscriptPath = absPath(str(w.TranscriptPath))
	p.Cwd = absPath(str(w.Cwd))
	if p.Cwd == "" && len(w.WorkspaceRoots) > 0 {
		p.Cwd = absPath(w.WorkspaceRoots[0])
	}
	p.ScratchpadDir = absPath(str(w.ScratchpadDir))
	p.Source = str(w.Source)
	p.Reason = str(w.Reason)
	p.Trigger = str(w.Trigger)
	p.ToolName = firstString(w.ToolName, w.ToolNameCamel)
	p.Notification = str(w.NotificationType)
	p.OldCwd = absPath(str(w.OldCwd))
	p.NewCwd = absPath(str(w.NewCwd))
	p.AgentID = str(w.AgentID)
	if d := absPath(str(w.Directory)); d != "" {
		p.AddedDirs = append(p.AddedDirs, d)
	}
	if host == HostCursor {
		for _, r := range w.WorkspaceRoots {
			if d := absPath(r); d != "" {
				p.AddedDirs = appendUnique(p.AddedDirs, d)
			}
		}
	}

	// Tool paths: only the path keys of tool_input (or Copilot's toolArgs),
	// Cursor's top-level file_path, and apply_patch header paths.
	var toolPaths []string
	toolPaths = append(toolPaths, objectPaths(w.ToolInput, p.Cwd)...)
	toolPaths = append(toolPaths, objectPaths(unquoteJSON(w.ToolArgs), p.Cwd)...)
	if f := resolve(str(w.FilePath), p.Cwd); f != "" {
		toolPaths = append(toolPaths, f)
	}
	if p.ToolName == "apply_patch" {
		toolPaths = append(toolPaths, patchPaths(w.ToolInput, p.Cwd)...)
	}
	seen := make(map[string]bool, len(toolPaths))
	for _, tp := range toolPaths {
		if len(p.Paths) >= maxPaths {
			break
		}
		if !seen[tp] {
			seen[tp] = true
			p.Paths = append(p.Paths, tp)
		}
	}
	if markdownWriters[p.ToolName] || (host == HostCursor && w.FilePath != nil && ev == PostToolUse) {
		for _, tp := range p.Paths {
			if isMarkdown(tp) {
				p.MarkdownPaths = append(p.MarkdownPaths, tp)
			}
		}
	}

	// Environment facts.
	if host != HostCodex {
		p.ProjectDir = absPath(env.Get(paths.EnvClaudeProjectDir))
		if p.ProjectDir == "" && host == HostDroid {
			p.ProjectDir = absPath(env.Get(envFactoryProject))
		}
	}
	p.Entrypoint = env.Get(envClaudeEntrypoint)
	switch host {
	case HostCodex:
		p.CodexHome = absPath(env.Get(paths.EnvCodexHome))
		p.ConfigDir = codexHomeOf(p.CodexHome, p.TranscriptPath, env)
		p.HarnessVersion = env.Get(envCodexVersion)
		if proc, ok := codexAncestor(procs); ok {
			p.HarnessPID, p.HarnessProc = proc.ID.PID, proc.ID
		}
	default:
		p.ConfigDir = claudeConfigOf(p.TranscriptPath, env)
		if host == HostClaude {
			p.HarnessVersion = claudeVersion(env, p.ConfigDir)
		}
		p.HarnessPID, p.HarnessProc = claudeProcess(env, procs)
	}
	return p, nil
}

// maxRegistryEntry bounds the registry entry read for the version (Claude
// writes a few hundred bytes).
const maxRegistryEntry = 64 << 10

// maxVersionLen bounds a version string ("2.1.329").
const maxVersionLen = 32

// claudeVersion returns the Claude Code version (D103): the `version` key of
// the live-session registry entry <config>/sessions/<CLAUDE_PID>.json, which
// Claude writes for its own process before SessionStart and removes before
// SessionEnd; else the basename of CLAUDE_CODE_EXECPATH, which Claude
// 2.1.329 sets only for its Bash-tool processes, never for hooks
// (HOOKS-IO §2.3). Informational only (ledger, registration, status).
func claudeVersion(env paths.Env, configDir string) string {
	if v := registryVersion(env, configDir); v != "" {
		return v
	}
	return versionOf(env.Get(envClaudeExecPath))
}

// registryVersion reads the version of Claude's registry entry for
// CLAUDE_PID: a regular file (never through a symlink, never blocking on a
// FIFO) whose pid, when present, is that pid.
func registryVersion(env paths.Env, configDir string) string {
	pid, err := strconv.Atoi(env.Get(paths.EnvClaudePID))
	if err != nil || pid <= 1 || configDir == "" || !filepath.IsAbs(configDir) {
		return ""
	}
	path := filepath.Join(configDir, "sessions", strconv.Itoa(pid)+".json")
	f, err := os.OpenFile(path, os.O_RDONLY|fsx.ONoFollow|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil || !st.IsRegular() {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRegistryEntry+1))
	if err != nil || len(data) > maxRegistryEntry {
		return ""
	}
	var entry struct {
		PID     *json.Number `json:"pid"`
		Version *string      `json:"version"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if dec.Decode(&entry) != nil || entry.Version == nil {
		return ""
	}
	if entry.PID != nil {
		if n, err := entry.PID.Int64(); err != nil || n != int64(pid) {
			return "" // another process's entry
		}
	}
	if len(*entry.Version) > maxVersionLen {
		return ""
	}
	return versionString(*entry.Version)
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func firstString(ss ...*string) string {
	for _, s := range ss {
		if v := str(s); v != "" {
			return v
		}
	}
	return ""
}

// absPath returns the cleaned p when it is absolute, else "".
func absPath(p string) string {
	if p == "" || !filepath.IsAbs(p) || strings.ContainsRune(p, 0) {
		return ""
	}
	return filepath.Clean(p)
}

// resolve returns p made absolute against cwd (relative tool paths), or "".
func resolve(p, cwd string) string {
	if p == "" || strings.ContainsRune(p, 0) {
		return ""
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	if cwd == "" {
		return ""
	}
	return filepath.Join(cwd, p)
}

func appendUnique(list []string, s string) []string {
	for _, have := range list {
		if have == s {
			return list
		}
	}
	return append(list, s)
}

// objectPaths reads the path keys of a JSON object (string values only);
// anything that is not an object yields nothing.
func objectPaths(raw json.RawMessage, cwd string) []string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	var out []string
	for _, k := range toolPathKeys {
		v, ok := obj[k]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(v, &s) != nil {
			continue
		}
		if p := resolve(s, cwd); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// unquoteJSON returns the JSON document held in a JSON string (Copilot's
// toolArgs), or raw itself when it is not a string.
func unquoteJSON(raw json.RawMessage) json.RawMessage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return raw
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return nil
	}
	return json.RawMessage(s)
}

// patchPaths returns the "*** Add File:", "*** Update File:" and
// "*** Move to:" paths of an apply_patch tool_input ({"command": patch}),
// resolved against cwd. The patch text itself is dropped at once.
func patchPaths(raw json.RawMessage, cwd string) (out []string) {
	var in struct {
		Command *string `json:"command"`
	}
	if json.Unmarshal(bytes.TrimSpace(raw), &in) != nil || in.Command == nil {
		return nil
	}
	defer func() {
		// A failing extractor must not lose the decision: its paths are
		// only taint facts, the cwd still decides managed-ness.
		if recover() != nil {
			out = nil
		}
	}()
	for _, p := range applyPatchPaths([]byte(*in.Command), cwd) {
		if a := resolve(p, cwd); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// isMarkdown reports whether p has a Markdown extension (SPEC §8.1).
func isMarkdown(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".md", ".mdx", ".markdown":
		return true
	}
	return false
}

// claudeConfigOf derives $CC (SPEC §7.0): from the transcript path
// <CC>/projects/<P>/<sid>.jsonl, else CLAUDE_CONFIG_DIR, else ~/.claude.
func claudeConfigOf(transcript string, env paths.Env) string {
	if transcript != "" {
		projects := filepath.Dir(filepath.Dir(transcript))
		if filepath.Base(projects) == "projects" {
			return filepath.Dir(projects)
		}
	}
	if d := absPath(env.Get(paths.EnvClaudeConfigDir)); d != "" {
		return d
	}
	if home, err := paths.UserHome(env); err == nil {
		return filepath.Join(home, ".claude")
	}
	return ""
}

// codexHomeOf derives the Codex home: CODEX_HOME, else the rollout path
// <home>/sessions/YYYY/MM/DD/rollout-….jsonl, else ~/.codex.
func codexHomeOf(codexHome, transcript string, env paths.Env) string {
	if codexHome != "" {
		return codexHome
	}
	if transcript != "" {
		sessions := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(transcript))))
		if filepath.Base(sessions) == "sessions" {
			return filepath.Dir(sessions)
		}
	}
	if home, err := paths.UserHome(env); err == nil {
		return filepath.Join(home, ".codex")
	}
	return ""
}

// versionOf returns the Claude version from CLAUDE_CODE_EXECPATH, whose
// basename is the version for the native installer (HOOKS-IO §2.3).
func versionOf(execPath string) string {
	if execPath == "" {
		return ""
	}
	return versionString(filepath.Base(execPath))
}

// versionString returns v when it is a dotted version of digits ("2.1.329"),
// else "".
func versionString(v string) string {
	if v == "" || !strings.ContainsRune(v, '.') {
		return ""
	}
	for _, c := range v {
		if (c < '0' || c > '9') && c != '.' {
			return ""
		}
	}
	return v
}

// shells are the programs between a harness and the hook binary (the
// harness's `sh -c`, the shim, its command substitution, Codex's login
// shell): never the harness itself.
var shells = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true,
	"fish": true, "ash": true, "busybox": true, "yash": true, "env": true,
}

// claudeProcess returns the Claude process: CLAUDE_PID when set (it is
// missing on some events, HOOKS-IO §0.7), else the nearest ancestor that is
// not a shell, else the parent. The ProcID is measured by precinto; the
// daemon measures it again and verifies the executable (SPEC §9.1).
func claudeProcess(env paths.Env, procs platform.ProcTable) (int, platform.ProcID) {
	if pid, err := strconv.Atoi(env.Get(paths.EnvClaudePID)); err == nil && pid > 1 {
		if procs != nil {
			if info, err := procs.Lookup(pid); err == nil {
				return pid, info.ID
			}
		}
		return pid, platform.ProcID{}
	}
	if procs != nil {
		if anc, err := platform.Ancestors(procs, selfPID(), maxAncestors); err == nil {
			for _, a := range anc {
				if a.Exe != "" && !shells[filepath.Base(a.Exe)] {
					return a.ID.PID, a.ID
				}
			}
		}
	}
	if ppid := parentPID(); ppid > 1 {
		return ppid, platform.ProcID{}
	}
	return 0, platform.ProcID{}
}

// codexAncestor returns the nearest ancestor whose executable basename is
// codex (Codex sets no pid variable, HA17).
func codexAncestor(procs platform.ProcTable) (platform.ProcInfo, bool) {
	if procs == nil {
		return platform.ProcInfo{}, false
	}
	anc, err := platform.Ancestors(procs, selfPID(), maxAncestors)
	if err != nil {
		return platform.ProcInfo{}, false
	}
	for _, a := range anc {
		if a.Exe != "" && filepath.Base(a.Exe) == "codex" {
			return a, true
		}
	}
	return platform.ProcInfo{}, false
}

// appServer reports whether the Codex process is `codex app-server`, whose
// home is then held by a daemon (HOOKS-IO §3.3).
func appServer(info platform.ProcInfo) bool {
	for _, a := range info.Argv {
		if a == "app-server" {
			return true
		}
	}
	return false
}
