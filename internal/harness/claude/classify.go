package claude

import (
	"strings"

	"github.com/precinto/precinto/internal/capsule"
)

// sidSearchDepth is how deep below $CC (and $TMP) sid-named entries are
// looked for (SPEC §7.1.1). Once a component carries a sid, its whole
// subtree belongs to that session at any depth.
const sidSearchDepth = 4

// Store names of the global-store units (D36).
const (
	storeUsage    = "usage-data"
	storeFeedback = "feedback/drafts"
)

// deniedTop are $CC entries that are never sealed (SPEC §7.1.1 deny-list):
// configuration, extensions and the live-session registry.
var deniedTop = []string{"plugins", "skills", "commands", "agents", "sessions", "ide", "shell-snapshots"}

// skippedTop are $CC entries that hold no session data and are not walked:
// Claude's own installation, and the stores other units or the history
// rotation own (claudeUnitOf handles projects/, plans/, jobs/ and the
// global stores).
var skippedTop = []string{"local"}

// denied reports whether a top-level $CC entry is on the deny-list.
func denied(name string) bool {
	for _, d := range deniedTop {
		if sameName(name, d) {
			return true
		}
	}
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "settings") && strings.HasSuffix(lower, ".json"):
		return true
	case lower == "keybindings.json", lower == "claude.md":
		return true
	case strings.Contains(lower, "credentials"):
		return true
	case strings.HasPrefix(lower, ".precinto-"):
		return true // the history rotation's hold link (SPEC §7.1.4)
	}
	return false
}

func skipped(name string) bool {
	for _, d := range skippedTop {
		if sameName(name, d) {
			return true
		}
	}
	return false
}

// configUnit says which unit a $CC-relative path belongs to. It is the one
// membership rule shared by the inventory (Scan) and the restore targets
// (Targets), so everything sealed can be restored and nothing else can be
// written (SPEC §7.1, §11.2). Plans are resolved by slug elsewhere (the
// slug list comes from transcripts); jobs/<id>/** belongs to the session
// its state names.
type configUnit struct {
	kind capsule.Kind
	id   string // sid, project directory name, store name
	// subtree is the base-relative root of the session subtree the path
	// lies in ("" for a single sid-named file).
	subtree string
}

// configUnitOf classifies parts (a cleaned $CC-relative path). ok=false
// means the path belongs to no unit (deny-listed, unknown, history,
// plans, jobs or too deep to carry a sid).
func configUnitOf(parts []string) (configUnit, bool) {
	if len(parts) == 0 {
		return configUnit{}, false
	}
	top := parts[0]
	switch {
	case denied(top), skipped(top):
		return configUnit{}, false
	case sameName(top, "projects"):
		if len(parts) < 3 {
			return configUnit{}, false
		}
		p, e := parts[1], parts[2]
		if sid, ok := sidOf(e); ok {
			sub := ""
			if len(parts) > 3 {
				sub = strings.Join(parts[:3], "/")
			}
			return configUnit{kind: capsule.KindClaudeSession, id: sid, subtree: sub}, true
		}
		if sameName(e, "memory") {
			return configUnit{kind: capsule.KindClaudeProject, id: p}, true
		}
		if len(parts) == 3 {
			// Other non-session files directly in projects/<P>/ (legacy
			// sessions-index.json and the like) belong to the project.
			return configUnit{kind: capsule.KindClaudeProject, id: p}, true
		}
		return configUnit{}, false
	case sameName(top, "plans"), sameName(top, "jobs"), sameName(top, "history.jsonl"), sameName(top, "paste-cache"):
		return configUnit{}, false
	case sameName(top, storeUsage):
		return configUnit{kind: capsule.KindGlobalStore, id: storeUsage}, true
	case sameName(top, "feedback") && len(parts) >= 2 && sameName(parts[1], "drafts"):
		return configUnit{kind: capsule.KindGlobalStore, id: storeFeedback}, true
	}
	for i, c := range parts {
		if i >= sidSearchDepth {
			break
		}
		if sid, ok := sidOf(c); ok {
			sub := ""
			if i < len(parts)-1 {
				sub = strings.Join(parts[:i+1], "/")
			}
			return configUnit{kind: capsule.KindClaudeSession, id: sid, subtree: sub}, true
		}
	}
	return configUnit{}, false
}

// tmpSessionOf classifies a $TMP-relative path: <P>/…/<sid-named>/… with
// the sid-named component at depth 2 to sidSearchDepth. It returns the sid
// and the project directory name.
func tmpSessionOf(parts []string) (sid, project string, ok bool) {
	if len(parts) < 2 {
		return "", "", false
	}
	for i := 1; i < len(parts) && i < sidSearchDepth; i++ {
		if s, ok := sidOf(parts[i]); ok {
			return s, parts[0], true
		}
	}
	return "", "", false
}

// isTranscript reports whether a session file is a JSONL transcript that
// Claude appends to: projects/<P>/<sid>.jsonl or a subagent transcript
// below projects/<P>/<sid>/subagents/ (placement jsonl-append, SPEC §7.1.1).
func isTranscript(parts []string, sid string) (main, sub bool) {
	if len(parts) < 3 || !sameName(parts[0], "projects") {
		return false, false
	}
	if len(parts) == 3 && sameName(parts[2], sid+".jsonl") {
		return true, false
	}
	if len(parts) >= 5 && sameName(parts[2], sid) && sameName(parts[3], "subagents") && strings.HasSuffix(strings.ToLower(parts[len(parts)-1]), ".jsonl") {
		return false, true
	}
	return false, false
}
