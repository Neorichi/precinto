package codex

import (
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// neverTouch is the deny-list of a per-root home (SPEC §7.2, HA24),
// mirrored by inventories/codex.toml (a test keeps them identical):
// everything else is content, so a file a newer Codex adds is sealed
// (fail closed).
var neverTouch = []string{
	"auth.json", "config.toml", "hooks.json", "plugins/**", "skills/**", "cache/**",
	"packages/**", "models_cache.json", "installation_id", "version.json",
	".tmp/**", "tmp/**", "thread-writer-locks/**", "app-server-control/**", "log/**",
	"rollout-maintenance.lock", "*-shm",
	// precinto's own record of the auth.json last synchronized (D100).
	".precinto-auth",
}

// SQLite file suffixes (opaque groups: no SQLite driver is linked).
const (
	sqliteExt  = ".sqlite"
	walSuffix  = "-wal"
	jrnSuffix  = "-journal"
	shmSuffix  = "-shm"
	tmpDirName = "precinto-tmp"
)

// lineUnionFiles are the JSONL indexes restored by adding missing lines.
var lineUnionFiles = []string{"history.jsonl", "session_index.jsonl"}

// foldCase makes matching case-insensitive on darwin, where the default
// APFS volume treats "Auth.json" and "auth.json" as one file: a case
// variant of a never-touch name must never be sealed.
func foldCase(s string) string {
	if runtime.GOOS == "darwin" {
		return strings.ToLower(s)
	}
	return s
}

// matchGlob matches a '/'-separated relative path against a glob whose
// components are path.Match patterns; "**" matches any number of
// components (also none), so "plugins/**" matches "plugins" itself.
func matchGlob(pattern, rel string) bool {
	return matchParts(strings.Split(foldCase(pattern), "/"), strings.Split(foldCase(rel), "/"))
}

func matchParts(pat, parts []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			if len(pat) == 1 {
				return true
			}
			for i := 0; i <= len(parts); i++ {
				if matchParts(pat[1:], parts[i:]) {
					return true
				}
			}
			return false
		}
		if len(parts) == 0 {
			return false
		}
		ok, err := path.Match(pat[0], parts[0])
		if err != nil || !ok {
			return false
		}
		pat, parts = pat[1:], parts[1:]
	}
	return len(parts) == 0
}

// relParts validates a home-relative path: local, clean, '/'-separated.
func relParts(rel string) ([]string, bool) {
	if rel == "" || strings.Contains(rel, "\\") || strings.Contains(rel, "\x00") || !filepath.IsLocal(rel) || filepath.Clean(rel) != rel {
		return nil, false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, false
		}
	}
	return parts, true
}

// classify implements Classify. A path that is not local and clean is
// never-touch: nothing outside the content set is ever sealed or restored.
func classify(rel string) Class {
	parts, ok := relParts(rel)
	if !ok {
		return ClassNeverTouch
	}
	base := foldCase(parts[len(parts)-1])
	if strings.HasSuffix(base, shmSuffix) {
		return ClassSHM
	}
	for _, g := range neverTouch {
		// A directory pattern ("cache/**") also covers its own name.
		if matchGlob(g, rel) {
			return ClassNeverTouch
		}
	}
	switch {
	case strings.HasSuffix(base, sqliteExt):
		return ClassSQLiteMain
	case strings.HasSuffix(base, sqliteExt+walSuffix), strings.HasSuffix(base, sqliteExt+jrnSuffix):
		return ClassSQLiteSide
	}
	return ClassContent
}

// groupOf implements GroupOf: the home-relative path of the database a
// SQLite file belongs to (main, -wal, -journal and -shm share it).
func groupOf(rel string) string {
	if _, ok := relParts(rel); !ok {
		return ""
	}
	low := foldCase(rel)
	for _, suf := range []string{walSuffix, jrnSuffix, shmSuffix, ""} {
		if strings.HasSuffix(low, sqliteExt+suf) {
			return rel[:len(rel)-len(suf)]
		}
	}
	return ""
}

func lineUnion(rel string) bool {
	for _, f := range lineUnionFiles {
		if foldCase(rel) == f {
			return true
		}
	}
	return false
}
