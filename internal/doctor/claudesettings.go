package doctor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/precinto/precinto/internal/harness"
)

// settingsFile is what the checks read from one Claude settings file: key
// names of "env" (never their values), disableAllHooks, enabledPlugins and
// the top-level values protect --claude-settings writes.
type settingsFile struct {
	path            string
	err             error // the file exists but could not be read or parsed
	env             []string
	disableAllHooks bool
	plugins         map[string]bool // enabledPlugins id → enabled
	top             map[string]json.RawMessage
}

// settingsAt returns the parsed settings file at path, or nil when there
// is none. Each file is read once per Run.
func (e *env) settingsAt(path string) *settingsFile {
	if s, ok := e.settings[path]; ok {
		return s
	}
	s := parseSettings(path)
	e.settings[path] = s
	return s
}

func parseSettings(path string) *settingsFile {
	b, err := readRegular(path, maxSettingsBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	s := &settingsFile{path: path}
	if err != nil {
		s.err = err
		return s
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return s // Claude treats an empty file as no settings
	}
	if err := json.Unmarshal(b, &s.top); err != nil {
		s.err = errInvalidJSON
		s.top = nil
		return s
	}
	if raw, ok := s.top["env"]; ok && !isJSONNull(raw) {
		var env map[string]json.RawMessage
		if err := json.Unmarshal(raw, &env); err != nil {
			s.err = errInvalidJSON
			return s
		}
		for k := range env {
			s.env = append(s.env, k)
		}
		sort.Strings(s.env)
	}
	if raw, ok := s.top["disableAllHooks"]; ok {
		s.disableAllHooks = bytes.Equal(bytes.TrimSpace(raw), []byte("true"))
	}
	if raw, ok := s.top["enabledPlugins"]; ok && !isJSONNull(raw) {
		var ps map[string]json.RawMessage
		if err := json.Unmarshal(raw, &ps); err == nil {
			s.plugins = map[string]bool{}
			for id, v := range ps {
				s.plugins[id] = bytes.Equal(bytes.TrimSpace(v), []byte("true"))
			}
		}
	}
	return s
}

var errInvalidJSON = errors.New("doctor: invalid JSON")

func isJSONNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// isPrecintoPlugin reports whether a plugin id (name@marketplace) is
// precinto's Claude plugin (SPEC §21: plugin name "precinto").
func isPrecintoPlugin(id string) bool {
	name, _, _ := strings.Cut(id, "@")
	return name == "precinto"
}

// claudeConfigDirs returns the Claude config dirs to inspect: every
// registered home (config) and the default of this environment
// (CLAUDE_CONFIG_DIR or ~/.claude), existing ones only, without duplicates.
func (e *env) claudeConfigDirs() []string {
	if e.claudeDirsDone {
		return e.claudeDirs
	}
	e.claudeDirsDone = true
	e.claudeDirs = e.findClaudeConfigDirs()
	return e.claudeDirs
}

func (e *env) findClaudeConfigDirs() []string {
	var cands []string
	for _, h := range e.o.Cfg.Harness[string(harness.ClaudeCode)].Homes {
		cands = append(cands, h.Dir)
	}
	if d := e.o.Env.Get("CLAUDE_CONFIG_DIR"); filepath.IsAbs(d) {
		cands = append(cands, filepath.Clean(d))
	} else if e.home != "" {
		cands = append(cands, filepath.Join(e.home, ".claude"))
	}
	var out []string
	seen := map[string]bool{}
	for _, c := range cands {
		if c == "" || !filepath.IsAbs(c) {
			continue
		}
		c = filepath.Clean(c)
		key := c
		if r, err := filepath.EvalSymlinks(c); err == nil {
			key = r
		}
		if seen[key] || !isDir(c) {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

// userSettingsFiles are the user-level settings files of every config dir.
func (e *env) userSettingsFiles() []string {
	var out []string
	for _, d := range e.claudeConfigDirs() {
		out = append(out, filepath.Join(d, "settings.json"), filepath.Join(d, "settings.local.json"))
	}
	return out
}

// rootSettingsFiles returns <root>/.claude/settings*.json of a root.
func rootSettingsFiles(root string) []string {
	dir := filepath.Join(root, ".claude")
	es, err := listDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, en := range es {
		n := en.Name()
		if strings.HasPrefix(n, "settings") && strings.HasSuffix(n, ".json") && !en.IsDir() {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out
}

// flaggedEnvKeys returns the keys of a settings "env" that reach every hook
// process and change where the shim and the hook look for precinto (D56):
// PRECINTO_*, HOME, XDG_*, PATH, DYLD_* and LD_*.
func flaggedEnvKeys(keys []string) []string {
	var out []string
	for _, k := range keys {
		switch {
		case k == "HOME", k == "PATH",
			strings.HasPrefix(k, "PRECINTO_"), strings.HasPrefix(k, "XDG_"),
			strings.HasPrefix(k, "DYLD_"), strings.HasPrefix(k, "LD_"):
			out = append(out, k)
		}
	}
	return out
}
