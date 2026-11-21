package doctor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/paths"
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
// precinto's Claude plugin: exactly paths.ClaudePluginID (SPEC §21, CC-37).
func isPrecintoPlugin(id string) bool { return id == paths.ClaudePluginID }

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

// settingsScanDepth is how many directory levels below a protected folder
// doctor looks for .claude/settings*.json: a session started in a
// subfolder reads that subfolder's project settings (SPEC §16.1).
const settingsScanDepth = 4

// settingsSkipDirs are never descended into while looking for settings.
var settingsSkipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true}

// rootSettingsFiles returns the .claude/settings*.json files of a root and
// of its subdirectories up to settingsScanDepth levels down, in walk order.
// The walk is fsx's: it never follows a symlinked directory (a linked
// .claude is read, as Claude reads it), skips .git, node_modules and vendor,
// and never lists a dataless cloud placeholder, which would download it
// (SPEC §17). Each root is walked once per Run.
func (e *env) rootSettingsFiles(root string) []string {
	if cached, ok := e.rootSettings[root]; ok {
		return cached
	}
	out := settingsFilesIn(filepath.Join(root, ".claude"))
	e.rootSettings[root] = out
	d, err := fsx.OpenBase(root)
	if err != nil {
		return out // missing, a symlink or not the user's: only the folder's own settings
	}
	defer d.Close()
	dirs := 0
	_ = d.Walk(".", func(we fsx.WalkEntry) error {
		if e.ctx.Err() != nil {
			return fs.SkipAll
		}
		depth := strings.Count(we.Rel, "/") + 1
		name := path.Base(we.Rel)
		isDir := we.Type == fsx.TypeDir
		switch {
		case name == ".claude":
			if depth > 1 && ((isDir && we.Hazard != fsx.HazardAccess) || we.Type == fsx.TypeSymlink) {
				out = append(out, settingsFilesIn(filepath.Join(root, filepath.FromSlash(we.Rel)))...)
			}
			if isDir {
				return fs.SkipDir
			}
			return nil // never SkipDir on a file: it would end the directory
		case !isDir || we.Hazard != fsx.HazardNone:
			return nil // files, links and hazards are never descended into
		case settingsSkipDirs[name], depth > settingsScanDepth:
			return fs.SkipDir
		}
		if dirs++; dirs > maxDirEntries {
			return fs.SkipAll
		}
		return nil
	})
	e.rootSettings[root] = out
	return out
}

// settingsFilesIn returns the settings*.json files of one .claude
// directory (a linked one is followed, as Claude follows it).
func settingsFilesIn(dir string) []string {
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
