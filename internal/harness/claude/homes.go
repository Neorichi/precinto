package claude

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/paths"
)

// home is a resolved Claude home plus whether config registers it (only
// registered homes are restore targets, SPEC §7.0).
type home struct {
	harness.Home
	registered bool
}

func (h home) configDir() string { return h.Bases[capsule.BaseClaudeConfig] }
func (h home) tmpDir() string    { return h.Bases[capsule.BaseClaudeTmp] }
func (h home) cacheDir() string  { return h.Bases[capsule.BaseClaudeCache] }

func newHome(dir, tmp, cache string, def, registered bool) home {
	bases := map[capsule.BaseID]string{capsule.BaseClaudeConfig: dir}
	if tmp != "" {
		bases[capsule.BaseClaudeTmp] = tmp
	}
	if cache != "" {
		bases[capsule.BaseClaudeCache] = cache
	}
	return home{Home: harness.Home{Harness: harness.ClaudeCode, ID: homeID(dir), Bases: bases, Default: def}, registered: registered}
}

// defaultTmp is Claude's tmp base for env (SPEC §7.0): CLAUDE_CODE_TMPDIR,
// else /private/tmp/claude-<uid> (darwin) or /tmp/claude-<uid>.
func defaultTmp(e paths.Env) string {
	if v := e.Get(paths.EnvClaudeTmpDir); filepath.IsAbs(v) {
		return realpath(v)
	}
	uid := strconv.Itoa(os.Getuid())
	if runtime.GOOS == "darwin" {
		return "/private/tmp/claude-" + uid
	}
	return "/tmp/claude-" + uid
}

// defaultCache is Claude's MCP-log cache base for env.
func defaultCache(e paths.Env) string {
	h, err := paths.UserHome(e)
	if runtime.GOOS == "darwin" {
		if err != nil {
			return ""
		}
		return realpath(filepath.Join(h, "Library", "Caches", "claude-cli-nodejs"))
	}
	if x := e.Get("XDG_CACHE_HOME"); filepath.IsAbs(x) {
		return realpath(filepath.Join(x, "claude-cli-nodejs"))
	}
	if err != nil {
		return ""
	}
	return realpath(filepath.Join(h, ".cache", "claude-cli-nodejs"))
}

// defaultConfigDir is $CC for env: CLAUDE_CONFIG_DIR, else ~/.claude.
func defaultConfigDir(e paths.Env) string {
	if v := e.Get(paths.EnvClaudeConfigDir); filepath.IsAbs(v) {
		return realpath(v)
	}
	h, err := paths.UserHome(e)
	if err != nil {
		return ""
	}
	return realpath(filepath.Join(h, ".claude"))
}

// homes resolves every Claude home: the registered ones of config, then
// config dirs the ledger saw (hooks run in the harness's own environment),
// then the default home of the invoking environment when it exists. Homes
// are deduplicated by their realpath'd config dir.
func homes(e harness.Env) []home {
	var out []home
	seen := map[string]bool{}
	addHome := func(h home) {
		dir := h.configDir()
		if dir == "" || !filepath.IsAbs(dir) || seen[dir] {
			return
		}
		seen[dir] = true
		out = append(out, h)
	}
	for _, h := range e.Cfg.Harness[string(harness.ClaudeCode)].Homes {
		addHome(registeredHome(h))
	}
	if e.Ledger != nil {
		if sessions, err := e.Ledger.List(string(harness.ClaudeCode)); err == nil {
			for _, s := range sessions {
				for i, d := range s.ConfigDirs {
					if !filepath.IsAbs(d) {
						continue
					}
					tmp := ""
					if i < len(s.TmpDirs) && filepath.IsAbs(s.TmpDirs[i]) {
						tmp = realpath(s.TmpDirs[i])
					} else if len(s.TmpDirs) > 0 && filepath.IsAbs(s.TmpDirs[0]) {
						tmp = realpath(s.TmpDirs[0])
					}
					if tmp == "" {
						tmp = defaultTmp(e.Host)
					}
					addHome(newHome(realpath(d), tmp, defaultCache(e.Host), false, false))
				}
			}
		}
	}
	if d := defaultConfigDir(e.Host); d != "" && isDir(d) {
		addHome(newHome(d, defaultTmp(e.Host), defaultCache(e.Host), true, false))
	}
	return out
}

// registeredHome turns a config [harness.claude-code].homes entry into a
// home. Registered paths were realpath'd at registration and are used as
// they are, so a home's id never changes.
func registeredHome(h config.Home) home {
	dir := filepath.Clean(h.Dir)
	tmp, cache := "", ""
	if filepath.IsAbs(h.Tmp) {
		tmp = filepath.Clean(h.Tmp)
	}
	if filepath.IsAbs(h.Cache) {
		cache = filepath.Clean(h.Cache)
	}
	return newHome(dir, tmp, cache, h.Default, true)
}

// registeredHomes returns only the homes config registers.
func registeredHomes(c config.Config) []home {
	var out []home
	for _, h := range c.Harness[string(harness.ClaudeCode)].Homes {
		if filepath.IsAbs(h.Dir) {
			out = append(out, registeredHome(h))
		}
	}
	return out
}

// Reasons a secondary base (Claude's $TMP or $CACHE) cannot receive
// restored files now (harness.TargetRules.Skip): short and content-free.
const (
	skipTmpUnsafe   = "unsafe tmp"   // not a directory owned by the user with mode 0700 (S7)
	skipTmpMissing  = "no tmp dir"   // absent (e.g. after a reboot): precinto never creates it
	skipCacheUnsafe = "unsafe cache" // not a real directory owned by the user
	skipCacheGone   = "no cache dir" // absent: precinto never creates it
)

// tmpUnsafe returns why the tmp base dir cannot receive restored files now,
// or "" when it can: it must be owned by the current user with no group or
// other permissions (SPEC §7.0, S7).
func tmpUnsafe(dir string) string {
	if dir == "" || !filepath.IsAbs(dir) {
		return skipTmpUnsafe
	}
	st, err := fsx.Lstat(dir)
	if notExist(err) {
		return skipTmpMissing
	}
	if err != nil || !st.IsDir() || int(st.UID) != os.Getuid() || st.Mode&0o077 != 0 {
		return skipTmpUnsafe
	}
	return ""
}

// cacheUnsafe returns why the cache base dir cannot receive restored files
// now (it must be a real directory owned by the user, like every base
// opened for placement, SPEC §11.4), or "" when it can.
func cacheUnsafe(dir string) string {
	if dir == "" || !filepath.IsAbs(dir) {
		return skipCacheUnsafe
	}
	st, err := fsx.Lstat(dir)
	if notExist(err) {
		return skipCacheGone
	}
	if err != nil || !st.IsDir() || int(st.UID) != os.Getuid() {
		return skipCacheUnsafe
	}
	return ""
}
