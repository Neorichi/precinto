package codex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/paths"
)

const (
	// maxConfigBytes bounds config.toml and auth.json reads.
	maxConfigBytes = 4 << 20
	configName     = "config.toml"
	authName       = "auth.json"
	// sourceHooksFile is where precinto's Codex plugin declares its hooks;
	// Codex keys plugin hook trust as "<plugin id>:<file>:<event>:<g>:<h>".
	sourceHooksFile = "hooks/codex.json"
	pluginName      = "precinto"
)

// precintoEvents are the event labels of plugins/codex/hooks/codex.json
// (HOOKS-IO §3.2) as Codex 0.154 writes them in trust keys.
var precintoEvents = []string{
	"session_start", "user_prompt_submit", "pre_tool_use", "permission_request", "post_tool_use",
	"pre_compact", "post_compact", "stop", "interrupt", "session_end",
}

// strippedKeys are the root-level config.toml keys a per-root home must
// not inherit: they would move databases or logs out of the sealed home
// (D44).
var strippedKeys = map[string]bool{"sqlite_home": true, "log_dir": true}

// errUnsafeHome: a per-root home path is not a private directory.
var errUnsafeHome = errors.New("codex: per-root home is not a private directory")

func readFileBounded(path string) ([]byte, fsx.Stat, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fsx.Stat{}, err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return nil, fsx.Stat{}, err
	}
	if !st.IsRegular() {
		return nil, st, fmt.Errorf("%w: %s is not a regular file", fsx.ErrUnsafe, filepath.Base(path))
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, st, err
	}
	if len(data) > maxConfigBytes {
		return nil, st, fmt.Errorf("codex: %s is larger than %d bytes", filepath.Base(path), maxConfigBytes)
	}
	return data, st, nil
}

// ensureHome creates dir (and missing parents) with mode 0700, or checks
// an existing one: a directory, not a symlink, owned by the current user;
// group/other permissions are removed (strengthening only).
func ensureHome(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: %q is not absolute", errUnsafeHome, dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := fsx.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || int(st.UID) != os.Getuid() {
		return fmt.Errorf("%w: %s", errUnsafeHome, dir)
	}
	if st.Mode&0o077 != 0 {
		return os.Chmod(dir, 0o700)
	}
	return nil
}

// prepareHome implements PrepareHome (D31, D44).
func prepareHome(ctx context.Context, s Seed) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(s.RootHome) {
		return fmt.Errorf("%w: %q is not absolute", errUnsafeHome, s.RootHome)
	}
	home := filepath.Clean(s.RootHome)
	if err := ensureHome(home); err != nil {
		return err
	}
	// TMPDIR of managed launches lives in the sealed home (D44).
	if err := ensureHome(filepath.Join(home, tmpDirName)); err != nil {
		return err
	}
	if s.UserHome == "" {
		return nil // no user home to seed from: Codex starts fresh
	}
	if !filepath.IsAbs(s.UserHome) {
		return fmt.Errorf("codex: user home %q is not absolute", s.UserHome)
	}
	user := filepath.Clean(s.UserHome)
	if user == home {
		return fmt.Errorf("codex: the per-root home cannot seed from itself")
	}
	if err := seedConfig(home, user, s.ForceConfig); err != nil {
		return err
	}
	if err := copyAuthIfNewer(filepath.Join(user, authName), filepath.Join(home, authName)); err != nil {
		return err
	}
	for _, name := range []string{"plugins", "skills"} {
		if err := linkShared(filepath.Join(home, name), filepath.Join(user, name)); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// seedConfig copies the user's config.toml into the per-root home once
// (or again with force), without sqlite_home and log_dir. With force the
// per-root home's hook trust entries are kept (they win over the user's
// entries for the same hooks). A config that cannot be parsed is never
// copied: the seed fails instead.
func seedConfig(home, user string, force bool) error {
	dst := filepath.Join(home, configName)
	existing, _, err := readFileBounded(dst)
	switch {
	case err == nil && !force:
		return nil // seeded once already
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	}
	src, _, err := readFileBounded(filepath.Join(user, configName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil // nothing to seed from; keep what the home has
	}
	if err != nil {
		return err
	}
	out, err := strippedConfig(string(src))
	if err != nil {
		return err
	}
	if force && existing != nil {
		if out, err = keepTrust(out, string(existing)); err != nil {
			return err
		}
	}
	if existing != nil && bytes.Equal(existing, []byte(out)) {
		return nil
	}
	return fsx.WriteFileAtomic(dst, []byte(out), 0o600)
}

// strippedConfig removes the root-level keys of strippedKeys.
func strippedConfig(src string) (string, error) {
	doc, err := parseTOML(src)
	if err != nil {
		return "", err
	}
	drop := map[int]bool{}
	for i, st := range doc.stmts {
		if st.kind != stmtKeyVal {
			break // the root table ends at the first header
		}
		if len(st.key) == 1 && strippedKeys[st.key[0]] {
			drop[i] = true
		}
	}
	out := doc.without(drop)
	if _, err := parseTOML(out); err != nil {
		return "", err
	}
	return out, nil
}

// keepTrust carries the hook trust entries of the per-root home's current
// config (old) into the new config text: entries of the new config for
// the same hooks are dropped, then old's entries are appended as
// [hooks.state."…"] tables.
func keepTrust(newText, oldText string) (string, error) {
	oldDoc, err := parseTOML(oldText)
	if err != nil {
		// The per-root config is unreadable: nothing can be kept, and the
		// re-seed must not silently drop trust. Fail closed.
		return "", err
	}
	keep := oldDoc.hookStates()
	if len(keep) == 0 {
		return newText, nil
	}
	newDoc, err := parseTOML(newText)
	if err != nil {
		return "", err
	}
	if newDoc.inlineHooks() {
		return "", fmt.Errorf("%w: hooks is an inline table; hook trust cannot be kept", errTOML)
	}
	drop := map[int]bool{}
	for k, hs := range newDoc.hookStates() {
		if _, ok := keep[k]; !ok {
			continue
		}
		if hs.inline {
			return "", fmt.Errorf("%w: a hook trust entry is part of an inline table", errTOML)
		}
		for _, i := range hs.stmts {
			drop[i] = true
		}
	}
	out := newDoc.without(drop)
	keys := make([]string, 0, len(keep))
	for k := range keep {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(out)
	if out != "" && !strings.HasSuffix(out, "\n") {
		b.WriteByte('\n')
	}
	for _, k := range keys {
		hs := keep[k]
		if hs.trustedHash == "" && hs.enabled == nil {
			continue
		}
		fmt.Fprintf(&b, "\n[hooks.state.%s]\n", tomlQuote(k))
		if hs.trustedHash != "" {
			fmt.Fprintf(&b, "trusted_hash = %s\n", tomlQuote(hs.trustedHash))
		}
		if hs.enabled != nil {
			fmt.Fprintf(&b, "enabled = %t\n", *hs.enabled)
		}
	}
	result := b.String()
	if _, err := parseTOML(result); err != nil {
		return "", err
	}
	return result, nil
}

// copyAuthIfNewer copies src over dst atomically (0600) when src is newer
// than dst or dst is missing, and keeps src's mtime on the copy so the next
// comparison sees them equal. It never removes either file.
func copyAuthIfNewer(src, dst string) error {
	data, sst, err := readFileBounded(src)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	cur, dst0, err := readFileBounded(dst)
	switch {
	case err == nil:
		if sst.MtimeNS <= dst0.MtimeNS || bytes.Equal(cur, data) {
			return nil
		}
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	if err := fsx.WriteFileAtomic(dst, data, 0o600); err != nil {
		return err
	}
	mt := time.Unix(0, sst.MtimeNS)
	return os.Chtimes(dst, mt, mt)
}

// linkShared makes link a symlink to target (plugins/ and skills/ are
// shared with the user's home, D31). It never removes a real file or
// directory: an existing non-link entry is left as it is.
func linkShared(link, target string) error {
	if st, err := fsx.Lstat(target); err != nil || !st.IsDir() {
		return nil // the user has none: Codex creates its own
	}
	st, err := fsx.Lstat(link)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return os.Symlink(target, link)
	case err != nil:
		return err
	case st.Mode&0o170000 != 0o120000:
		return nil // a real entry: never replaced
	}
	if cur, err := os.Readlink(link); err == nil && cur == target {
		return nil
	}
	tmp := link + ".precinto-link"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, link); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// syncAuthBack implements SyncAuthBack: a refreshed token in the per-root
// home goes back to the user's home (only if that home exists).
func syncAuthBack(ctx context.Context, s Seed) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(s.RootHome) || !filepath.IsAbs(s.UserHome) {
		return fmt.Errorf("codex: homes must be absolute")
	}
	user := filepath.Clean(s.UserHome)
	if st, err := fsx.Lstat(user); err != nil || !st.IsDir() {
		return nil
	}
	return copyAuthIfNewer(filepath.Join(filepath.Clean(s.RootHome), authName), filepath.Join(user, authName))
}

// launchEnv implements LaunchEnv.
func launchEnv(rootHome string) []string {
	home := filepath.Clean(rootHome)
	return []string{
		paths.EnvCodexHome + "=" + home,
		paths.EnvCodexSQLiteHome + "=" + home,
		"TMPDIR=" + filepath.Join(home, tmpDirName),
	}
}

// userHome implements UserHome: CODEX_HOME (absolute) or ~/.codex.
func userHome(e paths.Env) (string, error) {
	if v, ok := e.Lookup(paths.EnvCodexHome); ok && v != "" {
		if !filepath.IsAbs(v) {
			return "", fmt.Errorf("codex: CODEX_HOME %q is not absolute", v)
		}
		return resolve(v), nil
	}
	h, err := paths.UserHome(e)
	if err != nil {
		return "", err
	}
	return resolve(filepath.Join(h, ".codex")), nil
}

// resolve returns the realpath of an existing path (Codex canonicalizes
// CODEX_HOME), else the cleaned path.
func resolve(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// hooksTrusted implements HooksTrusted: every hook of precinto's Codex
// plugin has a trusted_hash entry and is not disabled. known is false when
// the config cannot be read or parsed (then trusted is false too).
func hooksTrusted(home string) (trusted, known bool, err error) {
	if !filepath.IsAbs(home) {
		return false, false, fmt.Errorf("codex: home %q is not absolute", home)
	}
	data, _, err := readFileBounded(filepath.Join(filepath.Clean(home), configName))
	if errors.Is(err, fs.ErrNotExist) {
		return false, true, nil // no config: no trust entries
	}
	if err != nil {
		return false, false, err
	}
	doc, perr := parseTOML(string(data))
	if perr != nil {
		return false, false, nil
	}
	seen := map[string]bool{}
	for k, hs := range doc.hookStates() {
		label, ok := precintoHookLabel(k)
		if !ok || hs.trustedHash == "" || (hs.enabled != nil && !*hs.enabled) {
			continue
		}
		seen[label] = true
	}
	for _, ev := range precintoEvents {
		if !seen[ev] {
			return false, true, nil
		}
	}
	return true, true, nil
}

// precintoHookLabel parses a trust key "<plugin id>:hooks/codex.json:
// <event>:<group>:<handler>" of precinto's plugin (id "precinto@<market>").
func precintoHookLabel(key string) (string, bool) {
	parts := strings.Split(key, ":")
	if len(parts) != 5 {
		return "", false
	}
	id, file, label := parts[0], parts[1], parts[2]
	name, _, _ := strings.Cut(id, "@")
	if name != pluginName || file != sourceHooksFile || !isIndex(parts[3]) || !isIndex(parts[4]) {
		return "", false
	}
	return label, true
}

func isIndex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
