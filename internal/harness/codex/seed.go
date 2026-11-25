package codex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
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

// strippedKeys are the root-level config.toml keys a per-root home must
// not inherit: they would move databases or logs out of the sealed home
// (D44).
var strippedKeys = map[string]bool{"sqlite_home": true, "log_dir": true}

// errUnsafeHome: a per-root home path is not a private directory.
var errUnsafeHome = errors.New("codex: per-root home is not a private directory")

func readFileBounded(path string) ([]byte, fsx.Stat, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|fsx.ONoFollow|syscall.O_NONBLOCK, 0)
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

// The WSL checks of D156, as variables so that tests stand in for WSL.
var (
	checkDrive   = paths.CheckDrive
	checkProgram = harness.CheckProgram
)

// checkHomes refuses, under WSL, a per-folder home or a user Codex home
// on a Windows drive, or one precinto cannot place (D156): Windows
// programs (a Windows Codex sharing CODEX_HOME) would write it unseen, and
// seeding would link its plugins and copy its auth.json across.
func checkHomes(homes ...string) error {
	for _, h := range homes {
		if !filepath.IsAbs(h) {
			continue // none, or refused below as not absolute
		}
		if err := checkDrive(h); err != nil {
			return err
		}
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
	if err := checkHomes(s.RootHome, s.UserHome); err != nil {
		return err
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
	// A user home that is not there now (an unmounted CODEX_HOME, a renamed
	// ~/.codex) says nothing about a logout: auth.json is synchronized only
	// with one that exists, as SyncAuthBack does.
	if isDir(user) {
		if err := syncAuth(filepath.Join(user, authName), filepath.Join(home, authName), filepath.Join(home, authRecordName), user, true); err != nil {
			return err
		}
	}
	for _, name := range []string{"plugins", "skills"} {
		if err := linkShared(home, filepath.Join(home, name), filepath.Join(user, name)); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// seedConfig writes the per-root home's config.toml as plannedConfig plans
// it, when that differs from what the home has.
func seedConfig(home, user string, force bool) error {
	existing, out, write, err := plannedConfig(home, user, force)
	if err != nil || !write || (existing != nil && bytes.Equal(existing, []byte(out))) {
		return err
	}
	return fsx.WriteFileAtomic(filepath.Join(home, configName), []byte(out), 0o600)
}

// plannedConfig returns the per-root home's config.toml (existing, nil when
// it has none) and the text PrepareHome leaves there (write reports that
// there is one to write). The user's config.toml is copied once — again
// with force — without sqlite_home and log_dir; with force the per-root
// home's hook trust entries are kept (they win over the user's entries for
// the same hooks). A config that cannot be parsed is never copied: the seed
// fails instead. Then, at every launch, the [marketplaces.<name>] and
// [plugins."<id>"] tables of the user's config that the per-root config
// lacks are added to it, in the form Codex writes them, so a plugin the
// user installs later (precinto integrate codex) is enabled in the folder's
// home too; values the per-root config has are never changed (D99). The
// merge is best effort: a user config that cannot be read or parsed, or a
// per-root config that defines plugins or marketplaces as one inline
// table, adds nothing and fails nothing.
func plannedConfig(home, user string, force bool) (existing []byte, out string, write bool, err error) {
	existing, _, err = readFileBounded(filepath.Join(home, configName))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, "", false, err
	}
	out, write = string(existing), existing != nil
	if user == "" {
		return existing, out, write, nil
	}
	src, _, serr := readFileBounded(filepath.Join(user, configName))
	seed := existing == nil || force
	switch {
	case errors.Is(serr, fs.ErrNotExist):
		return existing, out, write, nil // nothing to seed or merge from; keep what the home has
	case serr != nil:
		if seed {
			return existing, out, false, serr
		}
		return existing, out, write, nil
	}
	if seed {
		stripped, err := strippedConfig(string(src))
		if err != nil {
			return existing, out, false, err
		}
		if force && existing != nil {
			if stripped, err = keepTrust(stripped, string(existing)); err != nil {
				return existing, out, false, err
			}
		}
		out, write = stripped, true
	}
	if merged, ok := mergePluginTables(out, string(src)); ok {
		out, write = merged, true
	}
	return existing, out, write, nil
}

// pluginFamilies are the config.toml tables that make Codex load a plugin:
// the marketplace that provides it and the plugin entry that enables it.
var pluginFamilies = []string{"marketplaces", "plugins"}

// mergePluginTables appends to dst the [marketplaces.<name>] and
// [plugins."<id>"] tables of src (verbatim, in src's order) whose entity dst
// does not define in any form. It reports false when nothing was added or
// either text does not parse.
func mergePluginTables(dst, src string) (string, bool) {
	srcDoc, err := parseTOML(src)
	if err != nil {
		return "", false
	}
	dstDoc, err := parseTOML(dst)
	if err != nil {
		return "", false
	}
	var add []string
	for _, family := range pluginFamilies {
		if dstDoc.familyClosed(family) {
			continue
		}
		have := dstDoc.familyFields(family)
		for _, b := range srcDoc.familyBlocks(family) {
			if _, ok := have[b.name]; !ok {
				add = append(add, b.text)
			}
		}
	}
	if len(add) == 0 {
		return "", false
	}
	var b strings.Builder
	b.WriteString(dst)
	if dst != "" && !strings.HasSuffix(dst, "\n") {
		b.WriteByte('\n')
	}
	for _, text := range add {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(text)
		if !strings.HasSuffix(text, "\n") {
			b.WriteByte('\n')
		}
	}
	out := b.String()
	if _, err := parseTOML(out); err != nil {
		return "", false
	}
	return out, true
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
// [hooks.state."…"] tables. Only for precinto's own hooks, whose current
// hashes are known, does the new config's entry win when it holds the
// current hash and old's does not (D98).
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
	newStates := newDoc.hookStates()
	for k, hs := range keep {
		// D98: a per-root entry of a precinto hook that holds another
		// hash ("Modified" for Codex) never wins over the user's entry
		// for the current declaration.
		if want, ok := currentTrust(k); ok && hs.trustedHash != want {
			if n := newStates[k]; n != nil && n.trustedHash == want {
				delete(keep, k)
			}
		}
	}
	if len(keep) == 0 {
		return newText, nil
	}
	if newDoc.inlineHooks() {
		return "", fmt.Errorf("%w: hooks is an inline table; hook trust cannot be kept", errTOML)
	}
	drop := map[int]bool{}
	for k, hs := range newStates {
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
		if hs.trustedHash == "" && hs.contentHash == "" && hs.enabled == nil {
			continue
		}
		fmt.Fprintf(&b, "\n[hooks.state.%s]\n", tomlQuote(k))
		if hs.trustedHash != "" {
			fmt.Fprintf(&b, "trusted_hash = %s\n", tomlQuote(hs.trustedHash))
		}
		if hs.contentHash != "" {
			fmt.Fprintf(&b, "trusted_content_hash = %s\n", tomlQuote(hs.contentHash))
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

// authRecordName is the per-root home's record of the auth.json content
// last synchronized with each user home (D100). It is never sealed
// (never-touch, SPEC §7.2).
const authRecordName = ".precinto-auth"

// authRecord is the record: for every user home the per-root home was
// synchronized with, the SHA-256 of the auth.json both held after their
// last synchronization. Each pair has its own entry, so a launch with
// another CODEX_HOME neither erases another home's evidence nor counts as
// its logout.
type authRecord struct {
	V     int               `json:"v"`
	Homes map[string]string `json:"homes"` // user home → hex SHA-256
}

// syncAuth synchronizes auth.json from src to dst (PrepareHome: the user's
// home into the per-root home; SyncAuthBack: back), with the entry for
// user — the user home of the pair — in the per-root home's record (D100):
//
//   - both present: src is copied over dst when it is newer and differs
//     (a refreshed token), keeping src's mtime; the entry then names the
//     content both hold;
//   - only one present and no entry: the first synchronization of the pair
//     (or a login on that side): copied to the missing side when that is
//     dst and create allows it — always into the per-root home, into a
//     user home only when it is the default ~/.codex (D140): precinto
//     writes the credentials into no other CODEX_HOME, which keeps no
//     entry then, so no later loss there can count as a logout;
//   - only one present and an entry: the missing side held these
//     credentials and lost them — a logout (`codex logout`, Codex's
//     /logout). Nothing is ever copied into it, and the other side's copy
//     is removed too when it still holds exactly the recorded credentials
//     (a newer login there is kept). The entry goes once no side of the
//     pair holds the recorded credentials.
//
// It never removes anything else, and an unreadable record blocks copies
// into a missing side without removing anything.
func syncAuth(src, dst, record, user string, create bool) error {
	sdata, sst, err := readAuth(src)
	if err != nil {
		return err
	}
	ddata, dst0, err := readAuth(dst)
	if err != nil {
		return err
	}
	rec := readAuthRecord(record)
	want, hasEntry := rec.Homes[user]
	hasEntry = hasEntry || rec.corrupt
	switch {
	case sdata == nil && ddata == nil:
		return rec.drop(record, user)
	case sdata != nil && ddata != nil:
		if bytes.Equal(sdata, ddata) {
			return rec.set(record, user, sdata)
		}
		if sst.MtimeNS <= dst0.MtimeNS {
			return nil // dst is newer: the other direction copies it
		}
		if err := copyAuth(dst, sdata, sst); err != nil {
			return err
		}
		return rec.set(record, user, sdata)
	case !hasEntry:
		if sdata == nil {
			return nil // nothing to copy: dst has its own login
		}
		if !create {
			return nil // D140: no copy into another CODEX_HOME that has none
		}
		if err := copyAuth(dst, sdata, sst); err != nil {
			return err
		}
		return rec.set(record, user, sdata)
	}
	// One side logged out: never copy into it.
	path, data, st := src, sdata, sst
	if sdata == nil {
		path, data, st = dst, ddata, dst0
	}
	if rec.corrupt || sum256(data) != want {
		return nil // a newer login on the other side: kept, not synchronized
	}
	if err := removeIfUnchanged(path, st); err != nil {
		return err
	}
	return rec.drop(record, user)
}

// readAuth reads an auth.json; a missing file is (nil, zero, nil).
func readAuth(path string) ([]byte, fsx.Stat, error) {
	data, st, err := readFileBounded(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fsx.Stat{}, nil
	}
	if err != nil {
		return nil, fsx.Stat{}, err
	}
	if data == nil {
		data = []byte{}
	}
	return data, st, nil
}

// copyAuth writes data over path atomically (0600) with the source's mtime,
// so the next comparison sees both copies equal.
func copyAuth(path string, data []byte, src fsx.Stat) error {
	if err := fsx.WriteFileAtomic(path, data, 0o600); err != nil {
		return err
	}
	mt := time.Unix(0, src.MtimeNS)
	return os.Chtimes(path, mt, mt)
}

func sum256(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// readRecord is a decoded auth record; corrupt marks one that exists but
// cannot be read or decoded (it then stands for an entry of every user
// home).
type readRecord struct {
	authRecord
	corrupt bool
}

// readAuthRecord returns the record; a missing one has no entries.
func readAuthRecord(path string) readRecord {
	data, _, err := readFileBounded(path)
	if errors.Is(err, fs.ErrNotExist) {
		return readRecord{}
	}
	var r authRecord
	if err != nil || json.Unmarshal(data, &r) != nil || r.V != 1 || len(r.Homes) == 0 {
		return readRecord{corrupt: true} // a record is removed once it has no entry
	}
	for user, sum := range r.Homes {
		if !filepath.IsAbs(user) || filepath.Clean(user) != user || len(sum) != sha256.Size*2 {
			return readRecord{corrupt: true}
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return readRecord{corrupt: true}
		}
	}
	return readRecord{authRecord: r}
}

// set records that both homes of the pair hold data. A corrupt record is
// replaced by one holding this entry only.
func (r readRecord) set(path, user string, data []byte) error {
	sum := sum256(data)
	if !r.corrupt && r.Homes[user] == sum {
		return nil
	}
	homes := map[string]string{user: sum}
	if !r.corrupt {
		for u, s := range r.Homes {
			if u != user {
				homes[u] = s
			}
		}
	}
	return writeAuthRecord(path, homes)
}

// drop removes the pair's entry, and the record once it has none (a
// corrupt record goes as a whole: its entries cannot be told apart).
func (r readRecord) drop(path, user string) error {
	if !r.corrupt {
		if _, ok := r.Homes[user]; !ok {
			return nil
		}
		if len(r.Homes) > 1 {
			homes := make(map[string]string, len(r.Homes)-1)
			for u, s := range r.Homes {
				if u != user {
					homes[u] = s
				}
			}
			return writeAuthRecord(path, homes)
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// writeAuthRecord writes the record atomically (0600); json.Marshal sorts
// the map keys, so equal records have equal bytes.
func writeAuthRecord(path string, homes map[string]string) error {
	b, err := json.Marshal(authRecord{V: 1, Homes: homes})
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(path, append(b, '\n'), 0o600)
}

// removeIfUnchanged removes path when it is still the file observed as st.
func removeIfUnchanged(path string, st fsx.Stat) error {
	cur, err := fsx.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !cur.Unchanged(st) {
		return nil // replaced meanwhile: a newer copy, kept
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// linkShared makes link a symlink to target (plugins/ and skills/ are
// shared with the user's home, D31). When the user has none, nothing is
// done: Codex creates its own. A real directory there (Codex created it
// while the user had none) is moved next to the home, into
// <home>.displaced/<name>-<UTC time>, never deleted, and replaced by the
// link (D99); any other real entry is left as it is.
func linkShared(home, link, target string) error {
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
		if !st.IsDir() || int(st.UID) != os.Getuid() {
			return nil // not a directory of ours: never replaced
		}
		return displaceAndLink(home, link, target)
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

// displacedSuffix names the directory next to a per-root home that keeps
// what PrepareHome moved out of it (D99).
const displacedSuffix = ".displaced"

// displaceAndLink moves the directory link into <home>.displaced/ under a
// name of its own, then creates the link; if the link cannot be made the
// directory goes back.
func displaceAndLink(home, link, target string) error {
	dir := home + displacedSuffix
	if err := ensureHome(dir); err != nil {
		return err
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	dst := filepath.Join(dir, filepath.Base(link)+"-"+stamp)
	for i := 1; ; i++ {
		if _, err := fsx.Lstat(dst); errors.Is(err, fs.ErrNotExist) {
			break
		} else if err != nil {
			return err
		}
		dst = filepath.Join(dir, filepath.Base(link)+"-"+stamp+"-"+strconv.Itoa(i))
	}
	if err := os.Rename(link, dst); err != nil {
		return err
	}
	if err := os.Symlink(target, link); err != nil {
		if rerr := os.Rename(dst, link); rerr != nil {
			return errors.Join(err, rerr)
		}
		return err
	}
	return nil
}

// syncAuthBack implements SyncAuthBack: a refreshed token in the per-root
// home goes back to the user's home (only if that home exists), and a
// logout on either side is never undone (D100). A user home without an
// auth.json gets one only when it is the default ~/.codex (D140).
func syncAuthBack(ctx context.Context, s Seed) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(s.RootHome) || !filepath.IsAbs(s.UserHome) {
		return fmt.Errorf("codex: homes must be absolute")
	}
	user := filepath.Clean(s.UserHome)
	if !isDir(user) {
		return nil
	}
	home := filepath.Clean(s.RootHome)
	return syncAuth(filepath.Join(home, authName), filepath.Join(user, authName), filepath.Join(home, authRecordName), user, s.UserDefault)
}

// isDir reports whether p is a directory (not a symlink to one).
func isDir(p string) bool {
	st, err := fsx.Lstat(p)
	return err == nil && st.IsDir()
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

// isDefaultHome reports whether user (a UserHome) is the default ~/.codex
// of e: CODEX_HOME unset, or naming that directory (D140).
func isDefaultHome(e paths.Env, user string) bool {
	if user == "" {
		return false
	}
	h, err := paths.UserHome(e)
	if err != nil {
		return false
	}
	return filepath.Clean(user) == resolve(filepath.Join(h, ".codex"))
}

// resolve returns the realpath of an existing path (Codex canonicalizes
// CODEX_HOME), else the cleaned path.
func resolve(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// hooksTrusted implements HooksTrusted over homeTrust (D98, D99).
func hooksTrusted(home string) (trusted, known bool, err error) {
	st, err := homeTrust(home, "")
	switch {
	case err != nil:
		return false, false, err
	case st == trustTrusted:
		return true, true, nil
	case st == trustModified:
		return false, true, ErrHooksModified
	case st == trustPluginMissing:
		return false, true, ErrPluginMissing
	case st == trustUntrusted:
		return false, true, nil
	}
	return false, false, nil
}
