package harness

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Inventory schema values (SPEC §7.3, D33).
const (
	inventorySchema = 1

	statusVerified     = "verified"
	statusExperimental = "experimental"

	modeCapsule = "capsule"
	modeHome    = "home"

	partitionHome        = "home"
	partitionProjectSlug = "project-slug"
	partitionProjectDir  = "project-dir"

	lockFlock   = "flock"
	lockJSONPID = "json-pid"

	inventoryExt = ".toml"
	// maxInventoryBytes bounds one inventory file; they are a few hundred
	// bytes, so anything larger is not an inventory.
	maxInventoryBytes = 1 << 20
)

// errInventory is wrapped by every validation failure.
var errInventory = errors.New("harness: invalid inventory")

var (
	idRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	baseNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,63}$`)
	envNameRE  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	// placeholderRE finds {name} placeholders of base defaults.
	placeholderRE = regexp.MustCompile(`\{[^{}]*\}`)
)

// basePlaceholders are the placeholders a base default may use: the
// current uid (Claude's tmp dir), precinto's base and the root id (Codex
// per-root homes, D31).
var basePlaceholders = map[string]bool{"{uid}": true, "{base}": true, "{root_id}": true}

// builtIn reports whether id is one of the built-in adapters, which read
// their inventory only for process matching and launch classification.
func builtIn(id string) bool { return id == string(ClaudeCode) || id == string(Codex) }

// loadInventory implements LoadInventory.
func loadInventory(fsys fs.FS, name string) (Inventory, error) {
	if fsys == nil {
		return Inventory{}, fmt.Errorf("%w: no inventory file system", errInventory)
	}
	file := name
	if !strings.HasSuffix(file, inventoryExt) {
		file += inventoryExt
	}
	stem := strings.TrimSuffix(file, inventoryExt)
	if !fs.ValidPath(file) || strings.Contains(file, "/") || !idRE.MatchString(stem) {
		return Inventory{}, fmt.Errorf("%w: bad inventory name %q", errInventory, name)
	}
	data, err := readBounded(fsys, file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Inventory{}, fmt.Errorf("%w: no inventory %s: %w", ErrUnknownHarness, stem, err)
		}
		return Inventory{}, fmt.Errorf("harness: read inventory %s: %w", stem, err)
	}
	inv, err := decodeInventory(data)
	if err != nil {
		return Inventory{}, fmt.Errorf("%w %s: %w", errInventory, stem, err)
	}
	if inv.ID != stem {
		return Inventory{}, fmt.Errorf("%w %s: id %q does not match the file name", errInventory, stem, inv.ID)
	}
	if err := validateInventory(inv); err != nil {
		return Inventory{}, fmt.Errorf("%w %s: %w", errInventory, stem, err)
	}
	return inv, nil
}

// loadInventories implements LoadInventories: every *.toml at the root of
// fsys, in file-name order; duplicate ids are refused.
func loadInventories(fsys fs.FS) ([]Inventory, error) {
	if fsys == nil {
		return nil, fmt.Errorf("%w: no inventory file system", errInventory)
	}
	names, err := fs.Glob(fsys, "*"+inventoryExt)
	if err != nil {
		return nil, fmt.Errorf("harness: list inventories: %w", err)
	}
	sort.Strings(names)
	out := make([]Inventory, 0, len(names))
	seen := map[string]bool{}
	for _, n := range names {
		inv, err := loadInventory(fsys, n)
		if err != nil {
			return nil, err
		}
		if seen[inv.ID] {
			return nil, fmt.Errorf("%w: duplicate inventory id %q", errInventory, inv.ID)
		}
		seen[inv.ID] = true
		out = append(out, inv)
	}
	return out, nil
}

func readBounded(fsys fs.FS, name string) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxInventoryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxInventoryBytes {
		return nil, fmt.Errorf("%w: file larger than %d bytes", errInventory, maxInventoryBytes)
	}
	return data, nil
}

// decodeInventory decodes strictly: every key of the file must map to a
// field of Inventory, so a typo never silently drops a deny-list entry or a
// process matcher (fail closed, HA20).
func decodeInventory(data []byte) (Inventory, error) {
	var inv Inventory
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&inv)
	if err != nil {
		return Inventory{}, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return Inventory{}, fmt.Errorf("unknown keys %s", strings.Join(keys, ", "))
	}
	return inv, nil
}

// validateInventory checks every field against the schema of SPEC §7.3.
func validateInventory(inv Inventory) error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if inv.Schema != inventorySchema {
		bad("schema %d, want %d", inv.Schema, inventorySchema)
	}
	if !idRE.MatchString(inv.ID) {
		bad("bad id %q", inv.ID)
	}
	if strings.TrimSpace(inv.Name) == "" {
		bad("name is empty")
	}
	switch inv.Status {
	case statusVerified, statusExperimental:
	default:
		bad("status %q is neither %q nor %q", inv.Status, statusVerified, statusExperimental)
	}
	if !builtIn(inv.ID) && inv.Status != statusExperimental {
		bad("a non-built-in inventory must ship status = %q (D33)", statusExperimental)
	}
	if strings.ContainsAny(inv.VerifiedVersions, "\n\r") {
		bad("verified_versions spans several lines")
	}
	switch inv.Mode {
	case modeCapsule:
		if inv.ID != string(ClaudeCode) {
			bad("mode %q is reserved for the built-in claude-code adapter", modeCapsule)
		}
	case modeHome:
	default:
		bad("mode %q is neither %q nor %q", inv.Mode, modeCapsule, modeHome)
	}

	bases := map[string]bool{}
	if len(inv.Bases) == 0 {
		bad("no bases")
	}
	for i, b := range inv.Bases {
		if !baseNameRE.MatchString(b.Name) {
			bad("bases[%d]: bad name %q", i, b.Name)
		} else if bases[b.Name] {
			bad("bases[%d]: duplicate name %q", i, b.Name)
		}
		bases[b.Name] = true
		if err := checkBaseDefault(b.Default); err != nil {
			bad("bases[%d] (%s): %v", i, b.Name, err)
		}
		if b.Env != "" && !envNameRE.MatchString(b.Env) {
			bad("bases[%d] (%s): bad env %q", i, b.Name, b.Env)
		}
	}
	single := ""
	if len(inv.Bases) == 1 {
		single = inv.Bases[0].Name
	}
	checkGlobs := func(field string, globs []string, allowBare bool) {
		for i, g := range globs {
			base, glob, err := splitBaseGlob(g, single, allowBare)
			if err == nil && !bases[base] {
				err = fmt.Errorf("unknown base %q", base)
			}
			if err == nil {
				err = checkGlob(glob)
			}
			if err != nil {
				bad("%s[%d] %q: %v", field, i, g, err)
			}
		}
	}
	checkGlobs("content", inv.Content, false)
	checkGlobs("never_touch", inv.NeverTouch, true)
	checkGlobs("exclude", inv.Exclude, false)
	if !builtIn(inv.ID) && len(inv.Content) == 0 {
		bad("an experimental inventory must list its content (fail closed)")
	}
	for i, l := range inv.Locks {
		switch l.Kind {
		case lockFlock, lockJSONPID:
		default:
			bad("locks[%d]: kind %q is neither %q nor %q", i, l.Kind, lockFlock, lockJSONPID)
		}
		checkGlobs(fmt.Sprintf("locks[%d].glob", i), []string{l.Glob}, false)
	}

	if len(inv.Process.ExeBasenames)+len(inv.Process.ExePaths)+len(inv.Process.ArgvRegex) == 0 {
		bad("process: no matcher (exe_basenames, exe_paths or argv_regex)")
	}
	for i, n := range inv.Process.ExeBasenames {
		if n == "" || strings.Contains(n, "/") {
			bad("process.exe_basenames[%d]: %q is not a file name", i, n)
		}
	}
	for i, p := range inv.Process.ExePaths {
		if err := checkExePath(p); err != nil {
			bad("process.exe_paths[%d] %q: %v", i, p, err)
		}
	}
	for i, r := range inv.Process.ArgvRegex {
		if _, err := regexp.Compile(r); err != nil {
			bad("process.argv_regex[%d]: %v", i, err)
		}
	}

	switch inv.Partition {
	case "", partitionHome, partitionProjectDir:
		if inv.SlugGlob != "" {
			bad("slug_glob needs partition = %q", partitionProjectSlug)
		}
	case partitionProjectSlug:
		if inv.SlugGlob == "" {
			bad("partition %q needs slug_glob", partitionProjectSlug)
		} else {
			checkGlobs("slug_glob", []string{inv.SlugGlob}, false)
		}
	default:
		bad("unknown partition %q", inv.Partition)
	}
	if !builtIn(inv.ID) && inv.Partition == "" {
		bad("an experimental inventory must declare its partition")
	}
	if len(inv.StopCmd) > 0 && strings.TrimSpace(inv.StopCmd[0]) == "" {
		bad("stop_cmd[0] is empty")
	}
	checkArgvs := func(field string, lists [][]string) {
		for i, l := range lists {
			if len(l) == 0 {
				bad("%s[%d] is empty", field, i)
			}
			for j, a := range l {
				if a == "" {
					bad("%s[%d][%d] is empty", field, i, j)
				}
			}
		}
	}
	checkArgvs("passthrough", inv.Passthrough)
	checkArgvs("direct", inv.Direct)
	for field, vals := range map[string][]string{
		"resume.flags": inv.Resume.Flags, "resume.continue": inv.Resume.Continue,
		"resume.fork": inv.Resume.Fork, "resume.subcommand": inv.Resume.Subcommand,
	} {
		for i, v := range vals {
			if v == "" {
				bad("%s[%d] is empty", field, i)
			}
		}
	}
	return errors.Join(errs...)
}

// checkBaseDefault accepts an absolute path, "~/…" or "$VAR/…" (resolved
// against the harness's environment), each optionally using the
// placeholders {uid}, {base} and {root_id}.
func checkBaseDefault(d string) error {
	if d == "" {
		return errors.New("empty default")
	}
	for _, ph := range placeholderRE.FindAllString(d, -1) {
		if !basePlaceholders[ph] {
			return fmt.Errorf("unknown placeholder %s", ph)
		}
	}
	if strings.ContainsAny(d, "\x00\n") {
		return errors.New("control character in default")
	}
	switch {
	case strings.HasPrefix(d, "/"), strings.HasPrefix(d, "~/"), strings.HasPrefix(d, "{base}/"):
	case strings.HasPrefix(d, "$"):
		v, _, _ := strings.Cut(d[1:], "/")
		if !envNameRE.MatchString(v) {
			return fmt.Errorf("bad variable %q", v)
		}
	default:
		return errors.New("default must be absolute, ~/…, $VAR/… or {base}/…")
	}
	return nil
}

// splitBaseGlob splits "<base>:<glob>". A bare glob is accepted only where
// allowBare is set and the inventory has a single base.
func splitBaseGlob(s, single string, allowBare bool) (base, glob string, err error) {
	if b, g, ok := strings.Cut(s, ":"); ok {
		return b, g, nil
	}
	if allowBare && single != "" {
		return single, s, nil
	}
	return "", "", errors.New(`want "<base>:<glob>"`)
}

// checkGlob requires a clean relative pattern whose components are valid
// path.Match patterns ("**" matches any number of components).
func checkGlob(g string) error {
	if g == "" {
		return errors.New("empty glob")
	}
	if strings.HasPrefix(g, "/") || strings.Contains(g, "\x00") {
		return errors.New("glob must be relative")
	}
	if g != "**" && path.Clean(g) != g {
		return errors.New("glob is not clean")
	}
	for _, c := range strings.Split(g, "/") {
		if c == ".." || c == "." || c == "" {
			return errors.New("glob escapes its base")
		}
		if c == "**" {
			continue
		}
		if _, err := path.Match(c, ""); err != nil {
			return err
		}
	}
	return nil
}

// checkExePath accepts an absolute glob, or one rooted at "~/" or "$VAR/"
// (matched against any directory, see matchExePath).
func checkExePath(p string) error {
	rest, ok := exePathTail(p)
	if !ok {
		return errors.New("exe path must be absolute, ~/… or $VAR/…")
	}
	return checkGlob(rest)
}
