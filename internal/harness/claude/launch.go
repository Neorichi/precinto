package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
)

const (
	// defaultCleanupDays is Claude's cleanupPeriodDays default.
	defaultCleanupDays = 30
	// maxSettingsBytes bounds the user settings file read.
	maxSettingsBytes = 4 << 20
)

// managedSettings is the inline --settings JSON of managed launches (D32,
// HA12): no idle compaction, no away summary, no precomputed compaction, so
// Claude does not write derived data on its own while a folder is idle.
const managedSettings = `{"idleCompaction":false,"awaySummaryEnabled":false,"precomputeCompactionEnabled":false}`

// settingsJSON implements SettingsJSON. The values do not depend on the
// policy today; the policy is passed so a future setting can.
func settingsJSON(config.Policy) string { return managedSettings }

// cleanupPeriodDays implements CleanupPeriodDays: settings.json of the
// config dir, key cleanupPeriodDays; a missing file or key gives the
// default. A file that cannot be decoded, or a value that is not a
// non-negative whole number, returns the default with an error.
func cleanupPeriodDays(configDir string) (int, error) {
	if !filepath.IsAbs(configDir) {
		return defaultCleanupDays, fmt.Errorf("claude: config dir %q is not absolute", configDir)
	}
	data, _, err := readBounded(filepath.Join(filepath.Clean(configDir), "settings.json"), maxSettingsBytes)
	if notExist(err) {
		return defaultCleanupDays, nil
	}
	if err != nil {
		return defaultCleanupDays, err
	}
	var s struct {
		CleanupPeriodDays *json.Number `json:"cleanupPeriodDays"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&s); err != nil {
		return defaultCleanupDays, fmt.Errorf("claude: settings.json does not decode: %w", err)
	}
	if s.CleanupPeriodDays == nil {
		return defaultCleanupDays, nil
	}
	f, err := s.CleanupPeriodDays.Float64()
	if err != nil || f < 0 || f != math.Trunc(f) || f > 1e6 {
		return defaultCleanupDays, errors.New("claude: cleanupPeriodDays is not a whole number of days")
	}
	return int(f), nil
}

// Claude CLI flags precinto interprets (HA23, IM13).
var (
	resumeFlags   = []string{"--resume", "-r"}
	continueFlags = []string{"--continue", "-c"}
	forkFlags     = []string{"--fork-session"}
	jobCommands   = []string{"attach", "respawn"}
)

// resumeFlagsOf returns the resume flag lists of the inventory, falling
// back to the built-in ones.
func resumeFlagsOf(inv harness.Inventory) (resume, cont, fork []string) {
	resume, cont, fork = resumeFlags, continueFlags, forkFlags
	if len(inv.Resume.Flags) > 0 {
		resume = inv.Resume.Flags
	}
	if len(inv.Resume.Continue) > 0 {
		cont = inv.Resume.Continue
	}
	if len(inv.Resume.Fork) > 0 {
		fork = inv.Resume.Fork
	}
	return resume, cont, fork
}

func oneOf(s string, list []string) bool {
	for _, x := range list {
		if s == x {
			return true
		}
	}
	return false
}

// parseResume implements ParseResume with the given flag lists.
//
//	--resume <uuid> | -r <uuid>     ResumeSID (value lowercased)
//	--resume <path>.jsonl           ResumePath (value as given)
//	--resume <term>                 ResumeName
//	--resume / -r (no value)        ResumePicker
//	--continue / -c                 ResumeContinue
//	attach|respawn <job-id>         ResumeJob
//	--fork-session                  Fork, with any of the above
//
// "--resume=<v>" is accepted; parsing stops at "--".
func parseResume(args []string, resume, cont, fork []string) harness.Resume {
	var r harness.Resume
	set := func(k harness.ResumeKind, v string) {
		if r.Kind == harness.ResumeNone || (r.Kind == harness.ResumeContinue && k != harness.ResumeContinue) {
			r.Kind, r.Value = k, v
		}
	}
	positional := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		switch {
		case oneOf(a, fork):
			r.Fork = true
		case oneOf(a, cont):
			set(harness.ResumeContinue, "")
		case oneOf(a, resume):
			if i+1 < len(args) && args[i+1] != "--" && !strings.HasPrefix(args[i+1], "-") {
				set(classifyResumeValue(args[i+1]))
				i++
			} else {
				set(harness.ResumePicker, "")
			}
		case strings.HasPrefix(a, "--") && strings.Contains(a, "=") && oneOf(a[:strings.Index(a, "=")], resume):
			v := a[strings.Index(a, "=")+1:]
			if v == "" {
				set(harness.ResumePicker, "")
			} else {
				set(classifyResumeValue(v))
			}
		case !strings.HasPrefix(a, "-"):
			if positional == 0 && oneOf(a, jobCommands) && i+1 < len(args) && safeComponent(args[i+1]) && !strings.HasPrefix(args[i+1], "-") {
				set(harness.ResumeJob, args[i+1])
				i++
			}
			positional++
		}
	}
	return r
}

func classifyResumeValue(v string) (harness.ResumeKind, string) {
	if isUUID(v) {
		return harness.ResumeSID, strings.ToLower(v)
	}
	if strings.HasSuffix(v, ".jsonl") && (strings.Contains(v, "/") || filepath.IsAbs(v)) {
		return harness.ResumePath, v
	}
	return harness.ResumeName, v
}

// resumeSID returns the session id a resume target names directly (sid or
// a transcript path whose basename is <sid>.jsonl).
func resumeSID(r harness.Resume) (string, bool) {
	switch r.Kind {
	case harness.ResumeSID:
		return r.Value, isUUID(r.Value)
	case harness.ResumePath:
		return sidOf(strings.TrimSuffix(filepath.Base(r.Value), ".jsonl"))
	}
	return "", false
}

// addDirs returns the directories of --add-dir options (variadic, as the
// Claude CLI parses them), resolved against cwd and realpath'd like the
// roots of config.
func addDirs(args []string, cwd string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if v, ok := strings.CutPrefix(a, "--add-dir="); ok {
			out = append(out, absAgainst(v, cwd))
			continue
		}
		if a != "--add-dir" {
			continue
		}
		for i+1 < len(args) && args[i+1] != "--" && !strings.HasPrefix(args[i+1], "-") {
			i++
			out = append(out, absAgainst(args[i], cwd))
		}
	}
	return out
}

// positionals returns the arguments of a subcommand that are not options
// (claude purge [path]), as paths resolved against cwd and realpath'd.
func positionals(args []string, cwd string) []string {
	var out []string
	for _, a := range args {
		if a == "--" {
			break
		}
		if a != "" && !strings.HasPrefix(a, "-") {
			out = append(out, absAgainst(a, cwd))
		}
	}
	return out
}

// absAgainst resolves p against cwd and realpaths it when it exists.
func absAgainst(p, cwd string) string {
	if filepath.IsAbs(p) {
		return realpath(p)
	}
	return realpath(filepath.Join(cwd, p))
}

// hasSettingsFlag reports whether the user passed --settings.
func hasSettingsFlag(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--settings" || strings.HasPrefix(a, "--settings=") {
			return true
		}
	}
	return false
}

func hasArg(args []string, flag string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == flag {
			return true
		}
	}
	return false
}
