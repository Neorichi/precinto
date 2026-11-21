package harness

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/precinto/precinto/internal/platform"
)

// interpreters are the executables whose first argument names the program
// they run (node, bun or python CLIs): argv_regex also looks at argv[1] of
// such processes, and only of them, so an editor opening a file called
// "claude" is not taken for Claude.
var interpreters = map[string]bool{
	"node": true, "nodejs": true, "bun": true, "deno": true,
	"python": true, "python3": true, "pypy3": true,
}

func isInterpreter(name string) bool {
	if interpreters[name] {
		return true
	}
	// python3.12, node22 …
	for _, p := range []string{"python3.", "node"} {
		if strings.HasPrefix(name, p) && name != p && strings.Trim(name[len(p):], "0123456789.") == "" {
			return true
		}
	}
	return false
}

// regexCache compiles argv_regex patterns once per process (inventories are
// validated at load, so a pattern that does not compile matches nothing).
var regexCache sync.Map // string -> *regexp.Regexp (nil when invalid)

func compiled(expr string) *regexp.Regexp {
	if v, ok := regexCache.Load(expr); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		re = nil
	}
	regexCache.Store(expr, re)
	return re
}

// matchProcess implements MatchProcess. Matching is by executable path,
// never by the kernel's short name (Claude's p_comm is its version string,
// IM9), and a zombie is never a harness process (it has exited, R8).
func matchProcess(inv Inventory, p platform.ProcInfo) bool {
	if p.ID.PID <= 0 || p.State == platform.StateZombie {
		return false
	}
	exe := p.Exe
	for _, name := range inv.Process.ExeBasenames {
		if exe != "" && filepath.Base(exe) == name {
			return true
		}
	}
	for _, pat := range inv.Process.ExePaths {
		if exe != "" && matchExePath(pat, exe) {
			return true
		}
	}
	if len(inv.Process.ArgvRegex) == 0 {
		return false
	}
	candidates := make([]string, 0, 3)
	if exe != "" {
		candidates = append(candidates, exe)
	}
	if len(p.Argv) > 0 {
		candidates = append(candidates, p.Argv[0])
		if len(p.Argv) > 1 && (isInterpreter(filepath.Base(p.Argv[0])) || (exe != "" && isInterpreter(filepath.Base(exe)))) {
			candidates = append(candidates, p.Argv[1])
		}
	}
	for _, expr := range inv.Process.ArgvRegex {
		re := compiled(expr)
		if re == nil {
			continue
		}
		for _, c := range candidates {
			if re.MatchString(c) {
				return true
			}
		}
	}
	return false
}

// exePathTail returns the part of an exe_paths pattern that must match the
// end of the executable path: the whole pattern when it is absolute, the
// part after "~/" or "$VAR/" otherwise (MatchProcess has no environment, so
// such patterns match below any directory).
func exePathTail(p string) (string, bool) {
	switch {
	case strings.HasPrefix(p, "/"):
		return strings.TrimPrefix(p, "/"), true
	case strings.HasPrefix(p, "~/"):
		return p[2:], true
	case strings.HasPrefix(p, "$"):
		v, rest, ok := strings.Cut(p[1:], "/")
		if !ok || v == "" || rest == "" {
			return "", false
		}
		return rest, true
	}
	return "", false
}

// matchExePath matches an executable path against one exe_paths pattern,
// component by component (a "*" never crosses a "/"). Absolute patterns
// must match the whole path; "~/…" and "$VAR/…" patterns match its last
// components below any directory.
func matchExePath(pattern, exe string) bool {
	if !filepath.IsAbs(exe) {
		return false
	}
	tail, ok := exePathTail(pattern)
	if !ok {
		return false
	}
	pc := strings.Split(tail, "/")
	ec := strings.Split(strings.TrimPrefix(filepath.Clean(exe), "/"), "/")
	if strings.HasPrefix(pattern, "/") {
		if len(pc) != len(ec) {
			return false
		}
	} else {
		if len(ec) <= len(pc) { // the home directory itself must be a real prefix
			return false
		}
		ec = ec[len(ec)-len(pc):]
	}
	for i := range pc {
		ok, err := path.Match(pc[i], ec[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// classify implements Classify. Passthrough is decided by argv prefix only,
// because a passthrough launch is neither gated nor restored: a flag that
// merely appears later in argv (a prompt "-h") must never open the gate.
// Direct-mode flags (-p, --print, --output-format) count anywhere before a
// "--" terminator, since running a print-mode session on a PTY is harmless
// while running an interactive one without the lock screen is not; other
// direct entries (codex exec) are prefixes. Without terminals on both
// stdin and stdout an interactive launch runs direct (no PTY).
func classify(inv Inventory, args []string, stdinTTY, stdoutTTY bool) LaunchMode {
	for _, p := range inv.Passthrough {
		if hasPrefix(args, p) {
			return LaunchPassthrough
		}
	}
	for _, d := range inv.Direct {
		if hasPrefix(args, d) {
			return LaunchDirect
		}
		if len(d) == 1 && strings.HasPrefix(d[0], "-") && hasFlag(args, d[0]) {
			return LaunchDirect
		}
	}
	if !stdinTTY || !stdoutTTY {
		return LaunchDirect
	}
	return LaunchInteractive
}

func hasPrefix(args, prefix []string) bool {
	if len(prefix) == 0 || len(args) < len(prefix) {
		return false
	}
	for i := range prefix {
		if args[i] != prefix[i] {
			return false
		}
	}
	return true
}

// hasFlag reports whether flag (or flag=value for long flags) appears in
// args before a "--" terminator.
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == flag || (strings.HasPrefix(flag, "--") && strings.HasPrefix(a, flag+"=")) {
			return true
		}
	}
	return false
}
