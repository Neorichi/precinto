package doctor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// Harness versions are read without running the harness: from the path of
// its executable (native installs run …/versions/<version>, Homebrew
// installs live under …/<formula>/<version>/), from the package.json of an
// npm install, and from the kernel name of running Claude processes (Claude
// Code sets it to its version; it is read, never matched on, IM9).

// brewRevision is the "_1" revision suffix of Homebrew keg directories.
var brewRevision = regexp.MustCompile(`_[0-9]+$`)

// install is what doctor found of one harness.
type install struct {
	exe       string // resolved executable, "" when not found
	version   version
	versionOK bool
	running   []runningHarness // live processes of the harness
	// winProgram is, under WSL, why exe would run as a Windows program,
	// or why doctor could not tell (D156): precinto run and integrate
	// refuse it, and its version is not read.
	winProgram *harness.ProgramError
}

// checkInstalled applies D156 to the executable doctor found for h: under
// WSL a Windows install (WSL appends the Windows PATH) is recorded as such
// instead of being read for a version.
func (e *env) checkInstalled(in *install, h harness.ID) bool {
	if in.exe == "" || e.d.CheckProgram == nil {
		return true
	}
	var pe *harness.ProgramError
	if errors.As(e.d.CheckProgram(e.o.Env, h, in.exe), &pe) {
		in.winProgram = pe
		return false
	}
	return true
}

// winProgramFinding is the finding of an executable that would run as a
// Windows program, or that doctor could not check (D156); name is the
// harness's name, cmd its command.
func (e *env) winProgramFinding(code, name, cmd string, pe *harness.ProgramError) Finding {
	cause := pe.Why
	if pe.Runs != "" {
		cause = "it runs " + e.show(pe.Runs) + ", which " + pe.Why
	}
	fix := "install " + name + " inside this WSL distribution, ahead of the Windows PATH that WSL appends to PATH"
	if pe.Unknown {
		return fail(code, "could not check that the "+cmd+" precinto would run, "+e.show(pe.Exe)+", is not a Windows program ("+cause+"), so precinto run and integrate refuse it", fix)
	}
	return fail(code, "the "+cmd+" precinto would run, "+e.show(pe.Exe)+", is a Windows program ("+cause+"): precinto run and integrate refuse it, and precinto can neither see nor seal what a Windows "+name+" writes", fix)
}

type runningHarness struct {
	pid       int
	version   version
	versionOK bool
}

// findExecutable returns the first executable named name among the
// configured binary, PATH, the per-user install locations and the system
// directories of deps.SystemBins.
func (e *env) findExecutable(name, configured string) string {
	cands := []string{}
	if filepath.IsAbs(configured) {
		cands = append(cands, configured)
	}
	if p, err := paths.LookPath(e.o.Env, name); err == nil {
		cands = append(cands, p)
	}
	if e.home != "" {
		cands = append(cands,
			filepath.Join(e.home, ".local", "bin", name),
			filepath.Join(e.home, "."+name, "local", name), // claude's old local install
			filepath.Join(e.home, ".npm-global", "bin", name),
		)
	}
	for _, d := range e.d.SystemBins {
		cands = append(cands, filepath.Join(d, name))
	}
	for _, c := range cands {
		if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return c
		}
	}
	return ""
}

// versionOfExecutable derives the version of an installed harness: from
// the package.json of the npm package pkg when the executable is that
// package's script, else from the nearest path component that is a version
// (…/versions/2.1.329, …/Cellar/codex/0.154.0/bin/codex,
// …/Caskroom/claude-code/2.1.329/claude), at most four levels up. With pkg
// "" (data-driven inventories name no package) the package is the one the
// script lies in.
func versionOfExecutable(exe, pkg string) (version, bool) {
	real := exe
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		real = r
	}
	// npm: <prefix>/lib/node_modules/<pkg>/{cli.js,bin/codex.js}; the
	// prefix itself may carry a version (nvm), so this comes first.
	if dir := npmPackageDir(real, pkg); dir != "" {
		b, err := readRegular(filepath.Join(dir, "package.json"), maxSmallFile)
		if err != nil {
			return version{}, false
		}
		var meta struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(b, &meta) != nil || (pkg != "" && meta.Name != pkg) {
			return version{}, false
		}
		return parseVersion(meta.Version)
	}
	p := real
	for i := 0; i < 5 && p != "/" && p != "."; i++ {
		if v, ok := parseVersion(brewRevision.ReplaceAllString(filepath.Base(p), "")); ok {
			return v, true
		}
		p = filepath.Dir(p)
	}
	return version{}, false
}

// npmPackageDir returns the directory of the npm package a resolved script
// lies in: <…>/node_modules/<pkg>, or with pkg "" the package (name or
// @scope/name) after the last node_modules of the path; "" when the script
// is not inside such a package.
func npmPackageDir(real, pkg string) string {
	const nm = "/node_modules/"
	if pkg != "" {
		marker := nm + pkg + "/"
		if i := strings.Index(real, marker); i >= 0 {
			return real[:i+len(marker)-1]
		}
		return ""
	}
	i := strings.LastIndex(real, nm)
	if i < 0 {
		return ""
	}
	parts := strings.Split(real[i+len(nm):], "/")
	n := 1
	if strings.HasPrefix(parts[0], "@") {
		n = 2
	}
	if len(parts) <= n || parts[0] == "" || parts[n-1] == "" {
		return "" // the script must lie inside the package directory
	}
	return real[:i+len(nm)] + strings.Join(parts[:n], "/")
}

// runningOf lists the live processes of a harness, recognised by their
// executable or script (never by p_comm), with the version each runs.
func (e *env) runningOf(match func(platform.ProcInfo) bool, versionOf func(platform.ProcInfo) (version, bool)) []runningHarness {
	if e.o.Procs == nil {
		return nil
	}
	ps, err := e.o.Procs.List()
	if err != nil {
		return nil
	}
	var out []runningHarness
	for _, p := range ps {
		if p.State == platform.StateZombie || !match(p) {
			continue
		}
		v, ok := versionOf(p)
		out = append(out, runningHarness{pid: p.ID.PID, version: v, versionOK: ok})
	}
	return out
}

// procNames returns the executable, argv[0] and script of a process, for
// recognising harnesses.
func procNames(p platform.ProcInfo) []string {
	names := []string{p.Exe}
	if len(p.Argv) > 0 {
		names = append(names, p.Argv[0])
		for _, a := range p.Argv[1:] {
			if a != "" && !strings.HasPrefix(a, "-") {
				names = append(names, a) // the script of node/bun
				break
			}
		}
	}
	return names
}

// isClaudeProcess recognises Claude Code: a `claude` executable, a native
// versioned install (…/claude/versions/<v>) or the npm package's script.
func isClaudeProcess(p platform.ProcInfo) bool {
	for _, n := range procNames(p) {
		if n == "" {
			continue
		}
		base := filepath.Base(n)
		if base == "claude" || strings.Contains(n, "/claude/versions/") ||
			strings.Contains(n, "/node_modules/@anthropic-ai/claude-code/") {
			return true
		}
	}
	return false
}

// claudeProcessVersion reads a Claude process's version from its versioned
// executable, else from its kernel name (Claude sets it to the version).
func claudeProcessVersion(p platform.ProcInfo) (version, bool) {
	if strings.Contains(p.Exe, "/claude/versions/") {
		if v, ok := parseVersion(filepath.Base(p.Exe)); ok {
			return v, true
		}
	}
	return parseVersion(p.Comm)
}

// isCodexProcess recognises Codex by its executable or the npm script.
func isCodexProcess(p platform.ProcInfo) bool {
	for _, n := range procNames(p) {
		if n == "" {
			continue
		}
		if filepath.Base(n) == "codex" || strings.Contains(n, "/node_modules/@openai/codex/") {
			return true
		}
	}
	return false
}

// minVersion returns the stricter of the contract floor and the configured
// min_version of a harness.
func (e *env) minVersion(h harness.ID, floor string) version {
	v, _ := parseVersion(floor)
	if c, ok := parseVersion(e.o.Cfg.Harness[string(h)].MinVersion); ok && c.compare(v) > 0 {
		return c
	}
	return v
}

// verifiedRange returns the verified_versions range of a harness's
// inventory, or def when the inventory cannot be read.
func (e *env) verifiedRange(h harness.ID, def string) string {
	inv, err := e.d.Inventory(string(h))
	if err != nil || strings.TrimSpace(inv.VerifiedVersions) == "" {
		return def
	}
	if _, ok := inRange(version{}, inv.VerifiedVersions); !ok {
		return def
	}
	return inv.VerifiedVersions
}
