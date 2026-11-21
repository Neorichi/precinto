package doctor

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// Codex checks (SPEC §7.2; HOOKS-IO §3, §6; D31, D44, HA1, HA6, R12).

const (
	codexVerifiedDefault = ">=0.154.0 <0.155.0"
	codexNPMPackage      = "@openai/codex"
	// shellTimeout bounds `$SHELL -lc true`; slowShell is when its startup
	// eats a noticeable part of Codex's 3 s SessionEnd budget.
	shellTimeout = 10 * time.Second
	slowShell    = time.Second
)

// codex returns what doctor found of the Codex installation.
func (e *env) codex() *install {
	if e.codexIn != nil {
		return e.codexIn
	}
	in := &install{}
	in.exe = e.findExecutable("codex", e.o.Cfg.Harness[string(harness.Codex)].Bin)
	if in.exe != "" {
		in.version, in.versionOK = versionOfExecutable(in.exe, codexNPMPackage)
	}
	// Running Codex processes carry no readable version (only Claude's
	// kernel name is its version).
	in.running = e.runningOf(isCodexProcess, func(platform.ProcInfo) (version, bool) { return version{}, false })
	e.codexIn = in
	return in
}

// codexUserHome returns the user's own Codex home (CODEX_HOME or ~/.codex)
// when it exists. A CODEX_HOME that is one of precinto's per-root homes
// (doctor run from inside `precinto run codex`) is not the user's own: then
// ~/.codex is.
func (e *env) codexUserHome() string {
	h, err := e.d.CodexUserHome(e.o.Env)
	if err != nil || !filepath.IsAbs(h) || paths.Within(e.o.Layout.HomesDir, h) {
		if e.home == "" {
			return ""
		}
		h = filepath.Join(e.home, ".codex")
	}
	if !isDir(h) {
		return ""
	}
	return filepath.Clean(h)
}

// perRootHome is one existing per-root Codex home (D31).
type perRootHome struct {
	root config.Root
	dir  string
}

// codexHomes lists the per-root homes that exist, for roots protecting
// Codex.
func (e *env) codexHomes() []perRootHome {
	var out []perRootHome
	for _, r := range e.o.Cfg.Roots {
		if !rootProtects(r, harness.Codex) {
			continue
		}
		d := e.o.Layout.CodexHome(r.ID)
		if isDir(d) {
			out = append(out, perRootHome{root: r, dir: d})
		}
	}
	return out
}

// codexPresent reports whether Codex is installed or has been used here.
func (e *env) codexPresent() bool {
	in := e.codex()
	return in.exe != "" || len(in.running) > 0 || e.codexUserHome() != "" || len(e.codexHomes()) > 0
}

// knownCodexTop are the top-level entries of a per-root home that precinto
// knows (content or never-touch, SPEC §7.2) besides what codex.Classify
// recognises by pattern.
var knownCodexTop = map[string]bool{
	"sessions": true, "archived_sessions": true, "history.jsonl": true, "session_index.jsonl": true,
	"shell_snapshots": true, "precinto-tmp": true, "log": true, "plugins": true, "skills": true,
}

// checkExperimentalVersion is SPEC §7.3's warning for an installed
// experimental harness outside its inventory's verified_versions. Doctor
// has no version probe for the experimental inventories yet (it never runs
// a harness to ask), so it reports nothing until one exists; the code is
// reserved in the vocabulary (CC-44).
func checkExperimentalVersion(e *env) []Finding { return nil }

func checkCodexVersion(e *env) []Finding {
	if !e.codexPresent() {
		return nil
	}
	in := e.codex()
	verified := e.verifiedRange(harness.Codex, codexVerifiedDefault)
	var out []Finding
	switch {
	case in.exe == "":
		out = append(out, info(CheckCodexVersion, "the codex executable was not found, so its version was not checked", ""))
	case !in.versionOK:
		out = append(out, info(CheckCodexVersion, "could not tell the version of Codex at "+e.show(in.exe), "codex --version"))
	default:
		if inR, ok := inRange(in.version, verified); ok && !inR {
			out = append(out, warn(CheckCodexVersion, fmt.Sprintf("Codex %s is outside the versions precinto was verified with (%s): its hooks and home layout may differ", in.version, verified),
				"use a verified Codex version, or check precinto's release notes for this one"))
		} else if min := e.minVersion(harness.Codex, "0.154.0"); in.version.compare(min) < 0 {
			out = append(out, warn(CheckCodexVersion, fmt.Sprintf("Codex %s is older than %s", in.version, min), "update Codex"))
		}
	}
	// New top-level entries of a per-root home: sealed (fail closed,
	// HA24), but a sign that the layout changed.
	for _, h := range e.codexHomes() {
		es, err := listDir(h.dir)
		if err != nil {
			continue
		}
		var unknown []string
		for _, en := range es {
			n := en.Name()
			if knownCodexTop[n] || strings.HasPrefix(n, ".") {
				continue
			}
			// A directory (or the plugins/ and skills/ links PrepareHome
			// makes) is known when a file inside it is: never-touch globs
			// name directories as dir/**.
			if e.d.CodexClassify(n) == codex.ClassContent && e.d.CodexClassify(n+"/x") == codex.ClassContent && !looksLikeCodexData(n) {
				unknown = append(unknown, n)
			}
		}
		if len(unknown) > 0 {
			out = append(out, info(CheckCodexVersion, "the sealed Codex home of "+e.folder(h.root)+" has entries precinto does not know ("+joinNames(unknown)+"); they are sealed with the rest (HA24)", ""))
		}
	}
	if len(out) == 0 {
		out = append(out, ok(CheckCodexVersion, fmt.Sprintf("Codex %s is a verified version", in.version)))
	}
	return out
}

// looksLikeCodexData recognises the content files Codex 0.154 writes at the
// top of its home (SQLite databases and their side files).
func looksLikeCodexData(name string) bool {
	return strings.Contains(name, ".sqlite")
}

func checkCodexHooksTrust(e *env) []Finding {
	if !e.codexPresent() {
		return nil
	}
	var out []Finding
	trustedN := 0
	for _, h := range e.codexHomes() {
		trusted, known, err := e.d.CodexHooksTrusted(h.dir)
		switch {
		case err != nil || !known:
			out = append(out, info(CheckCodexHooksTrust, "could not tell whether Codex trusts precinto's hooks in the sealed Codex home of "+e.folder(h.root), ""))
		case !trusted:
			out = append(out, warn(CheckCodexHooksTrust, "Codex has not trusted precinto's hooks in the sealed Codex home of "+e.folder(h.root)+", so it does not pause prompts when the folder locks (its history is still sealed when Codex exits)",
				`in that folder run precinto run codex, then /hooks, and trust "precinto"`))
		default:
			trustedN++
		}
	}
	if home := e.codexUserHome(); home != "" {
		trusted, known, err := e.d.CodexHooksTrusted(home)
		if err == nil && known && !trusted {
			out = append(out, warn(CheckCodexHooksTrust, "Codex has not trusted precinto's hooks in your own Codex home ("+e.show(home)+"), so Codex started there without precinto in a protected folder is not stopped (D31)",
				`run codex (outside precinto), then /hooks, and trust "precinto"`))
		} else if err == nil && known {
			trustedN++
		}
	}
	if len(out) == 0 && trustedN > 0 {
		out = append(out, ok(CheckCodexHooksTrust, "Codex trusts precinto's hooks"))
	}
	return out
}

func checkCodexShellNoise(e *env) []Finding {
	if !e.codexPresent() {
		return nil
	}
	shell := e.o.Env.Get("SHELL")
	if !filepath.IsAbs(shell) {
		shell = "/bin/sh" // what Codex falls back to
	}
	dir := e.home
	if dir == "" {
		dir = "/"
	}
	ctx, cancel := context.WithTimeout(e.ctx, shellTimeout)
	defer cancel()
	printed, took, err := e.d.RunShell(ctx, shell, e.o.Env.Environ(), dir)
	name := oneLine(filepath.Base(shell))
	switch {
	case e.ctx.Err() == nil && (ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded)):
		return []Finding{warn(CheckCodexShellNoise, fmt.Sprintf("%s -lc true did not finish within %s: Codex runs every hook through your login shell and gives SessionEnd 3 s", name, shellTimeout),
			"make your login profile start faster")}
	case printed > 0:
		return []Finding{warn(CheckCodexShellNoise, fmt.Sprintf("%s -lc true prints %s on stdout: Codex runs hooks through your login shell, and that output corrupts their answers (HA6)", name, plural(printed, "byte", "bytes")),
			"move whatever prints in your login profile behind an interactive-shell check, or send it to stderr")}
	case err != nil:
		return []Finding{info(CheckCodexShellNoise, fmt.Sprintf("%s -lc true failed, so Codex hooks may fail to start", name), "check that "+e.arg(shell)+" -lc true succeeds")}
	case took > slowShell:
		return []Finding{warn(CheckCodexShellNoise, fmt.Sprintf("%s -lc true takes %.1f s: Codex runs every hook through your login shell and gives SessionEnd 3 s", name, took.Seconds()),
			"make your login profile start faster")}
	}
	return []Finding{ok(CheckCodexShellNoise, name+" -lc true prints nothing")}
}

func checkCodexWrongHome(e *env) []Finding {
	home := e.codexUserHome()
	if home == "" {
		if e.codexPresent() {
			return []Finding{ok(CheckCodexWrongHome, "your own Codex home holds no conversations from protected folders")}
		}
		return nil
	}
	// Only folders that protect Codex count (D72); the first-line reader is
	// the codex adapter's (CC-18).
	cfg := e.o.Cfg
	cfg.Roots = nil
	for _, r := range e.o.Cfg.Roots {
		if rootProtects(r, harness.Codex) {
			cfg.Roots = append(cfg.Roots, r)
		}
	}
	counts, err := codex.WrongHomeRollouts(e.ctx, home, cfg)
	if err != nil && e.ctx.Err() == nil {
		return []Finding{info(CheckCodexWrongHome, "could not list the conversations in "+e.show(home)+" ("+errClass(err)+")", "")}
	}
	unknown := counts[""]
	var out []Finding
	for _, r := range e.o.Cfg.Roots {
		if n := counts[r.ID]; n > 0 {
			out = append(out, warn(CheckCodexWrongHome, codexWrongHomeText(n, e.folder(r)), "precinto run codex"))
		}
	}
	if unknown > 0 {
		out = append(out, info(CheckCodexWrongHome, plural(unknown, "conversation", "conversations")+" in "+e.show(home)+" could not be checked (the first line is unreadable or too long)", ""))
	}
	if len(out) == 0 {
		out = append(out, ok(CheckCodexWrongHome, "your own Codex home holds no conversations from protected folders"))
	}
	return out
}

func checkCodexOutsideRuns(e *env) []Finding {
	homes := e.codexHomes()
	if len(homes) == 0 {
		return nil
	}
	salt, _ := e.nameSalt()
	queued := e.queuedCodexRoots()
	var out []Finding
	for _, h := range homes {
		if e.unlocked(h.root.ID) {
			continue // a folder in use: its home is expected to be plaintext
		}
		files, err := e.rolloutFiles(h.dir)
		if err != nil || len(files) == 0 {
			continue
		}
		key := ""
		if salt != nil {
			key, _ = harness.UnitKeyFor(salt, capsule.KindCodexHome, harness.Codex, "", h.root.ID, "")
		}
		if e.codexHomeInUse(h.dir, key) || queued[h.root.ID] {
			continue // a precinto run is active, or its seal is queued
		}
		covered := map[string]bool{}
		if key != "" {
			if rc, okR, err := e.d.Receipt(key); err == nil && okR {
				for _, f := range rc.Files {
					if f.Base == capsule.BaseCodexHome {
						covered[f.Rel] = true
					}
				}
			}
		}
		n := 0
		for _, f := range files {
			rel, err := filepath.Rel(h.dir, f)
			if err != nil || covered[filepath.ToSlash(rel)] {
				continue
			}
			n++
		}
		if n > 0 {
			out = append(out, warn(CheckCodexOutsideRuns, plural(n, "Codex conversation", "Codex conversations")+" in the sealed Codex home of "+e.folder(h.root)+" "+verb(n, "has", "have")+" no matching sealed copy and no precinto run is active: Codex may have run there without precinto (R12)",
				"precinto sweep seals them; if precinto run codex then refuses, choose a side: precinto codex reconcile --root "+e.arg(h.root.Path)+" --prefer capsule|plaintext"))
		}
	}
	if len(out) == 0 {
		out = append(out, ok(CheckCodexOutsideRuns, "the sealed Codex homes hold no conversations written outside precinto"))
	}
	return out
}

// codexHomeInUse reports whether a precinto run holds a per-root home: its
// launch lease is held (SPEC §9.3), or a process has files open below it.
// Any doubt counts as in use, so doctor never calls a live run an outside
// one.
func (e *env) codexHomeInUse(dir, key string) bool {
	if key != "" {
		held, err := e.d.LeaseHeld(key)
		if err != nil || held {
			return true
		}
	}
	if e.o.Procs == nil {
		return true
	}
	ctx, cancel := e.bounded()
	defer cancel()
	hs, err := e.o.Procs.OpenFilesUnder(ctx, []string{dir})
	return err != nil || len(hs) > 0
}

// queuedCodexRoots returns the roots whose Codex home has a pending seal
// request (the run ended and its seal waits for the writer to finish).
func (e *env) queuedCodexRoots() map[string]bool {
	out := map[string]bool{}
	if !isDir(e.o.Layout.QueueDir) {
		return out
	}
	reqs, err := e.d.QueueList()
	if err != nil {
		return out
	}
	for _, r := range reqs {
		if r.Harness != string(harness.Codex) {
			continue
		}
		if root, ok := e.rootFor(r.Cwd, harness.Codex); ok {
			out[root.ID] = true
		}
		if root, ok := e.homeRoot(r.ConfigDir); ok {
			out[root.ID] = true
		}
	}
	return out
}

// homeRoot maps a per-root Codex home directory to its root.
func (e *env) homeRoot(dir string) (config.Root, bool) {
	if dir == "" {
		return config.Root{}, false
	}
	for _, r := range e.o.Cfg.Roots {
		if filepath.Clean(dir) == e.o.Layout.CodexHome(r.ID) {
			return r, true
		}
	}
	return config.Root{}, false
}
