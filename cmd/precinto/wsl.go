package main

import (
	"errors"
	"path/filepath"
	"slices"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/ui"
)

// Windows through WSL 2 (D155, D156): the CLI's refusals. precinto runs in
// a WSL 2 distribution as on linux, but refuses WSL 1 wherever it would set
// up or rely on protection, and refuses locations on a Windows drive and
// harness executables that would run as Windows programs: Windows
// programs write such files, or run such sessions, without precinto
// seeing them.

// refuseWSL1 reports whether the command must stop because this
// distribution runs under WSL 1, which emulates linux in the Windows
// kernel (no real /proc for the holders check, no pidfd, Windows writers
// to every file): it prints E.wsl1 with the conversion command. init,
// protect, unlock, run (and resume), integrate, the agent, and seal and
// sweep, which delete plaintext after a liveness check, call it.
func (a *app) refuseWSL1() bool {
	if a.sys.wsl().Version != 1 {
		return false
	}
	a.line(ui.MsgWSL1, ui.Vars{Command: wslConvertCommand(a.env)})
	return true
}

// wslConvertCommand is the Windows command that converts this
// distribution to WSL 2, named when WSL_DISTRO_NAME names it (the
// environment only fills the message, it decides nothing).
func wslConvertCommand(e paths.Env) string {
	name := e.Get("WSL_DISTRO_NAME")
	if name == "" || len(name) > 64 || !plainName(name) {
		name = "<distro>"
	}
	return "wsl --set-version " + name + " 2"
}

// plainName reports a name made of letters, digits, '.', '_' and '-'.
func plainName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// claudeEnvDirs returns Claude's config, tmp and cache folders as Claude
// uses them in this environment (SPEC §7.0), unresolved and whether or not
// they exist: CLAUDE_CONFIG_DIR or ~/.claude, CLAUDE_CODE_TMPDIR or
// claude.TmpBase, and the cache. def reports the default config folder.
// An entry precinto cannot name is "".
func (a *app) claudeEnvDirs() (dir, tmp, cache string, def bool) {
	return claude.EnvDirs(a.env, a.sys.goos, a.sys.uid(), a.home())
}

// harnessDriveDirs lists the harness homes of this environment that the
// listed harnesses would write: Claude's config, tmp and cache folders,
// and the user's Codex home (CODEX_HOME or ~/.codex), which a folder's
// sealed Codex home is seeded from.
func (a *app) harnessDriveDirs(harnesses []string) []string {
	var out []string
	if slices.Contains(harnesses, string(harness.ClaudeCode)) {
		dir, tmp, cache, _ := a.claudeEnvDirs()
		for _, d := range []string{dir, tmp, cache} {
			if d != "" {
				out = append(out, d)
			}
		}
	}
	if slices.Contains(harnesses, string(harness.Codex)) {
		if h, err := codex.UserHome(a.env); err == nil && filepath.IsAbs(h) {
			out = append(out, h)
		}
	}
	return out
}

// checkHarnessDrives refuses, under WSL, harness homes on a Windows drive
// for the listed harnesses (D156): the *paths.DriveError of the first one.
func (a *app) checkHarnessDrives(harnesses []string) error {
	for _, d := range a.harnessDriveDirs(harnesses) {
		if err := a.sys.checkDrive(d); err != nil {
			return err
		}
	}
	return nil
}

// sayDrive prints the refusal of a location on a Windows drive (D156),
// or of one precinto could not place, with what stopped it.
func (a *app) sayDrive(de *paths.DriveError) {
	if de.Unknown {
		a.line(ui.MsgWindowsDriveUnsure, ui.Vars{Folder: a.display(de.Path), Cause: driveWhy(de)})
		return
	}
	a.line(ui.MsgWindowsDrive, ui.Vars{Folder: a.display(de.Path)})
}

// sayOnDrive prints E.windrive (or E.windrive.unsure) for every protected
// folder and every registered Claude config folder on a Windows drive
// (D156): a seal leaves the folder's notes in plaintext, a restore leaves
// their capsules sealed. It reports whether it printed one.
func (a *app) sayOnDrive() bool {
	cfg, err := a.config()
	if err != nil {
		return false
	}
	var dirs []string
	for _, r := range cfg.Roots {
		dirs = append(dirs, r.Path)
	}
	for _, h := range cfg.Harness[string(harness.ClaudeCode)].Homes {
		dirs = append(dirs, h.Dir)
	}
	printed := false
	seen := map[string]bool{}
	for _, d := range dirs {
		if !filepath.IsAbs(d) || seen[d] {
			continue
		}
		seen[d] = true
		var de *paths.DriveError
		if errors.As(a.sys.checkDrive(d), &de) {
			a.sayDrive(de)
			printed = true
		}
	}
	return printed
}

// driveWhy is the {cause} of an unknown drive verdict.
func driveWhy(de *paths.DriveError) string {
	if de.Why != "" {
		return de.Why
	}
	return "precinto could not read where it lies"
}

// sayProgram prints the refusal of a harness executable that would run as
// a Windows program (D156), or that precinto could not check: the program
// it runs, from a "#!" or env line the user's programs can write, is
// displayed like any path (S17), never echoed raw.
func (a *app) sayProgram(pe *harness.ProgramError) {
	h := harnessCommand(string(pe.Harness))
	if h == "" {
		h = "the harness"
	}
	cause := pe.Why
	if pe.Runs != "" {
		cause = "runs " + a.display(pe.Runs) + ", which " + pe.Why
	}
	id := ui.MsgWindowsProgram
	if pe.Unknown {
		id = ui.MsgWinProgramUnsure
	}
	a.line(id, ui.Vars{File: a.display(pe.Exe), Cause: cause, Harness: h})
}

// wslStatus is what status reports under WSL (D155, D156): the facts for
// --json and the human summary, and attention items, with doctor's codes,
// for WSL 1, Windows interoperability on and every location of precinto,
// of a protected folder or of a harness on a Windows drive (doctor
// explains each). claudeGap reports a Claude folder among them: its
// sessions' files are never scanned, so status cannot count them and
// --check cannot pass. Outside WSL it adds nothing.
func (a *app) wslStatus(cfg config.Config, l paths.Layout, local []ipc.Attention) (st *statusWSL, out []ipc.Attention, claudeGap bool) {
	w := a.sys.wsl()
	if w.Version == 0 {
		return nil, local, false
	}
	st = &statusWSL{Version: w.Version, Interop: "unknown", MountRoot: w.MountRoot}
	switch {
	case w.Interop:
		st.Interop = "on"
	case w.InteropKnown:
		st.Interop = "off"
	}
	if w.Version == 1 {
		local = append(local, ipc.Attention{Code: doctor.CheckWSL, Detail: textWSL1Detail, Fix: wslConvertCommand(a.env)})
	}
	if w.Interop {
		local = append(local, ipc.Attention{Code: doctor.CheckWSLInterop, Detail: textInteropDetail, Fix: textInteropFix})
	}
	claudeDirs := map[string]bool{}
	for _, p := range a.claudeDriveDirs(cfg, l) {
		claudeDirs[p] = true
	}
	for _, p := range a.driveLocations(cfg, l) {
		err := a.sys.checkDrive(p)
		if err == nil {
			continue
		}
		detail := textDriveDetail
		var de *paths.DriveError
		if errors.As(err, &de) && de.Unknown {
			detail = textDriveUnsure
		}
		claudeGap = claudeGap || claudeDirs[p]
		local = append(local, ipc.Attention{Code: doctor.CheckWindowsDrive, Folder: a.display(p), Detail: detail, Fix: "precinto doctor"})
	}
	return st, local, claudeGap
}

// driveLocations lists what must not lie on a Windows drive (D156), as
// doctor's windows-drive check does: precinto's data and run folders, the
// protected folders, and the homes of the harnesses they protect (the
// registered Claude folders and this environment's Claude folders and
// Codex home).
func (a *app) driveLocations(cfg config.Config, l paths.Layout) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && filepath.IsAbs(p) && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	add(l.Base)
	if !paths.Within(l.Base, l.RunDir) {
		add(l.RunDir)
	}
	var protects []string
	for _, r := range cfg.Roots {
		add(r.Path)
		hs := r.Harnesses
		if len(hs) == 0 {
			hs = []string{string(harness.ClaudeCode), string(harness.Codex)}
		}
		for _, h := range hs {
			if !slices.Contains(protects, h) {
				protects = append(protects, h)
			}
		}
	}
	if slices.Contains(protects, string(harness.ClaudeCode)) {
		for _, d := range a.claudeDriveDirs(cfg, l) {
			add(d)
		}
	}
	for _, d := range a.harnessDriveDirs(protects) {
		add(d)
	}
	return out
}

// claudeDriveDirs lists the Claude folders that must not lie on a Windows
// drive (D156), as doctor's windows-drive check does: the registered ones,
// this environment's, and the config and temporary folders hooks reported
// for Claude sessions (the ledger), which Claude really used.
func (a *app) claudeDriveDirs(cfg config.Config, l paths.Layout) []string {
	var out []string
	for _, h := range cfg.Harness[string(harness.ClaudeCode)].Homes {
		out = append(out, h.Dir, h.Tmp, h.Cache)
	}
	dir, tmp, cache, _ := a.claudeEnvDirs()
	out = append(out, dir, tmp, cache)
	if l.SessionsDir != "" {
		if ss, err := ledger.Open(l.SessionsDir).List(string(harness.ClaudeCode)); err == nil {
			for _, s := range ss {
				out = append(out, s.ConfigDirs...)
				out = append(out, s.TmpDirs...)
			}
		}
	}
	var clean []string
	for _, d := range out {
		if d != "" && filepath.IsAbs(d) {
			clean = append(clean, filepath.Clean(d))
		}
	}
	return clean
}
