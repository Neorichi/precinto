package doctor

import (
	"path/filepath"
)

// Terminal residue (doctor --leaks; SPEC §19 "Residue outside the
// inventory"): terminal programs that keep copies of what was on screen.
// Only the existence of their stores is checked; nothing in them is read.

type residueStore struct {
	rel  string // relative to $HOME
	app  string
	fix  string
	mac  bool // a macOS location
	pane bool // holds pane or window contents
}

var terminalStores = []residueStore{
	{rel: "Library/Saved Application State/com.googlecode.iterm2.savedState", app: "iTerm2", mac: true, pane: true,
		fix: "turn off iTerm2 > Settings > General > Startup > window restoration, or System Settings > Desktop & Dock > Close windows when quitting an application"},
	{rel: "Library/Application Support/iTerm2/SavedState", app: "iTerm2", mac: true, pane: true,
		fix: "turn off iTerm2 > Settings > General > Startup > window restoration"},
	{rel: "Library/Saved Application State/com.apple.Terminal.savedState", app: "Terminal", mac: true, pane: true,
		fix: "turn on System Settings > Desktop & Dock > Close windows when quitting an application"},
	{rel: "Library/Saved Application State/dev.warp.Warp-Stable.savedState", app: "Warp", mac: true,
		fix: "turn off session restoration in Warp's settings"},
	{rel: ".tmux/resurrect", app: "tmux-resurrect", pane: true,
		fix: "turn off @resurrect-capture-pane-contents, or remove the saved files"},
	{rel: ".local/share/tmux/resurrect", app: "tmux-resurrect", pane: true,
		fix: "turn off @resurrect-capture-pane-contents, or remove the saved files"},
}

func checkTerminalResidue(e *env) []Finding {
	if e.home == "" {
		return nil
	}
	var out []Finding
	for _, s := range terminalStores {
		if s.mac && e.d.GOOS != "darwin" {
			continue
		}
		p := filepath.Join(e.home, filepath.FromSlash(s.rel))
		if !exists(p) {
			continue
		}
		what := "a saved state"
		if s.pane {
			what = "copies of terminal contents"
		}
		out = append(out, warn(CheckTerminalResidue, s.app+" keeps "+what+" in "+e.show(p)+": text shown while a folder was unlocked may be there (SPEC §19)", s.fix))
	}
	if x := e.o.Env.Get("XDG_DATA_HOME"); filepath.IsAbs(x) {
		p := filepath.Join(filepath.Clean(x), "tmux", "resurrect")
		if exists(p) && filepath.Clean(x) != filepath.Join(e.home, ".local", "share") {
			out = append(out, warn(CheckTerminalResidue, "tmux-resurrect keeps copies of terminal contents in "+e.show(p)+": text shown while a folder was unlocked may be there (SPEC §19)",
				"turn off @resurrect-capture-pane-contents, or remove the saved files"))
		}
	}
	if len(out) == 0 {
		out = append(out, ok(CheckTerminalResidue, "no terminal restoration store was found"))
	}
	return out
}
