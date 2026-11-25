package doctor

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Neorichi/precinto/internal/harness"
)

// Experimental (data-driven) harnesses: SPEC §7.3, D33.

// statusExperimental is the inventory status of every data-driven harness.
const statusExperimental = "experimental"

// checkExperimentalVersion is SPEC §7.3's warning for an installed
// experimental harness outside its inventory's verified_versions. It is
// informational: the range never enables or blocks sealing. The version is
// read without running the harness, as for the built-in ones (install.go):
// from a versioned install path or the package.json of an npm install. Only
// the harnesses precinto manages ([harness.<id>] enabled) are looked at, or
// the one `precinto doctor HARNESS` names; an inventory without a verified
// range has nothing to compare with.
func checkExperimentalVersion(e *env) []Finding {
	var out []Finding
	for _, id := range e.experimentalHarnesses() {
		inv, err := e.d.Inventory(id)
		if err != nil || inv.Status != statusExperimental {
			continue
		}
		verified := strings.TrimSpace(inv.VerifiedVersions)
		if _, ok := inRange(version{}, verified); !ok {
			continue
		}
		name := oneLine(inv.Name)
		if name == "" {
			name = oneLine(id)
		}
		exe := e.experimentalExecutable(id, inv)
		if exe == "" {
			out = append(out, info(CheckExperimentalVersion, "the "+name+" executable was not found, so its version was not checked", ""))
			continue
		}
		v, known := versionOfExecutable(exe, "")
		if !known {
			out = append(out, info(CheckExperimentalVersion, "could not tell the version of "+name+" at "+e.show(exe), ""))
			continue
		}
		if in, _ := inRange(v, verified); !in {
			out = append(out, warn(CheckExperimentalVersion, fmt.Sprintf("%s %s is outside the versions precinto's experimental support for it was verified with (%s): the files it keeps may have changed, so check what precinto seals for it (sealing is not affected)", name, v, verified),
				"use a verified version of "+name+", or check precinto's release notes for this one"))
			continue
		}
		out = append(out, ok(CheckExperimentalVersion, fmt.Sprintf("%s %s is a version precinto's experimental support was verified with", name, v)))
	}
	return out
}

// experimentalHarnesses lists the ids of the embedded data-driven
// inventories to check: the one Options.Harness names, else every one
// enabled in config.toml, in order.
func (e *env) experimentalHarnesses() []string {
	ids := inventoryIDs()
	delete(ids, string(harness.ClaudeCode))
	delete(ids, string(harness.Codex))
	if h := strings.TrimSpace(e.o.Harness); h != "" {
		if ids[h] {
			return []string{h}
		}
		return nil // a built-in harness was named
	}
	var out []string
	for id := range ids {
		if e.o.Cfg.Harness[id].Enabled {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// experimentalExecutable finds the executable of a data-driven harness: the
// configured binary, else the first of the inventory's executable names on
// PATH or in the usual install locations.
func (e *env) experimentalExecutable(id string, inv harness.Inventory) string {
	bin := e.o.Cfg.Harness[id].Bin
	names := inv.Process.ExeBasenames
	if len(names) == 0 && filepath.IsAbs(bin) {
		names = []string{filepath.Base(bin)}
	}
	for _, n := range names {
		if n == "" || strings.ContainsRune(n, '/') {
			continue
		}
		if exe := e.findExecutable(n, bin); exe != "" {
			return exe
		}
	}
	return ""
}
