package doctor_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/doctor"
	"github.com/Neorichi/precinto/internal/harness"
)

// geminiInventory is an experimental inventory with a verified range.
func geminiInventory(verified string) harness.Inventory {
	return harness.Inventory{Schema: 1, ID: "gemini", Name: "Gemini CLI", Status: "experimental", VerifiedVersions: verified,
		Process: harness.ProcessMatch{ExeBasenames: []string{"gemini"}}}
}

// experimental enables a data-driven harness in the fixture's config and
// serves inv as its inventory (the built-in ones stay unreadable, as in
// every unit test).
func (f *fixture) experimental(inv harness.Inventory, enabled bool) {
	f.t.Helper()
	hs := map[string]config.Harness{}
	for k, v := range f.o.Cfg.Harness {
		hs[k] = v
	}
	hs[inv.ID] = config.Harness{Enabled: enabled, Experimental: true}
	f.o.Cfg.Harness = hs
	f.d.Inventory = func(id string) (harness.Inventory, error) {
		if id == inv.ID {
			return inv, nil
		}
		return harness.Inventory{}, errors.New("no inventory")
	}
}

// npmGemini installs a fake npm Gemini CLI of version v and puts its bin
// directory on PATH.
func (f *fixture) npmGemini(v string) {
	f.t.Helper()
	dir := filepath.Join(f.h.Dir, "npm-"+v)
	pkg := filepath.Join(dir, "lib", "node_modules", "@google", "gemini-cli")
	js := writeFile(f.t, filepath.Join(pkg, "dist", "index.js"), "#!/usr/bin/env node\n", 0o700)
	writeJSON(f.t, filepath.Join(pkg, "package.json"), map[string]string{"name": "@google/gemini-cli", "version": v})
	bin := mkdir(f.t, filepath.Join(dir, "bin"), 0o700)
	if err := os.Symlink(js, filepath.Join(bin, "gemini")); err != nil {
		f.t.Fatal(err)
	}
	f.setEnv("PATH", bin)
}

// TestExperimentalVersion (SPEC §7.3, CC-44): an installed experimental
// harness outside its inventory's verified_versions is a warning; inside
// it is fine; an unknown version or a missing executable is a note; a
// harness precinto does not manage, or an inventory without a range, is
// not looked at.
func TestExperimentalVersion(t *testing.T) {
	f := newFixture(t)
	none(t, f.run(), doctor.CheckExperimentalVersion)

	f.experimental(geminiInventory(">=0.10.0 <0.11.0"), true)
	f.setEnv("PATH", filepath.Join(f.h.Dir, "empty-bin"))
	got := want(t, f.run(), doctor.CheckExperimentalVersion, doctor.Info, "the Gemini CLI executable was not found")
	if got.Fix != "" {
		t.Errorf("fix %q", got.Fix)
	}
	f.npmGemini("0.12.0")
	got = want(t, f.run(), doctor.CheckExperimentalVersion, doctor.Warn, "Gemini CLI 0.12.0 is outside the versions", "(>=0.10.0 <0.11.0)", "sealing is not affected")
	if got.Fix == "" {
		t.Error("no fix")
	}
	f.npmGemini("0.10.3")
	want(t, f.run(), doctor.CheckExperimentalVersion, doctor.OK, "Gemini CLI 0.10.3")

	// A versioned install path (Homebrew keg), found through [harness].bin.
	keg := writeFile(t, filepath.Join(f.h.Dir, "Cellar", "gemini-cli", "0.9.0", "bin", "gemini"), "#!/bin/sh\n", 0o700)
	f.setEnv("PATH", "/nonexistent")
	hc := f.o.Cfg.Harness["gemini"]
	hc.Bin = keg
	f.o.Cfg.Harness["gemini"] = hc
	want(t, f.run(), doctor.CheckExperimentalVersion, doctor.Warn, "Gemini CLI 0.9.0 is outside")

	// A script whose version cannot be told.
	hc.Bin = writeFile(t, filepath.Join(f.h.Dir, "plain", "gemini"), "#!/bin/sh\n", 0o700)
	f.o.Cfg.Harness["gemini"] = hc
	want(t, f.run(), doctor.CheckExperimentalVersion, doctor.Info, "could not tell the version of Gemini CLI")

	// Not managed by precinto: not looked at, unless named on the command
	// line; a built-in harness named on the command line skips it.
	g := newFixture(t)
	g.experimental(geminiInventory(">=0.10.0 <0.11.0"), false)
	g.npmGemini("0.12.0")
	none(t, g.run(), doctor.CheckExperimentalVersion)
	g.o.Harness = "gemini"
	want(t, g.run(), doctor.CheckExperimentalVersion, doctor.Warn, "Gemini CLI 0.12.0 is outside")
	g.o.Harness = "codex"
	none(t, g.run(), doctor.CheckExperimentalVersion)

	// Nothing to compare with: an empty range, or a verified inventory.
	h := newFixture(t)
	h.experimental(geminiInventory(""), true)
	h.npmGemini("0.12.0")
	none(t, h.run(), doctor.CheckExperimentalVersion)
	inv := geminiInventory(">=0.10.0 <0.11.0")
	inv.Status = "verified"
	h.experimental(inv, true)
	none(t, h.run(), doctor.CheckExperimentalVersion)
}

func TestNPMVersionWithoutPackageName(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "lib", "node_modules", "@qwen-code", "qwen-code")
	cli := writeFile(t, filepath.Join(pkg, "cli.js"), "#!/usr/bin/env node\n", 0o700)
	writeJSON(t, filepath.Join(pkg, "package.json"), map[string]string{"name": "@qwen-code/qwen-code", "version": "0.4.1"})
	if v, ok := doctor.VersionOfExecutable(cli, ""); !ok || v != "0.4.1" {
		t.Errorf("scoped package: %q %v", v, ok)
	}
	plain := filepath.Join(dir, "lib", "node_modules", "opencode-ai")
	bin := writeFile(t, filepath.Join(plain, "bin", "opencode"), "#!/usr/bin/env node\n", 0o700)
	writeJSON(t, filepath.Join(plain, "package.json"), map[string]string{"name": "opencode-ai", "version": "1.2.3"})
	if v, ok := doctor.VersionOfExecutable(bin, ""); !ok || v != "1.2.3" {
		t.Errorf("package: %q %v", v, ok)
	}
	// A named package must match its package.json.
	if _, ok := doctor.VersionOfExecutable(bin, "other-package"); ok {
		t.Error("another package's version was taken")
	}
}
