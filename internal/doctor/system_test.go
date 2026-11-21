package doctor_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/testkit"
)

func TestDiskEncryption(t *testing.T) {
	cases := []struct {
		on, known bool
		err       error
		sev       doctor.Severity
		part      string
	}{
		{true, true, nil, doctor.OK, "FileVault is on"},
		{false, true, nil, doctor.Warn, "FileVault is off"},
		{false, false, nil, doctor.Info, "could not tell"},
		{true, true, errors.New("fdesetup failed"), doctor.Info, "could not tell"},
	}
	for _, c := range cases {
		f := newFixture(t)
		f.d.GOOS = "darwin"
		f.d.DiskEncryption = func(context.Context) (bool, bool, error) { return c.on, c.known, c.err }
		got := want(t, f.run(), doctor.CheckDiskEncryption, c.sev, c.part)
		if c.sev != doctor.OK && !strings.Contains(got.Fix, "FileVault") {
			t.Errorf("fix %q does not name FileVault", got.Fix)
		}
	}
	f := newFixture(t)
	f.d.GOOS = "linux"
	f.d.DiskEncryption = func(context.Context) (bool, bool, error) { return false, true, nil }
	got := want(t, f.run(), doctor.CheckDiskEncryption, doctor.Warn, "disk encryption is off")
	if !strings.Contains(got.Fix, "encrypted volume") {
		t.Errorf("linux fix %q", got.Fix)
	}
}

func TestUnhardenedBuild(t *testing.T) {
	dir := t.TempDir()
	hardened := writeBinary(t, dir, "hardened", thinMachO(cpuARM64, superBlob(csRuntime)))
	adhoc := writeBinary(t, dir, "adhoc", thinMachO(cpuARM64, superBlob(csAdhoc|csLinkerSigned)))
	unsigned := writeBinary(t, dir, "unsigned", thinMachO(cpuARM64, nil))
	script := writeBinary(t, dir, "script", []byte("#!/bin/sh\n"))

	run := func(exe string, goos string) []doctor.Finding {
		f := newFixture(t)
		f.d.GOOS = goos
		f.d.Executable = func() (string, error) { return exe, nil }
		return f.run()
	}
	want(t, run(hardened, "darwin"), doctor.CheckUnhardenedBuild, doctor.OK)
	want(t, run(adhoc, "darwin"), doctor.CheckUnhardenedBuild, doctor.Warn, "signed without the hardened runtime")
	want(t, run(unsigned, "darwin"), doctor.CheckUnhardenedBuild, doctor.Warn, "not code-signed")
	want(t, run(script, "darwin"), doctor.CheckUnhardenedBuild, doctor.Info, "could not read the code signature")
	none(t, run(adhoc, "linux"), doctor.CheckUnhardenedBuild)

	// The pinned link the hooks run is checked as well.
	f := newFixture(t)
	f.d.GOOS = "darwin"
	f.d.Executable = func() (string, error) { return hardened, nil }
	if err := os.MkdirAll(filepath.Dir(f.h.Layout.BinLink), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(unsigned, f.h.Layout.BinLink); err != nil {
		t.Fatal(err)
	}
	want(t, f.run(), doctor.CheckUnhardenedBuild, doctor.Warn, "unsigned is not code-signed")
}

func TestLoaderEnv(t *testing.T) {
	f := newFixture(t)
	want(t, f.run(), doctor.CheckLoaderEnv, doctor.OK)

	value := testkit.Marker(t)
	f.secret(value)
	f.setEnv("DYLD_INSERT_LIBRARIES", "/tmp/"+value+".dylib", "LD_LIBRARY_PATH", value)
	got := want(t, f.run(), doctor.CheckLoaderEnv, doctor.Fail, "DYLD_INSERT_LIBRARIES, LD_LIBRARY_PATH")
	if !strings.Contains(got.Fix, "unset DYLD_INSERT_LIBRARIES LD_LIBRARY_PATH") {
		t.Errorf("fix %q", got.Fix)
	}

	g := newFixture(t)
	g.setEnv("LD_LIBRARY_PATH", "/opt/lib")
	want(t, g.run(), doctor.CheckLoaderEnv, doctor.Warn, "LD_LIBRARY_PATH")
}

func TestCloudSync(t *testing.T) {
	f := newFixture(t)
	fs := f.run()
	want(t, fs, doctor.CheckBaseSynced, doctor.OK)
	want(t, fs, doctor.CheckCloudRoot, doctor.OK)

	f.d.CloudSynced = func(p string) bool { return p == f.h.Base || p == f.h.Root }
	fs = f.run()
	want(t, fs, doctor.CheckBaseSynced, doctor.Fail, "cloud-synced", "Codex homes")
	want(t, fs, doctor.CheckCloudRoot, doctor.Warn, f.tilde(f.h.Root)+" is in a cloud-synced folder")
}

func TestSpotlight(t *testing.T) {
	f := newFixture(t)
	f.d.GOOS = "darwin"
	other := f.h.Protect(t, "work/beta")
	f.o.Cfg = f.h.Cfg
	f.d.SpotlightIndexed = func(_ context.Context, p string) (bool, bool, error) {
		if p == other.Path {
			return false, false, nil
		}
		return true, true, nil
	}
	fs := f.run()
	got := want(t, fs, doctor.CheckSpotlight, doctor.Warn, "Spotlight indexes "+f.tilde(f.h.Root))
	if !strings.Contains(got.Fix, "Spotlight Privacy") {
		t.Errorf("fix %q", got.Fix)
	}
	want(t, fs, doctor.CheckSpotlight, doctor.Info, f.tilde(other.Path))

	f.d.GOOS = "linux"
	none(t, f.run(), doctor.CheckSpotlight)
}

func TestBackups(t *testing.T) {
	f := newFixture(t)
	f.d.GOOS = "darwin"
	f.d.BackupExcluded = func(_ context.Context, p string) (bool, bool, error) { return p != f.h.ClaudeConfig, true, nil }
	got := want(t, f.run(), doctor.CheckBackups, doctor.Warn, "Time Machine backs up "+f.h.ClaudeConfig)
	if got.Fix != "tmutil addexclusion "+f.h.ClaudeConfig {
		t.Errorf("fix %q", got.Fix)
	}
	f.d.BackupExcluded = func(context.Context, string) (bool, bool, error) { return false, false, errors.New("tmutil failed") }
	want(t, f.run(), doctor.CheckBackups, doctor.Info, "could not tell")
	// No backup destination (platform.BackupExcluded: known=false, no
	// error): nothing is backed up.
	f.d.BackupExcluded = func(context.Context, string) (bool, bool, error) { return false, false, nil }
	want(t, f.run(), doctor.CheckBackups, doctor.OK, "Time Machine does not back up")
	f.d.GOOS = "linux"
	none(t, f.run(), doctor.CheckBackups)
}

func TestTerminalResidue(t *testing.T) {
	f := newFixture(t)
	f.d.GOOS = "darwin"
	saved := mkdir(t, filepath.Join(f.h.HomeDir, "Library", "Saved Application State", "com.googlecode.iterm2.savedState"), 0o700)
	none(t, f.run(), doctor.CheckTerminalResidue) // only with --leaks
	f.o.Leaks = true
	fs := f.run()
	want(t, fs, doctor.CheckTerminalResidue, doctor.Warn, "iTerm2 keeps copies of terminal contents in "+f.tilde(saved))

	g := newFixture(t)
	g.d.GOOS = "linux"
	g.o.Leaks = true
	want(t, g.run(), doctor.CheckTerminalResidue, doctor.OK)
	tmux := mkdir(t, filepath.Join(g.h.HomeDir, ".tmux", "resurrect"), 0o700)
	want(t, g.run(), doctor.CheckTerminalResidue, doctor.Warn, "tmux-resurrect", g.tilde(tmux))
	mkdir(t, filepath.Join(g.h.HomeDir, "Library", "Saved Application State", "com.apple.Terminal.savedState"), 0o700)
	for _, x := range of(g.run(), doctor.CheckTerminalResidue) {
		if strings.Contains(x.Message, "Terminal keeps") {
			t.Errorf("macOS store reported on linux: %q", x.Message) // macOS stores only on darwin
		}
	}
}
