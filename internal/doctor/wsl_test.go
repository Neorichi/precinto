package doctor_test

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/paths"
)

var wslCodes = []string{doctor.CheckWSL, doctor.CheckWSLInterop, doctor.CheckWSLIdle, doctor.CheckWindowsDrive, doctor.CheckWindowsHarnessData}

// Outside WSL the WSL checks find nothing (D155).
func TestWSLChecksSilentOutsideWSL(t *testing.T) {
	f := newFixture(t)
	f.o.Leaks = true
	fs := f.run()
	for _, c := range wslCodes {
		none(t, fs, c)
	}
}

// D155, D156: WSL 1 fails; WSL 2 is ok, interop on warns, the idle
// shutdown is reported, and disk encryption is unknown with a BitLocker
// hint.
func TestWSLVersionAndInterop(t *testing.T) {
	f := newFixture(t)
	f.d.WSL = func() paths.WSL { return paths.WSL{Version: 1, MountRoot: "/mnt/"} }
	f.d.DiskEncryption = func(context.Context) (bool, bool, error) { return false, false, nil }
	fs := f.run()
	x := want(t, fs, doctor.CheckWSL, doctor.Fail, "WSL 1")
	if x.Fix == "" || !strings.Contains(x.Fix, "wsl --set-version <distro> 2") {
		t.Errorf("WSL 1 fix: %q", x.Fix)
	}
	none(t, fs, doctor.CheckWSLIdle)

	f.d.WSL = func() paths.WSL { return paths.WSL{Version: 2, Interop: true, InteropKnown: true, MountRoot: "/mnt/"} }
	fs = f.run()
	want(t, fs, doctor.CheckWSL, doctor.OK, "WSL 2")
	x = want(t, fs, doctor.CheckWSLInterop, doctor.Warn, "/etc/wsl.conf", "wsl.exe", "superuser", "unlocked folders")
	if !strings.Contains(x.Fix, "[interop]") || !strings.Contains(x.Fix, "enabled=false") {
		t.Errorf("interop fix: %q", x.Fix)
	}
	x = want(t, fs, doctor.CheckWSLIdle, doctor.Info, "instanceIdleTimeout", "sealed only when precinto runs again")
	if !strings.Contains(x.Fix, "instanceIdleTimeout=-1") || !strings.Contains(x.Fix, "[general]") {
		t.Errorf("idle fix: %q", x.Fix)
	}
	x = want(t, fs, doctor.CheckDiskEncryption, doctor.Info, "virtual disk file on a Windows drive")
	if !strings.Contains(x.Fix, "BitLocker") {
		t.Errorf("disk encryption fix: %q", x.Fix)
	}

	// Off is what wsl.conf says, which applies once WSL restarted: the
	// text names the setting and never claims more.
	f.d.WSL = func() paths.WSL { return paths.WSL{Version: 2, InteropKnown: true, MountRoot: "/mnt/"} }
	want(t, f.run(), doctor.CheckWSLInterop, doctor.OK, "off", "/etc/wsl.conf", "enabled=false", "wsl --shutdown")
	f.d.WSL = func() paths.WSL { return paths.WSL{Version: 2, MountRoot: "/mnt/"} }
	want(t, f.run(), doctor.CheckWSLInterop, doctor.Info, "could not tell", "/etc/wsl.conf could not be read")
}

// D156: precinto's folders, the protected folders and the harness homes
// must not be on a Windows drive; a location precinto cannot place counts
// as one.
func TestWindowsDrive(t *testing.T) {
	f := newFixture(t)
	f.d.WSL = func() paths.WSL { return paths.WSL{Version: 2, InteropKnown: true, MountRoot: "/mnt/"} }
	want(t, f.run(), doctor.CheckWindowsDrive, doctor.OK, "no protected folder")

	var onDrive, unsure []string
	f.d.CheckDrive = func(p string) error {
		for _, d := range onDrive {
			if paths.Within(d, p) {
				return &paths.DriveError{Path: p}
			}
		}
		for _, d := range unsure {
			if paths.Within(d, p) {
				return &paths.DriveError{Path: p, Unknown: true, Why: "it or a folder above it can't be read", Err: fs.ErrPermission}
			}
		}
		return nil
	}
	onDrive = []string{f.h.Layout.Base, f.h.Root, f.h.ClaudeConfig}
	unsure = []string{f.h.ClaudeTmp}
	codexHome := filepath.Join(f.h.HomeDir, "win-codex")
	f.setEnv("CODEX_HOME", codexHome)
	onDrive = append(onDrive, codexHome)
	fs := f.run()
	x := want(t, fs, doctor.CheckWindowsDrive, doctor.Fail, "precinto's data folder", f.tilde(f.h.Layout.Base), "is on a Windows drive")
	if !strings.Contains(x.Fix, "XDG_DATA_HOME") {
		t.Errorf("base fix: %q", x.Fix)
	}
	want(t, fs, doctor.CheckWindowsDrive, doctor.Fail, "the protected folder "+f.tilde(f.h.Root))
	want(t, fs, doctor.CheckWindowsDrive, doctor.Fail, "Claude's config folder "+f.tilde(f.h.ClaudeConfig))
	want(t, fs, doctor.CheckWindowsDrive, doctor.Fail, "could not tell whether Claude's temporary folder", "(it or a folder above it can't be read)")
	want(t, fs, doctor.CheckWindowsDrive, doctor.Fail, "Codex's folder "+f.tilde(codexHome))
	none(t, fs, doctor.CheckWindowsDrive, doctor.OK)

	// F3: this environment's temporary and cache folders, and the folders
	// hooks reported for Claude sessions (the ledger), are checked too.
	envTmp := filepath.Join(f.h.Dir, "wintmp")
	cacheHome := filepath.Join(f.h.Dir, "wincache")
	hookCfg := filepath.Join(f.h.Dir, "hooked", ".claude")
	hookTmp := filepath.Join(f.h.Dir, "hooked-tmp")
	f.d.GOOS = "linux" // WSL: the cache follows XDG_CACHE_HOME
	f.setEnv("CLAUDE_CODE_TMPDIR", envTmp)
	f.setEnv("XDG_CACHE_HOME", cacheHome)
	f.d.Sessions = func(h harness.ID) ([]ledger.Session, error) {
		if h != harness.ClaudeCode {
			return nil, nil
		}
		return []ledger.Session{{Harness: string(h), SID: "00000000-0000-4000-8000-0000000000d1", ConfigDirs: []string{hookCfg}, TmpDirs: []string{hookTmp, "relative"}}}, nil
	}
	onDrive = []string{envTmp, cacheHome, hookCfg, hookTmp}
	unsure = nil
	fs = f.run()
	want(t, fs, doctor.CheckWindowsDrive, doctor.Fail, "Claude's temporary folder "+f.tilde(envTmp))
	want(t, fs, doctor.CheckWindowsDrive, doctor.Fail, "Claude's cache folder "+f.tilde(filepath.Join(cacheHome, "claude-cli-nodejs")))
	want(t, fs, doctor.CheckWindowsDrive, doctor.Fail, "Claude's config folder "+f.tilde(hookCfg))
	want(t, fs, doctor.CheckWindowsDrive, doctor.Fail, "Claude's temporary folder "+f.tilde(hookTmp))
	none(t, fs, doctor.CheckWindowsDrive, doctor.OK)
	onDrive = nil
	want(t, f.run(), doctor.CheckWindowsDrive, doctor.OK, "no protected folder")

	// A folder that protects no Codex does not make the Codex home matter.
	f.o.Cfg.Roots = []config.Root{{ID: "root-acme", Path: f.h.Root, Harnesses: []string{"claude-code"}}}
	for _, x := range of(f.run(), doctor.CheckWindowsDrive) {
		if strings.Contains(x.Message, "Codex") {
			t.Errorf("Codex home reported without a folder that protects Codex: %q", x.Message)
		}
	}
}

// D156 (--leaks): Claude Code and Codex data in the Users folders of the
// Windows drives belongs to sessions precinto never sees.
func TestWindowsHarnessData(t *testing.T) {
	f := newFixture(t)
	drives := filepath.Join(f.h.Dir, "drives")
	mkdir(t, filepath.Join(drives, "c", "Users", "someone", ".claude"), 0o700)
	mkdir(t, filepath.Join(drives, "c", "Users", "someone", ".codex"), 0o700)
	mkdir(t, filepath.Join(drives, "d", "Users", "Public"), 0o700)
	mkdir(t, filepath.Join(drives, "wsl", "Users", "x", ".claude"), 0o700) // not a drive letter
	f.d.WSL = func() paths.WSL { return paths.WSL{Version: 2, InteropKnown: true, MountRoot: drives + "/"} }
	none(t, f.run(), doctor.CheckWindowsHarnessData) // only with --leaks
	f.o.Leaks = true
	fs := f.run()
	want(t, fs, doctor.CheckWindowsHarnessData, doctor.Warn, "Claude Code data of a Windows account", f.tilde(filepath.Join(drives, "c", "Users", "someone", ".claude")))
	want(t, fs, doctor.CheckWindowsHarnessData, doctor.Warn, "Codex data of a Windows account")
	if n := len(of(fs, doctor.CheckWindowsHarnessData)); n != 2 {
		t.Errorf("%d findings, want 2: %s", n, dump(of(fs, doctor.CheckWindowsHarnessData)))
	}
	f.d.WSL = func() paths.WSL { return paths.WSL{Version: 2, MountRoot: filepath.Join(f.h.Dir, "nodrives") + "/"} }
	want(t, f.run(), doctor.CheckWindowsHarnessData, doctor.OK, "no Claude Code or Codex data")
}
