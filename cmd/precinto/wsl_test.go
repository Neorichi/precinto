package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/wrapper"
)

var (
	wsl1 = paths.WSL{Version: 1, MountRoot: "/mnt/"}
	wsl2 = paths.WSL{Version: 2, InteropKnown: true, MountRoot: "/mnt/"}
)

// D156: under WSL 1 every command that would set up or rely on protection
// refuses, naming the conversion command, and so do seal and sweep, which
// delete plaintext after a liveness check WSL 1's emulated /proc cannot
// back; locking and stopping still work.
func TestWSL1Refused(t *testing.T) {
	for _, args := range [][]string{
		{"init"},
		{"protect", "."},
		{"unlock"},
		{"run", "--", "claude"},
		{"resume", "--last"},
		{"integrate", "claude-code"},
		{"agent", "--foreground"},
		{"seal"},
		{"seal", "--queue"},
		{"sweep"},
		{"sweep", "--dry-run"},
	} {
		e := newEnv(t)
		e.wsl = wsl1
		e.h.Env = e.h.Env.With("WSL_DISTRO_NAME", "Ubuntu-24.04")
		code := e.run(args...)
		want := ui.Format(ui.MsgWSL1, ui.Vars{Command: "wsl --set-version Ubuntu-24.04 2"})
		if code != exitError || !strings.Contains(e.stderr(), want) {
			t.Errorf("%v: exit %d, stderr %q; want 1 and %q", args, code, e.stderr(), want)
		}
		if e.hardened != 0 || len(e.dials) != 0 || len(e.wrapped) != 0 || len(e.agentOpts) != 0 || len(e.execs) != 0 {
			t.Errorf("%v: something ran under WSL 1 (hardened %d, dials %d, wrapped %d, agent %d, execs %d)",
				args, e.hardened, len(e.dials), len(e.wrapped), len(e.agentOpts), len(e.execs))
		}
	}
	// A distribution name that is not a plain word is not echoed.
	e := newEnv(t)
	e.wsl = wsl1
	e.h.Env = e.h.Env.With("WSL_DISTRO_NAME", "x; rm -rf ~")
	e.run("unlock")
	if !strings.Contains(e.stderr(), "wsl --set-version <distro> 2") {
		t.Errorf("odd distribution name: %q", e.stderr())
	}
	// Stopping the agent only locks: WSL 1 does not refuse it.
	e = newEnv(t)
	e.wsl = wsl1
	if e.run("agent", "--stop"); strings.Contains(e.stderr(), "WSL 1") || len(e.dials) == 0 {
		t.Errorf("agent --stop under WSL 1 refused: %s", e.stderr())
	}
	// Outside WSL nothing changes.
	e = newEnv(t)
	e.wsl = paths.WSL{}
	if e.run("agent", "--foreground"); len(e.agentOpts) != 1 {
		t.Errorf("agent did not start outside WSL: %s", e.stderr())
	}
}

// D156: under WSL protect refuses a folder on a Windows drive, and harness
// homes there; nothing is listed or created.
func TestProtectRefusesWindowsDrives(t *testing.T) {
	e := newEnv(t)
	e.wsl = wsl2
	mkdir(t, filepath.Join(e.h.HomeDir, "win", "proj"))
	e.drives = []string{filepath.Join(e.h.HomeDir, "win")}
	e.cwd = e.h.HomeDir
	before := e.loadConfig()
	if code := e.run("protect", "win/proj"); code != exitError {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if want := ui.Format(ui.MsgWindowsDrive, ui.Vars{Folder: "~/win/proj"}); !strings.Contains(e.stderr(), want) {
		t.Fatalf("stderr %q, want %q", e.stderr(), want)
	}
	if after := e.loadConfig(); len(after.Roots) != len(before.Roots) || len(e.daemon.creates) != 0 {
		t.Fatalf("the folder was protected: %+v %+v", after.Roots, e.daemon.creates)
	}
	// A folder precinto cannot place is refused too.
	e = newEnv(t)
	e.wsl = wsl2
	mkdir(t, filepath.Join(e.h.HomeDir, "odd", "proj"))
	e.unsureDrives = []string{filepath.Join(e.h.HomeDir, "odd")}
	e.cwd = e.h.HomeDir
	if code := e.run("protect", "odd/proj"); code != exitError || !strings.Contains(e.stderr(), "could not tell whether ~/odd/proj is on a Windows drive") {
		t.Fatalf("unknown drive: exit %d (%s)", code, e.stderr())
	}
	// Claude's config folder on a Windows drive: the folder is not protected.
	e = newEnv(t)
	e.wsl = wsl2
	mkdir(t, filepath.Join(e.h.HomeDir, "work", "gamma"))
	e.drives = []string{e.h.ClaudeConfig}
	e.cwd = e.h.HomeDir
	if code := e.run("protect", "work/gamma", "--harness", "claude-code"); code != exitError {
		t.Fatalf("claude home on a drive: exit %d (%s)", code, e.stderr())
	}
	if !strings.Contains(e.stderr(), "is on a Windows drive") || len(e.daemon.creates) != 0 {
		t.Fatalf("claude home on a drive: %q", e.stderr())
	}
	// The Codex home matters only when the folder manages Codex.
	e = newEnv(t)
	e.wsl = wsl2
	codexHome := mkdir(t, filepath.Join(e.h.HomeDir, "wincodex"))
	e.h.Env = e.h.Env.With("CODEX_HOME", codexHome)
	e.drives = []string{codexHome}
	mkdir(t, filepath.Join(e.h.HomeDir, "work", "delta"))
	e.cwd = e.h.HomeDir
	e.vaults.metas["x"] = e.vaults.metas["root-acme"]
	if code := e.run("protect", "work/delta", "--harness", "claude-code"); code != exitOK {
		t.Fatalf("claude only, codex home on a drive: exit %d (%s)", code, e.stderr())
	}
	mkdir(t, filepath.Join(e.h.HomeDir, "work", "epsilon"))
	if code := e.run("protect", "work/epsilon", "--harness", "codex"); code != exitError || !strings.Contains(e.stderr(), "~/wincodex is on a Windows drive") {
		t.Fatalf("codex home on a drive: exit %d (%s)", code, e.stderr())
	}
}

// D156: integrate never runs a harness that is a Windows program (its
// --version, its plugin commands) nor installs precinto's plugin into it.
func TestIntegrateRefusesWindowsPrograms(t *testing.T) {
	e := newEnv(t)
	e.wsl = wsl2
	bin := filepath.Join(fakePluginDir(t, e, "claude"), "claude")
	e.winPrograms = []string{bin}
	if code := e.run("integrate", "claude-code"); code != exitError {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	want := ui.Format(ui.MsgWindowsProgram, ui.Vars{File: e.app().display(bin), Cause: "is a Windows executable", Harness: "claude"})
	if !strings.Contains(e.stderr(), want) {
		t.Fatalf("stderr %q, want %q", e.stderr(), want)
	}
	if len(e.execs) != 0 {
		t.Fatalf("ran %+v", e.execs)
	}
	// Claude's folders on a Windows drive: refused before anything runs.
	e = newEnv(t)
	e.wsl = wsl2
	fakePluginDir(t, e, "claude")
	e.drives = []string{e.h.ClaudeTmp}
	if code := e.run("integrate", "claude-code"); code != exitError || len(e.execs) != 0 || !strings.Contains(e.stderr(), "is on a Windows drive") {
		t.Fatalf("claude tmp on a drive: exit %d, execs %d (%s)", code, len(e.execs), e.stderr())
	}
}

// D156: run reports a launch the adapter refused (a Windows program, a
// home on a Windows drive) with the catalog's words.
func TestRunReportsWSLRefusals(t *testing.T) {
	e := newEnv(t)
	e.wrapCode, e.wrapErr = wrapper.ExitNotStarted, &harness.ProgramError{Harness: harness.ClaudeCode, Exe: "/mnt/c/tools/claude.exe", Why: "is on a Windows drive"}
	if code := e.run("run", "--", "claude"); code != exitError {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if want := ui.Format(ui.MsgWindowsProgram, ui.Vars{File: "/mnt/c/tools/claude.exe", Cause: "is on a Windows drive", Harness: "claude"}); !strings.Contains(e.stderr(), want) {
		t.Fatalf("stderr %q", e.stderr())
	}
	e = newEnv(t)
	e.wrapCode, e.wrapErr = wrapper.ExitNotStarted, &paths.DriveError{Path: filepath.Join(e.h.HomeDir, ".claude")}
	if code := e.run("run", "--", "claude"); code != exitError || !strings.Contains(e.stderr(), ui.Format(ui.MsgWindowsDrive, ui.Vars{Folder: "~/.claude"})) {
		t.Fatalf("home on a drive: exit %d (%s)", code, e.stderr())
	}
	// A location precinto could not place: the message says what stopped
	// it, not a fixed guess.
	e = newEnv(t)
	e.wrapCode, e.wrapErr = wrapper.ExitNotStarted, &paths.DriveError{Path: filepath.Join(e.h.HomeDir, ".claude"), Unknown: true, Why: "it is a dangling symlink"}
	want := ui.Format(ui.MsgWindowsDriveUnsure, ui.Vars{Folder: "~/.claude", Cause: "it is a dangling symlink"})
	if code := e.run("run", "--", "claude"); code != exitError || !strings.Contains(e.stderr(), want) || strings.Contains(e.stderr(), "mountinfo") {
		t.Fatalf("unsure drive: exit %d (%s)", code, e.stderr())
	}
	// A program precinto could not check is not called a Windows program.
	e = newEnv(t)
	e.wrapCode, e.wrapErr = wrapper.ExitNotStarted, &harness.ProgramError{Harness: harness.ClaudeCode, Exe: "/usr/local/bin/claude", Why: "can't be read to check that it is not a Windows program", Unknown: true}
	want = ui.Format(ui.MsgWinProgramUnsure, ui.Vars{File: "/usr/local/bin/claude", Cause: "can't be read to check that it is not a Windows program", Harness: "claude"})
	if code := e.run("run", "--", "claude"); code != exitError || !strings.Contains(e.stderr(), want) || strings.Contains(e.stderr(), "would run as a Windows program (") {
		t.Fatalf("unsure program: exit %d (%s)", code, e.stderr())
	}
	// The program a "#!" line names reaches the terminal displayed like a
	// path, never raw (S17): a shebang naming an OSC 52 sequence.
	e = newEnv(t)
	evil := "/mnt/c/x\x1b]52;c;AAAA\x07y"
	e.wrapCode, e.wrapErr = wrapper.ExitNotStarted, &harness.ProgramError{Harness: harness.ClaudeCode, Exe: "/home/u/bin/claude", Runs: evil, Why: "is on a Windows drive"}
	if code := e.run("run", "--", "claude"); code != exitError || strings.ContainsAny(e.stderr(), "\x1b\x07") || !strings.Contains(e.stderr(), "runs "+shownValue(evil)+", which is on a Windows drive") {
		t.Fatalf("escape in a shebang: exit %d (%q)", code, e.stderr())
	}
}

// D156: under WSL --recovery-out refuses the Users folder of a Windows
// drive (OneDrive and Known Folder Move sync it) and a folder precinto
// cannot place; another Windows drive only gets a note.
func TestInitRecoveryOutUnderWSL(t *testing.T) {
	setup := func() *env {
		e := newEnv(t)
		e.vaults.initialized = false
		fakePluginDir(t, e, "age-plugin-se")
		e.execOut["keygen"] = []byte("# public key: age1se1q\nAGE-PLUGIN-SE-1Q\n")
		e.tty.yesno = []bool{false}
		return e
	}
	e := setup()
	drives := mkdir(t, filepath.Join(e.h.Dir, "drives"))
	users := mkdir(t, filepath.Join(drives, "c", "Users", "Public"))
	e.wsl = paths.WSL{Version: 2, MountRoot: drives + "/"}
	e.drives = []string{drives}
	if code := e.run("init", "--recovery-out", filepath.Join(users, "key.txt")); code != exitLocked || !strings.Contains(e.stderr(), textRecoveryUsers) {
		t.Fatalf("Users folder: exit %d (%s)", code, e.stderr())
	}
	if _, err := os.Stat(filepath.Join(users, "key.txt")); !errors.Is(err, os.ErrNotExist) || len(e.vaults.initOpts) != 0 {
		t.Fatal("the key was written to a Users folder")
	}

	e = setup()
	other := mkdir(t, filepath.Join(e.h.Dir, "drives", "d", "keys"))
	e.wsl = paths.WSL{Version: 2, MountRoot: filepath.Join(e.h.Dir, "drives") + "/"}
	e.drives = []string{filepath.Join(e.h.Dir, "drives")}
	if code := e.run("init", "--recovery-out", filepath.Join(other, "key.txt")); code != exitOK {
		t.Fatalf("another drive: exit %d (%s)", code, e.stderr())
	}
	if !strings.Contains(e.stderr(), "is on a Windows drive: Windows programs") {
		t.Fatalf("no note for another drive: %q", e.stderr())
	}

	e = setup()
	odd := mkdir(t, filepath.Join(e.h.Dir, "odd"))
	e.wsl = wsl2
	e.unsureDrives = []string{odd}
	if code := e.run("init", "--recovery-out", filepath.Join(odd, "key.txt")); code != exitLocked || !strings.Contains(e.stderr(), textRecoveryDriveUnsure) {
		t.Fatalf("unknown drive: exit %d (%s)", code, e.stderr())
	}
}

// D156 (item 9): Claude's temporary folder follows os.tmpdir() off darwin
// (TMPDIR, TMP, TEMP, else /tmp) when CLAUDE_CODE_TMPDIR does not say.
func TestClaudeHomeFromEnvFollowsTMPDIR(t *testing.T) {
	e := newEnv(t)
	e.goos = "linux"
	tmp := mkdir(t, filepath.Join(e.h.Dir, "sys-tmp"))
	claudeTmp := mkdir(t, filepath.Join(tmp, "claude-501"))
	e.h.Env = e.h.Env.Without(paths.EnvClaudeTmpDir).With("TMPDIR", tmp+"/")
	h, ok := e.app().claudeHomeFromEnv()
	real, _ := filepath.EvalSymlinks(claudeTmp)
	if !ok || h.Tmp != real {
		t.Fatalf("home %+v, want tmp %s", h, real)
	}
	e.goos = "darwin"
	if _, tmpDir, _, _ := e.app().claudeEnvDirs(); tmpDir != "/private/tmp/claude-501" {
		t.Fatalf("darwin tmp %q", tmpDir)
	}
	// Under WSL a home or a tmp folder on a Windows drive is never
	// registered (D156).
	e.goos = "linux"
	e.wsl = wsl2
	e.drives = []string{tmp}
	if h, ok := e.app().claudeHomeFromEnv(); !ok || h.Tmp != "" || h.Dir == "" {
		t.Fatalf("tmp on a drive: %+v %v", h, ok)
	}
	e.drives = []string{e.h.ClaudeConfig}
	if h, ok := e.app().claudeHomeFromEnv(); ok {
		t.Fatalf("a home on a drive was registered: %+v", h)
	}
}

// D155, D156: status reports WSL (JSON and summary line) and attention
// items for WSL 1, interop and Windows-drive locations; it still runs
// when precinto's own folder is on a Windows drive.
func TestStatusUnderWSL(t *testing.T) {
	e := newEnv(t)
	e.wsl = paths.WSL{Version: 2, Interop: true, InteropKnown: true, MountRoot: "/mnt/"}
	e.drives = []string{e.h.Root, e.h.Layout.Base}
	lay := e.h.Layout
	e.app() // builds e.sys
	e.sys.newLayout = func(paths.Env) (paths.Layout, error) { return lay, &paths.DriveError{Path: lay.Base} }
	a := newApp(stdio{in: e.in, out: &e.out, err: &e.err}, e.h.Env, e.sys)
	if code := a.run([]string{"status", "--json"}); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	var s struct {
		WSL       *statusWSL      `json:"wsl"`
		Attention []ipc.Attention `json:"attention"`
	}
	if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.WSL == nil || *s.WSL != (statusWSL{Version: 2, Interop: "on", MountRoot: "/mnt/"}) {
		t.Fatalf("wsl %+v", s.WSL)
	}
	if len(e.engCfg) != 0 {
		t.Fatal("status built an engine (which creates directories) on a Windows drive")
	}
	var codes []string
	folders := map[string]bool{}
	for _, at := range s.Attention {
		codes = append(codes, at.Code)
		if at.Code == doctor.CheckWindowsDrive {
			folders[at.Folder] = true
		}
	}
	if !strings.Contains(strings.Join(codes, " "), doctor.CheckWSLInterop) || !folders[a.display(e.h.Root)] || !folders[a.display(e.h.Layout.Base)] {
		t.Fatalf("attention %+v", s.Attention)
	}
	for _, c := range codes {
		if c == doctor.CheckWSL {
			t.Fatalf("a WSL 1 item under WSL 2: %+v", s.Attention)
		}
	}

	e = newEnv(t)
	e.wsl = wsl1
	if code := e.run("status"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	out := e.stdout()
	if !strings.Contains(out, "wsl      WSL 1 · Windows interop unknown") || !strings.Contains(out, "  wsl  "+textWSL1Detail) || strings.Contains(out, "instanceIdleTimeout") {
		t.Fatalf("status under WSL 1:\n%s", out)
	}
	e = newEnv(t)
	e.wsl = wsl2
	e.run("status")
	if !strings.Contains(e.stdout(), "instanceIdleTimeout=-1") {
		t.Fatalf("status under WSL 2 does not name the idle shutdown:\n%s", e.stdout())
	}
	// Outside WSL nothing is added.
	e = newEnv(t)
	e.run("status", "--json")
	if strings.Contains(e.stdout(), `"wsl"`) {
		t.Fatalf("wsl outside WSL: %s", e.stdout())
	}
}

// D156: doctor runs when precinto's own folder is on a Windows drive (the
// windows-drive check reports it); other commands stop.
// D155, D156: lock and agent --stop only wipe keys, so a folder of
// precinto on a Windows drive (an agent an earlier build started there, or
// a drive check that turned unknown) never stops them: they reach the
// agent; unlock still refuses (TestDoctorRunsWithAWindowsDriveLayout).
func TestLockAndStopWithAWindowsDriveLayout(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		onDrive := func(e *env) {
			lay := e.h.Layout
			e.sys.newLayout = func(paths.Env) (paths.Layout, error) {
				return lay, &paths.DriveError{Path: lay.Base, Unknown: unknown, Err: errors.New("no mount holds the path")}
			}
		}
		for _, args := range [][]string{{"lock"}, {"lock", "--end"}} {
			e := newEnv(t)
			e.app()
			onDrive(e)
			a := newApp(stdio{in: e.in, out: &e.out, err: &e.err}, e.h.Env, e.sys)
			if code := a.run(args); code != exitOK || len(e.daemon.locks) != 1 || strings.Contains(e.stderr(), "Windows drive") {
				t.Errorf("%v (unknown %v): exit %d, %d locks (%s)", args, unknown, code, len(e.daemon.locks), e.stderr())
			}
		}
		e := newEnv(t)
		e.app()
		onDrive(e)
		calls := 0
		inner := e.sys.dial
		e.sys.dial = func(ctx context.Context, o ipc.DialOptions) (daemonClient, error) {
			if calls++; calls > 1 {
				return nil, ipc.ErrNoDaemon // stopped
			}
			return inner(ctx, o)
		}
		a := newApp(stdio{in: e.in, out: &e.out, err: &e.err}, e.h.Env, e.sys)
		if code := a.run([]string{"agent", "--stop"}); code != exitOK || e.daemon.shutdowns != 1 {
			t.Errorf("agent --stop (unknown %v): exit %d, %d shutdowns (%s)", unknown, code, e.daemon.shutdowns, e.stderr())
		}
	}
}

func TestDoctorRunsWithAWindowsDriveLayout(t *testing.T) {
	e := newEnv(t)
	lay := e.h.Layout
	e.app()
	e.sys.newLayout = func(paths.Env) (paths.Layout, error) { return lay, &paths.DriveError{Path: lay.Base} }
	var got doctor.Options
	e.sys.doctorRun = func(_ context.Context, o doctor.Options) ([]doctor.Finding, error) { got = o; return nil, nil }
	a := newApp(stdio{in: e.in, out: &e.out, err: &e.err}, e.h.Env, e.sys)
	if code := a.run([]string{"doctor"}); code != exitOK || got.Layout.Base != lay.Base {
		t.Fatalf("doctor: exit %d, layout %q (%s)", code, got.Layout.Base, e.stderr())
	}
	a = newApp(stdio{in: e.in, out: &e.out, err: &e.err}, e.h.Env, e.sys)
	if code := a.run([]string{"unlock"}); code != exitError || !strings.Contains(e.stderr(), ui.Format(ui.MsgWindowsDrive, ui.Vars{Folder: a.display(lay.Base)})) {
		t.Fatalf("unlock: exit %d (%s)", code, e.stderr())
	}
}
