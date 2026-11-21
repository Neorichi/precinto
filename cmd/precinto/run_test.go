package main

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/wrapper"
)

// run passes the command line verbatim to wrapper.Run with the backend,
// after hardening, and returns the child's exit code.
func TestRunPassesThrough(t *testing.T) {
	e := newEnv(t)
	e.wrapCode = 7
	code := e.run("run", "--no-pty", "--", "claude", "-p", "--harness", "x")
	if code != 7 {
		t.Fatalf("exit %d, want the child's 7", code)
	}
	if e.hardened != 1 {
		t.Fatal("run did not harden (SPEC §4.6)")
	}
	o := e.wrapped[0]
	if o.Harness != harness.ClaudeCode || !o.NoPTY || strings.Join(o.Argv, " ") != "claude -p --harness x" || o.Cwd != e.h.Root {
		t.Fatalf("options %+v", o)
	}
	if o.Backend == nil || o.Policy.IdleSoft.D() == 0 || o.Env.Get("HOME") != e.h.HomeDir {
		t.Fatalf("options %+v", o)
	}
	e = newEnv(t)
	if code := e.run("run", "--harness", "codex", "codex", "exec", "x"); code != exitOK || e.wrapped[0].Harness != harness.Codex {
		t.Fatalf("exit %d %+v", code, e.wrapped)
	}
}

func TestRunUnknownHarness(t *testing.T) {
	e := newEnv(t)
	if code := e.run("run", "--", "ls", "-l"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if len(e.wrapped) != 0 {
		t.Fatal("ran an unknown program")
	}
	e = newEnv(t)
	if code := e.run("run"); code != exitUsage {
		t.Fatalf("no command: exit %d", code)
	}
}

// A codex launch whose home diverged is exit 4 (R12); a forged capsule 5.
// The wrapper reports a launch that never started with ExitNotStarted and
// the reason (CC-42); a child that ran keeps its own code.
func TestRunErrorsKeepTheirClass(t *testing.T) {
	e := newEnv(t)
	e.wrapCode, e.wrapErr = wrapper.ExitNotStarted, sweep.ErrConflict
	if code := e.run("run", "--", "codex"); code != exitLive {
		t.Fatalf("exit %d", code)
	}
	e = newEnv(t)
	e.wrapCode, e.wrapErr = wrapper.ExitNotStarted, sweep.ErrNotLogged
	if code := e.run("run", "--", "claude"); code != exitVerify {
		t.Fatalf("exit %d", code)
	}
	e = newEnv(t)
	e.wrapCode, e.wrapErr = wrapper.ExitNotStarted, &ipc.Error{Code: ipc.CodeLocked, Msg: "precinto: ~/work/acme is locked."}
	if code := e.run("run", "--", "claude"); code != exitLocked {
		t.Fatalf("locked: exit %d", code)
	}
	e = newEnv(t)
	e.wrapCode, e.wrapErr = wrapper.ExitNotStarted, &fs.PathError{Op: "fork/exec", Path: "/x/claude", Err: fs.ErrNotExist}
	if code := e.run("run", "--", "claude"); code != 127 {
		t.Fatalf("missing executable: exit %d", code)
	}
	e = newEnv(t)
	e.wrapCode, e.wrapErr = 7, errors.New("sealing after exit failed")
	if code := e.run("run", "--", "claude"); code != 7 {
		t.Fatalf("a child that ran: exit %d, want its own 7", code)
	}
	// API §5 rows for launches that never started: running as root, a
	// wrong passphrase at the unlock before launch, a declined confirm.
	for _, c := range []struct {
		err  error
		want int
		text string
	}{
		{platform.ErrRoot, exitLocked, ""},
		{&ipc.Error{Code: ipc.CodeBadSecret}, exitLocked, ui.Format(ui.MsgUnlockBadSecret, ui.Vars{Folder: "the folder"})},
		{ui.ErrCancelled, exitLocked, ""},
		{&ipc.Error{Code: ipc.CodeAgentContext, Msg: "precinto: refused"}, exitLocked, "precinto: refused"},
	} {
		e = newEnv(t)
		e.wrapCode, e.wrapErr = wrapper.ExitNotStarted, c.err
		if code := e.run("run", "--", "claude"); code != c.want {
			t.Errorf("%v: exit %d, want %d", c.err, code, c.want)
		}
		if c.text != "" && !strings.Contains(e.stderr(), c.text) {
			t.Errorf("%v: stderr %q, want %q", c.err, e.stderr(), c.text)
		}
	}
}

func TestResumeArgv(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"resume", "00000000-0000-4000-8000-000000000001"}, "claude --resume 00000000-0000-4000-8000-000000000001"},
		{[]string{"resume", "--last"}, "claude --continue"},
		{[]string{"resume", "--pick"}, "claude --resume"},
		{[]string{"resume"}, "claude --resume"},
		{[]string{"resume", "--harness", "codex", "--last"}, "codex resume --last"},
	}
	for _, c := range cases {
		e := newEnv(t)
		if code := e.run(c.args...); code != exitOK {
			t.Fatalf("%v: exit %d (%s)", c.args, code, e.stderr())
		}
		if got := strings.Join(e.wrapped[0].Argv, " "); got != c.want {
			t.Errorf("%v: argv %q, want %q", c.args, got, c.want)
		}
	}
	e := newEnv(t)
	if code := e.run("resume", "x", "--last"); code != exitUsage {
		t.Fatalf("exclusive: exit %d", code)
	}
	if code := e.run("resume", "--harness", "gemini"); code != exitUsage {
		t.Fatalf("gemini: exit %d", code)
	}
}

// agent runs the daemon in this process (ipc.Dial's autostart executes
// `precinto agent`); --restart shuts the running one down first.
func TestAgent(t *testing.T) {
	e := newEnv(t)
	e.dialErr = nil
	if code := e.run("agent", "--foreground"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	o := e.agentOpts[0]
	if !o.Foreground || o.Exe != "/opt/precinto/bin/precinto" || o.Layout.Base != e.h.Base || o.Clock == nil || o.Procs == nil {
		t.Fatalf("options %+v", o)
	}
	e = newEnv(t)
	e.daemon.statusErr = nil
	calls := 0
	a := e.app()
	inner := a.sys.dial
	a.sys.dial = func(ctx context.Context, o ipc.DialOptions) (daemonClient, error) {
		calls++
		if calls > 1 {
			return nil, ipc.ErrNoDaemon
		}
		return inner(ctx, o)
	}
	if code := a.run([]string{"agent", "--restart"}); code != exitOK {
		t.Fatalf("restart: exit %d (%s)", code, e.stderr())
	}
	if e.daemon.shutdowns != 1 || len(e.agentOpts) != 1 {
		t.Fatalf("shutdowns %d runs %d", e.daemon.shutdowns, len(e.agentOpts))
	}
}

func TestDoctorExitCodes(t *testing.T) {
	e := newEnv(t)
	e.doctorOut = []doctor.Finding{{Code: doctor.CheckDiskEncryption, Severity: doctor.OK, Message: "FileVault is on"}}
	if code := e.run("doctor"); code != exitOK || !strings.Contains(e.stdout(), "precinto doctor: 0 failed, 0 warnings, 0 notes, 1 ok") {
		t.Fatalf("exit %d %q", code, e.stdout())
	}
	// Warnings do not change the exit code (SPEC §16.2).
	e = newEnv(t)
	e.doctorOut = []doctor.Finding{{Code: doctor.CheckBackups, Severity: doctor.Warn, Message: "Time Machine backs up x"}}
	if code := e.run("doctor"); code != exitOK {
		t.Fatalf("warning: exit %d", code)
	}
	e = newEnv(t)
	e.doctorOut = []doctor.Finding{{Code: doctor.CheckLoaderEnv, Severity: doctor.Fail, Message: "DYLD_INSERT_LIBRARIES is set", Fix: "unset it"}}
	if code := e.run("doctor", "--leaks"); code != exitError {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(e.stdout(), "FAIL  loader-env  DYLD_INSERT_LIBRARIES is set") || !strings.Contains(e.stdout(), "fix: unset it") {
		t.Fatalf("stdout %q", e.stdout())
	}
	// --json prints the v1 document (doctor.Render).
	e = newEnv(t)
	e.doctorOut = []doctor.Finding{{Code: doctor.CheckLoaderEnv, Severity: doctor.Fail, Message: "DYLD_INSERT_LIBRARIES is set", Fix: "unset it"}}
	if code := e.run("doctor", "--json"); code != exitError || !strings.Contains(e.stdout(), `"worst": "fail"`) {
		t.Fatalf("json: exit %d %q", code, e.stdout())
	}
	e = newEnv(t)
	if code := e.run("doctor", "nosuch"); code != exitUsage {
		t.Fatalf("unknown harness: exit %d", code)
	}
}

// doctor is read-only: it never builds the engine (which creates
// precinto's directories and the name salt).
func TestDoctorBuildsNoEngine(t *testing.T) {
	e := newEnv(t)
	registered := 0
	a := e.app()
	a.sys.registerAdapters = func() { registered++ }
	if code := a.run([]string{"doctor"}); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if len(e.engExp) != 0 || registered != 1 {
		t.Fatalf("engine built %d times, adapters registered %d times", len(e.engExp), registered)
	}
}
