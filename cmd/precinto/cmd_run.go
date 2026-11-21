package main

import (
	"context"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/wrapper"
)

func cmdRun(a *app, args []string) int {
	f := newFlags("run")
	h := f.String("harness", "", "the harness `H` (default: from the command name)")
	noPTY := f.Bool("no-pty", false, "run without a terminal proxy (still gated and sealed)")
	// Flags end at the first argument or `--`: everything after is the
	// harness command line, passed verbatim.
	argv, err := f.parseHead(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(argv) == 0 {
		return a.usageFail(f, "run needs the harness command after --")
	}
	return a.runHarness(harness.ID(*h), argv, *noPTY)
}

// runHarness runs argv through the wrapper (SPEC §15.1) and returns the
// child's exit code.
func (a *app) runHarness(h harness.ID, argv []string, noPTY bool) int {
	if err := a.sys.harden(); err != nil {
		return a.fail("run", err)
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("run", err)
	}
	ctx := context.Background()
	eng, err := a.engine(ctx, false)
	if err != nil {
		return a.fail("run", err)
	}
	if h == "" {
		id, ok := eng.HarnessFor(argv[0])
		if !ok {
			a.say(textNotHarness, argv[0])
			return exitUsage
		}
		h = id
	}
	wd, err := a.sys.getwd()
	if err != nil {
		return a.fail("run", err)
	}
	b := newBackend(a, eng)
	defer b.close()
	code, err := a.sys.wrapperRun(ctx, wrapper.Options{
		Harness: h,
		Argv:    argv,
		Cwd:     wd,
		Env:     a.env,
		NoPTY:   noPTY,
		Stdin:   a.sys.stdinFile,
		Stdout:  a.sys.stdoutFile,
		Stderr:  a.err,
		Policy:  cfg.Policy,
		Backend: b,
	})
	if err != nil {
		// Restore-before-launch refusals keep their class (a Codex home
		// that diverged is exit 4, a forged capsule exit 5).
		return a.failRestore("run", err)
	}
	return code
}

func cmdResume(a *app, args []string) int {
	f := newFlags("resume")
	last := f.Bool("last", false, "resume the most recent session of this folder")
	pick := f.Bool("pick", false, "choose from the folder's sessions (the harness picker)")
	h := f.String("harness", string(harness.ClaudeCode), "the harness `H`")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 1 {
		return a.usageFail(f, "resume takes at most one session id")
	}
	id := ""
	if len(pos) == 1 {
		id = pos[0]
	}
	if err := exclusive(map[string]bool{"ID": id != "", "last": *last, "pick": *pick}); err != nil {
		return a.usageFail(f, err.Error())
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("resume", err)
	}
	var argv []string
	switch harness.ID(*h) {
	case harness.ClaudeCode:
		exe := harnessExe(cfg.Harness[*h].Bin, "claude")
		switch {
		case id != "":
			argv = []string{exe, "--resume", id}
		case *last:
			argv = []string{exe, "--continue"}
		default:
			argv = []string{exe, "--resume"}
		}
	case harness.Codex:
		exe := harnessExe(cfg.Harness[*h].Bin, "codex")
		switch {
		case id != "":
			argv = []string{exe, "resume", id}
		case *last:
			argv = []string{exe, "resume", "--last"}
		default:
			argv = []string{exe, "resume"}
		}
	default:
		a.say(textResumeHarness)
		return exitUsage
	}
	return a.runHarness(harness.ID(*h), argv, false)
}

// harnessExe is the configured harness binary, else its name (the adapter
// resolves it to an absolute path in the launch plan).
func harnessExe(bin, name string) string {
	if bin != "" {
		return bin
	}
	return name
}
