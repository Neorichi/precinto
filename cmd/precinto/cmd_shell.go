package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/shellinit"
)

func cmdShellInit(a *app, args []string) int {
	f := newFlags("shell-init")
	install := f.Bool("install", false, "add the eval line to your shell's rc file (asks first)")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) != 1 || !validShell(pos[0]) {
		return a.usageFail(f, "shell-init needs zsh, bash or fish")
	}
	shell := pos[0]
	if *install {
		return a.shellInstall(shell)
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("shell-init", err)
	}
	exe, err := a.pinnedExe()
	if err != nil {
		return a.fail("shell-init", err)
	}
	// Wrapper functions for the enabled built-in harnesses. Experimental
	// inventories are wrapper-only and opt-in: they are run explicitly with
	// precinto run --harness H (D33).
	var exes []string
	if cfg.Harness[string(harness.ClaudeCode)].Enabled {
		exes = append(exes, "claude")
	}
	if cfg.Harness[string(harness.Codex)].Enabled {
		exes = append(exes, "codex")
	}
	script, err := a.sys.shell.Script(shellinit.Options{Shell: shell, Harnesses: exes, Exe: exe})
	if err != nil {
		return a.fail("shell-init", err)
	}
	fmt.Fprint(a.out, script)
	if !strings.HasSuffix(script, "\n") {
		fmt.Fprintln(a.out)
	}
	return exitOK
}

func validShell(s string) bool {
	return s == shellinit.Zsh || s == shellinit.Bash || s == shellinit.Fish
}

// shellInstall appends the eval line to the rc file after consent.
func (a *app) shellInstall(shell string) int {
	home := a.home()
	if home == "" {
		return a.fail("shell-init", fmt.Errorf("HOME is not set"))
	}
	t, err := a.needTerminal("shell-init --install")
	if err != nil {
		return exitLocked
	}
	defer t.Close()
	rc := a.sys.shell.RCFile(shell, home)
	ok, err := t.YesNo(fmt.Sprintf(textShellInstall, a.display(rc)), true)
	if err != nil || !ok {
		a.say(textNotConfirmed)
		return exitLocked
	}
	if err := a.sys.shell.Install(shell, home); err != nil {
		return a.fail("shell-init", err)
	}
	a.say(textShellDone, a.display(rc))
	return exitOK
}

// cmdShellHook is the folder-entry hook (SPEC §15.5, D29, D69). The
// decision is shellinit.OnEnter (≤ 150 ms daemon query, never reads the
// TTY, never autostarts); its stdout is shellinit.EnterResult.Lines() and
// nothing else: key=value data the calling shell parses without eval. The
// scripts print the message, keep the skip key, and for action=prompt read
// one key and run `precinto unlock --root PATH` themselves; this command
// never prompts or unlocks. Any failure is silent: a broken hook must
// never break the user's prompt.
func cmdShellHook(a *app, args []string) int {
	f := newFlags("shell-hook")
	shell := f.String("shell", "", "zsh, bash or fish")
	pwd := f.String("pwd", "", "the new working directory")
	prev := f.String("prev", "", "the previous working directory")
	skip := f.String("skip", "", "the current skip key (<id>:<epoch>)")
	first := f.Bool("first", false, "first prompt of a new shell")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 0 || !validShell(*shell) || *pwd == "" {
		return a.usageFail(f, "shell-hook needs --shell zsh|bash|fish and --pwd DIR")
	}
	cfg, err := a.config()
	if err != nil {
		return exitOK
	}
	l, err := a.layout()
	if err != nil {
		return exitOK
	}
	req := shellinit.EnterRequest{PWD: *pwd, PrevPWD: *prev, Shell: *shell, SkipKey: *skip, FirstRun: *first,
		GUI: a.sys.uiContext(a.env).GUI}
	if home, err := paths.UserHome(a.env); err == nil {
		req.Home = home
	}
	res, err := a.sys.shell.OnEnter(context.Background(), cfg, l, req)
	if err != nil {
		return exitOK
	}
	// D69: the decision as key=value data and nothing else. The scripts
	// parse it without eval, print the message, set _PRECINTO_SKIP, and
	// for action=prompt read one key and run precinto unlock --root PATH
	// themselves: precinto never prompts from shell-hook.
	fmt.Fprint(a.out, res.Lines())
	return exitOK
}
