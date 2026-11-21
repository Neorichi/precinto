package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/shellinit"
	"github.com/precinto/precinto/internal/ui"
)

// skipVar is the shell variable the folder-entry hook keeps the skip key
// in (_PRECINTO_SKIP=<root-id>:<epoch>, SPEC §15.5).
const skipVar = "_PRECINTO_SKIP"

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

// cmdShellHook is the folder-entry hook (SPEC §15.5, D29). The decision is
// shellinit.OnEnter (≤ 150 ms daemon query, never reads the TTY, never
// autostarts). Only when it says "prompt" does this command read the
// terminal: Enter unlocks, anything else (or Ctrl-C) skips. Its stdout is
// shell assignments for the calling shell (the skip key, so the folder
// asks at most once per lock epoch). Any failure is silent: a broken hook
// must never break the user's prompt.
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
	ctx := context.Background()
	res, err := a.sys.shell.OnEnter(ctx, cfg, l, shellinit.EnterRequest{PWD: *pwd, PrevPWD: *prev, Shell: *shell, SkipKey: *skip, FirstRun: *first})
	if err != nil || res.Action == shellinit.EnterNothing {
		return exitOK
	}
	folder := res.Folder
	if folder == "" {
		if r, ok := cfg.RootByID(res.RootID); ok {
			folder = a.display(r.Path)
		}
	}
	key := res.RootID + ":" + strconv.FormatUint(res.Epoch, 10)
	switch res.Action {
	case shellinit.EnterNotify:
		a.enterMessage(res.Message, ui.MsgEnterNotify, folder)
	case shellinit.EnterBusy:
		// Another terminal is unlocking: say so, and ask again later.
		a.enterMessage(res.Message, ui.MsgEnterElsewhere, folder)
		return exitOK
	case shellinit.EnterPrompt:
		a.enterPrompt(ctx, res, folder)
	default:
		return exitOK
	}
	fmt.Fprintln(a.out, shellAssign(*shell, skipVar, key))
	return exitOK
}

// enterMessage prints the decision's message, or the catalog text.
func (a *app) enterMessage(msg string, id ui.MsgID, folder string) {
	if msg != "" {
		a.say("%s", oneLineText(msg))
		return
	}
	a.line(id, ui.Vars{Folder: folder})
}

// enterPrompt asks C1.prompt on the terminal and unlocks on Enter.
func (a *app) enterPrompt(ctx context.Context, res shellinit.EnterResult, folder string) {
	t, err := a.sys.openTTY()
	if err != nil {
		a.line(ui.MsgEnterNotify, ui.Vars{Folder: folder})
		return
	}
	defer t.Close()
	prompt := res.Message
	if prompt == "" {
		prompt = ui.Format(ui.MsgEnterPrompt, ui.Vars{Folder: folder})
	}
	answer, err := t.ReadLine(prompt)
	if err != nil || strings.TrimSpace(answer) != "" {
		return // any other key, or Ctrl-C, skips (D29)
	}
	if err := a.sys.harden(); err != nil {
		return
	}
	cfg, _ := a.config()
	c, err := a.dial(ctx, true)
	if err != nil {
		a.line(ui.MsgAgentDown, ui.Vars{Folder: folder})
		return
	}
	defer c.Close()
	resp, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{res.RootID}, TTY: true, Deadline: a.now().Add(unlockDeadline)}, t)
	if err != nil {
		if isCancel(err) {
			a.line(ui.MsgUnlockCancelled, ui.Vars{Folder: folder})
			return
		}
		a.fail("unlock", err)
		return
	}
	a.line(ui.MsgUnlockOK, ui.Vars{Folder: folder, N: cfg.Policy.RestoreRecent, Idle: cfg.Policy.IdleSoft.D(), Until: resp.Until.In(a.sys.loc)})
}

// shellAssign renders a global variable assignment for shell.
func shellAssign(shell, name, value string) string {
	if shell == shellinit.Fish {
		v := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(value)
		return "set -g " + name + " '" + v + "'"
	}
	return name + "='" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
