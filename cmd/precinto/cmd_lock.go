package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

// unlockDeadline bounds one unlock request (presence prompts included).
const unlockDeadline = 3 * time.Minute

func cmdUnlock(a *app, args []string) int {
	f := newFlags("unlock")
	rootDir := f.String("root", "", "unlock the protected folder containing `DIR`")
	all := f.Bool("all", false, "unlock every folder (asks once per folder, D40)")
	global := f.Bool("global", false, "unlock the global vault (Claude global stores)")
	dur := f.Duration("for", 0, "keep it unlocked at most `DUR` (capped by policy.max_unlock)")
	factor := f.String("factor", "", "unlock method to use (see precinto factor list)")
	extend := f.Bool("extend", false, "extend the time limit of an unlocked folder (asks for presence again)")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageFail(f, "unexpected argument "+pos[0])
	}
	if err := exclusive(map[string]bool{"root": *rootDir != "", "all": *all, "global": *global}); err != nil {
		return a.usageFail(f, err.Error())
	}
	if *dur < 0 {
		return a.usageFail(f, "--for must be positive")
	}
	if err := a.sys.harden(); err != nil {
		return a.fail("unlock", err)
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("unlock", err)
	}
	req := ipc.UnlockReq{Factor: *factor, TTL: *dur, Extend: *extend, Deadline: a.now().Add(unlockDeadline)}
	var targets []config.Root
	switch {
	case *global:
		req.Global = true
	case *all:
		req.All = true
		targets = cfg.Roots
	case *rootDir != "":
		r, err := a.rootArg(cfg, *rootDir)
		if err != nil {
			return a.fail("unlock", err)
		}
		req.RootIDs, targets = []string{r.ID}, []config.Root{r}
	default:
		r, ok := a.cwdRoot(cfg)
		switch {
		case ok:
			req.RootIDs, targets = []string{r.ID}, []config.Root{r}
		case !cfg.Policy.PerRootAuth && len(cfg.Roots) > 0:
			// per_root_auth = false: unlock every folder, one prompt each
			// (D40); the policy itself is the confirmation.
			req.All, req.Confirmed, targets = true, true, cfg.Roots
		default:
			wd, _ := a.sys.getwd()
			a.say(textUnlockWhich, a.display(wd))
			return exitUsage
		}
	}
	if req.All && len(cfg.Roots) == 0 {
		a.say(textNothingToDo)
		return exitOK
	}

	var t terminal
	if a.sys.interactive() {
		if tt, err := a.sys.openTTY(); err == nil {
			t = tt
			defer t.Close()
		}
	}
	if req.All && !req.Confirmed {
		// D40: typed confirmation on a TTY; without one only the folder
		// of the working directory can be unlocked (SPEC §12.8).
		if t == nil {
			a.say(textNeedTerminal, "precinto unlock --all")
			return exitLocked
		}
		prompt := ui.Format(ui.MsgUnlockConfirmAll, ui.Vars{N: len(targets), Folder: a.display(targets[0].Path)})
		if err := a.typedWord(t, prompt, wordUnlock); err != nil {
			return exitLocked
		}
		req.Confirmed = true
	}
	req.TTY = t != nil
	var relay ipc.UIHandler = headlessUI{w: a.err}
	if t != nil {
		relay = t
	}
	ctx := context.Background()
	c, err := a.dial(ctx, true)
	if err != nil {
		return a.fail("unlock", err)
	}
	defer c.Close()
	resp, err := c.Unlock(ctx, req, relay)
	if err != nil {
		if isCancel(err) {
			a.line(ui.MsgUnlockCancelled, ui.Vars{Folder: a.folderList(cfg, req, targets)})
			return exitLocked
		}
		return a.fail("unlock", err)
	}
	if len(resp.Unlocked) == 0 {
		a.say(textAlreadyOpen, a.folderList(cfg, req, targets))
	}
	for _, id := range resp.Unlocked {
		folder := "the global vault"
		if r, ok := cfg.RootByID(id); ok {
			folder = a.display(r.Path)
		} else if id != vault.GlobalID {
			folder = id
		}
		a.line(ui.MsgUnlockOK, ui.Vars{
			Folder: folder,
			N:      cfg.Policy.RestoreRecent,
			Idle:   cfg.Policy.IdleSoft.D(),
			Until:  resp.Until.In(a.sys.loc),
		})
	}
	// D48: weakening config edits wait for an interactive confirmation.
	if len(resp.Pending) > 0 && t != nil {
		a.showPending(resp.Pending)
		if ok, err := t.YesNo(textPolicyConfirm, false); err == nil && ok {
			if _, err := c.Policy(ctx, ipc.PolicyReq{Confirm: true}); err != nil {
				return a.fail("unlock", err)
			}
		}
	}
	return exitOK
}

// isCancel reports a user cancel (daemon code cancelled, or a local one).
func isCancel(err error) bool {
	var ie *ipc.Error
	if errors.As(err, &ie) {
		return ie.Code == ipc.CodeCancelled
	}
	return errors.Is(err, ui.ErrCancelled) || errors.Is(err, vault.ErrCancelled)
}

// folderList names the folders of an unlock request for messages.
func (a *app) folderList(cfg config.Config, req ipc.UnlockReq, targets []config.Root) string {
	if req.Global {
		return "the global vault"
	}
	var names []string
	for _, r := range targets {
		names = append(names, a.display(r.Path))
	}
	if len(names) == 0 {
		return "the folder"
	}
	return strings.Join(names, ", ")
}

func cmdLock(a *app, args []string) int {
	f := newFlags("lock")
	rootDir := f.String("root", "", "lock only the protected folder containing `DIR`")
	all := f.Bool("all", false, "lock every folder (the default)")
	end := f.Bool("end", false, "also end the sessions in the folders and seal them")
	hard := f.Bool("hard", false, "alias of --end")
	force := f.Bool("force", false, "with --end: do not wait for an in-flight compaction")
	letFinish := f.Bool("let-finish", false, "let busy turns finish before gating tools")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageFail(f, "unexpected argument "+pos[0])
	}
	if err := exclusive(map[string]bool{"root": *rootDir != "", "all": *all}); err != nil {
		return a.usageFail(f, err.Error())
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("lock", err)
	}
	// D50: no flag locks every folder.
	req := ipc.LockReq{All: true, End: *end || *hard, Force: *force, LetFinish: *letFinish}
	if *rootDir != "" {
		r, err := a.rootArg(cfg, *rootDir)
		if err != nil {
			return a.fail("lock", err)
		}
		req.All, req.RootIDs = false, []string{r.ID}
	}
	ctx := context.Background()
	c, err := a.dial(ctx, false)
	if err != nil {
		if errors.Is(err, ipc.ErrNoDaemon) {
			// Daemon start locks every vault (SPEC §12.5): nothing is
			// unlocked when it does not run.
			a.sayOut(textLockedNone)
			return exitOK
		}
		return a.fail("lock", err)
	}
	defer c.Close()
	resp, err := c.Lock(ctx, req)
	if err != nil {
		return a.fail("lock", err)
	}
	var names []string
	for _, id := range resp.Locked {
		if r, ok := cfg.RootByID(id); ok {
			names = append(names, a.display(r.Path))
		} else if id == vault.GlobalID {
			names = append(names, "the global vault")
		}
	}
	if len(names) == 0 {
		a.sayOut(textLockedNone)
	} else {
		a.sayOut(textLocked, strings.Join(names, ", "))
	}
	if len(resp.Ended) > 0 {
		a.sayOut(textEnded, len(resp.Ended))
	}
	if len(resp.Unsealed) > 0 {
		a.sayOut(textStillPlain, len(resp.Unsealed))
	}
	return exitOK
}
