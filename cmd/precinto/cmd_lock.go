package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
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
	all := f.Bool("all", false, "unlock every folder (type unlock to confirm; each folder asks for you once)")
	global := f.Bool("global", false, "unlock the global vault (Claude global stores)")
	dur := f.Duration("for", 0, "keep it unlocked at most `DUR` (capped by policy.max_unlock)")
	factor := f.String("factor", "", "the unlock method `NAME` to use (see precinto factor list)")
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
	if a.refuseWSL1() {
		return exitError
	}
	if err := a.sys.harden(); err != nil {
		return a.fail("unlock", err)
	}
	settings, err := a.config()
	if err != nil {
		return a.fail("unlock", err)
	}
	l, err := a.layout()
	if err != nil {
		return a.fail("unlock", err)
	}
	// D146: the folders the agent enforces can be named and unlocked, a
	// folder whose removal from config.toml waits for its confirmation
	// too, so the review of that change is reachable from the folder.
	cfg := a.enforcedConfig(settings, l)
	req := ipc.UnlockReq{Factor: *factor, TTL: *dur, Extend: *extend, Deadline: wireDeadline(unlockDeadline)}
	var targets []config.Root
	pick := false // outside every folder, on a terminal: choose (DC-35)
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
		case len(cfg.Roots) > 0 && a.sys.interactive() && !*extend:
			// --extend names an unlocked folder; picking is for locked ones.
			pick = true
		default:
			// Without a terminal only the working directory's folder can be
			// unlocked (SPEC §12.8).
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
	if pick && t == nil {
		wd, _ := a.sys.getwd()
		a.say(textUnlockWhich, a.display(wd))
		return exitUsage
	}
	if req.All && !req.Confirmed {
		// D40: typed confirmation on a TTY; without one only the folder
		// of the working directory can be unlocked (SPEC §12.8).
		if t == nil {
			a.line(ui.MsgNeedTerminal, ui.Vars{Command: "precinto unlock --all"})
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
	if pick {
		chosen, code, ok := a.pickLocked(ctx, c, t, cfg)
		if !ok {
			return code
		}
		targets, req.RootIDs = chosen, rootIDs(chosen)
		req.Confirmed = len(chosen) > 1 // typed "unlock" in pickLocked (D40)
	}
	resp, err := c.Unlock(ctx, req, relay)
	if err != nil {
		switch {
		case isCancel(err):
			a.line(ui.MsgUnlockCancelled, ui.Vars{Folder: a.folderList(cfg, req, targets)})
			a.retryHint(cfg)
			return exitLocked
		case isBadSecret(err):
			// CC-08: a wrong passphrase or recovery key is no tamper alert.
			a.line(ui.MsgUnlockBadSecret, ui.Vars{Folder: a.folderList(cfg, req, targets)})
			a.retryHint(cfg)
			return exitLocked
		}
		return a.fail("unlock", err)
	}
	if len(resp.Unlocked) == 0 {
		a.say(textAlreadyOpen, a.folderList(cfg, req, targets))
	}
	// D48: weakening config edits wait for an interactive confirmation.
	// The review comes first, so that C2.ok quotes the policy the
	// decision put in force (UX-14). A confirmation that fails still
	// leaves the folders unlocked: C2.ok says so (with the policy in
	// force) before the error.
	confirmed := false
	var confirmErr error
	pending := resp.Pending
	if t != nil && !req.Global {
		// D145: confirming adopts config.toml. While the confirmed
		// settings name no folder (signed by the global vault alone, which
		// a folder unlock never checks), the folders whose vault is kept
		// but that config.toml does not protect are named too, so that a
		// yes never drops one unseen. unlock --global checks that MAC
		// itself.
		for _, ch := range droppedFolderChanges(a.unprotectedFolders(settings, l)) {
			if !slices.Contains(pending, ch) {
				pending = append(pending, ch)
			}
		}
	}
	if len(pending) > 0 && t != nil {
		open := map[string]bool{}
		if st, err := c.Status(ctx); err == nil {
			open = unlockedVaults(st)
		}
		for _, id := range resp.Unlocked {
			open[id] = true
		}
		confirmed, confirmErr = a.confirmChanges(ctx, c, t, pending, settings, cfg, open, true)
	}
	pol := a.policyInForce(cfg)
	if confirmed {
		pol = settings.Policy // confirming makes config.toml the confirmed policy
	}
	for _, id := range resp.Unlocked {
		if id == vault.GlobalID {
			// Nothing is restored after a global unlock: what belongs to
			// no folder comes back with restore --global (D150).
			a.line(ui.MsgUnlockOKGlobal, ui.Vars{Idle: pol.IdleSoft.D(), Until: resp.Until.In(a.sys.loc)})
			continue
		}
		folder := id
		if r, ok := cfg.RootByID(id); ok {
			folder = a.display(r.Path)
		}
		a.line(ui.MsgUnlockOK, ui.Vars{
			Folder: folder,
			N:      pol.RestoreRecent,
			Idle:   pol.IdleSoft.D(),
			Until:  resp.Until.In(a.sys.loc),
		})
	}
	if confirmErr != nil {
		return a.fail("unlock", confirmErr)
	}
	return exitOK
}

// policyInForce is the policy the agent enforces (floorPolicy: config.toml
// merged with the confirmed settings), which is what the user's messages
// quote, never an unconfirmed weakening edit of config.toml (UX-14).
func (a *app) policyInForce(cfg config.Config) config.Policy {
	l, err := a.layout()
	if err != nil {
		return cfg.Policy
	}
	return floorPolicy(cfg, l)
}

// retryHint says when a cancelled or mistyped unlock can be tried again:
// the agent waits policy.prompt_backoff (the policy in force, D27) before
// it asks again, and refuses an earlier retry (C2.wait, UX-08).
func (a *app) retryHint(cfg config.Config) {
	if wait := a.policyInForce(cfg).PromptBackoff.D(); wait > 0 {
		a.line(ui.MsgUnlockRetry, ui.Vars{Wait: wait})
	}
}

// pickLocked chooses what `precinto unlock` unlocks outside every folder on
// a terminal (SPEC §12.8, DC-35): the one locked folder, or one of several
// by its number, or all of them after the typed "unlock" (C2.confirmall).
// ok is false when the command ends with code (nothing locked, a cancel).
func (a *app) pickLocked(ctx context.Context, c daemonClient, t terminal, cfg config.Config) ([]config.Root, int, bool) {
	open := map[string]bool{}
	if st, err := c.Status(ctx); err == nil {
		open = unlockedVaults(st)
	}
	var locked []config.Root
	for _, r := range cfg.Roots {
		if !open[r.ID] {
			locked = append(locked, r)
		}
	}
	switch len(locked) {
	case 0:
		a.sayOut(textAllOpen)
		return nil, exitOK, false
	case 1:
		return locked, 0, true
	}
	for i, r := range locked {
		a.say(textUnlockPickLine, i+1, a.display(r.Path))
	}
	answer, err := t.ReadLine(fmt.Sprintf(textUnlockPick, len(locked)))
	if err != nil {
		a.say(textNotConfirmed)
		return nil, exitLocked, false
	}
	answer = strings.TrimSpace(answer)
	if strings.EqualFold(answer, "all") {
		prompt := ui.Format(ui.MsgUnlockConfirmAll, ui.Vars{N: len(locked), Folder: a.display(locked[0].Path)})
		if err := a.typedWord(t, prompt, wordUnlock); err != nil {
			return nil, exitLocked, false
		}
		return locked, 0, true
	}
	n, err := strconv.Atoi(answer)
	if err != nil || n < 1 || n > len(locked) {
		a.say(textNotConfirmed)
		return nil, exitLocked, false
	}
	return locked[n-1 : n], 0, true
}

// isCancel reports a user cancel (daemon code cancelled, or a local one).
func isCancel(err error) bool {
	var ie *ipc.Error
	if errors.As(err, &ie) {
		return ie.Code == ipc.CodeCancelled
	}
	return errors.Is(err, ui.ErrCancelled) || errors.Is(err, vault.ErrCancelled)
}

// isBadSecret reports a wrong passphrase or recovery key (CC-08): the
// daemon's bad_secret code, or vault.ErrBadSecret from a local unwrap.
func isBadSecret(err error) bool {
	var ie *ipc.Error
	if errors.As(err, &ie) {
		return ie.Code == ipc.CodeBadSecret
	}
	return errors.Is(err, vault.ErrBadSecret)
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
	// D50: no flag locks every folder. Locking everything needs no
	// configuration, so a config.toml that does not load never stops it
	// (UX-09); only --root reads it, to find the folder.
	req := ipc.LockReq{All: true, End: *end || *hard, Force: *force, LetFinish: *letFinish}
	cfg, cfgErr := a.config()
	if l, err := a.layout(); err == nil && cfgErr == nil {
		cfg = a.enforcedConfig(cfg, l) // D142: a folder whose removal waits can be locked by name
	}
	if *rootDir != "" {
		if cfgErr != nil {
			code := a.fail("lock", cfgErr)
			a.say(textLockAllInstead)
			return code
		}
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
			a.reportBrokenConfig("lock", cfgErr)
			return exitOK
		}
		return a.fail("lock", err)
	}
	defer c.Close()
	resp, err := c.Lock(ctx, req)
	if err != nil {
		return a.fail("lock", err)
	}
	folders := map[string]string{}
	if cfgErr != nil {
		// The folders are named from the agent's own view: it keeps the
		// settings it loaded last.
		if st, err := c.Status(ctx); err == nil {
			for _, v := range st.Vaults {
				folders[v.VaultID] = v.RootPath
			}
		}
	}
	var names []string
	for _, id := range resp.Locked {
		if r, ok := cfg.RootByID(id); ok {
			names = append(names, a.display(r.Path))
		} else if p := folders[id]; p != "" {
			names = append(names, a.display(p))
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
	a.reportBrokenConfig("lock", cfgErr)
	return exitOK
}

// reportBrokenConfig tells the user, after a command that did its work
// without config.toml, that the file does not load and why (UX-09).
func (a *app) reportBrokenConfig(name string, err error) {
	if err == nil {
		return
	}
	a.say("%s: %s", name, oneLineText(err.Error()))
	a.say(textConfigBroken)
}
