package agent

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/ui"
	"github.com/Neorichi/precinto/internal/vault"
)

// errNoVault reports a folder without a vault.
var errNoVault = errors.New("agent: the folder has no vault")

// relayUI is the vault.UI of one unlock (D4): prompts are relayed to the
// requesting client's terminal, or to pinentry when it has none. Prompt
// texts are the daemon's, built from verified data (D27).
type relayUI struct {
	ctx    context.Context
	cs     *connState
	id     uint64
	seq    int
	tty    bool
	gui    bool
	folder string
	pin    func(ctx context.Context, desc, prompt string) (*memguard.LockedBuffer, error)
	desc   string
}

func (u *relayUI) send(r ipc.UIRequest) error {
	u.seq++
	r.Seq = u.seq
	return u.cs.c.WriteResponse(ipc.Response{ID: u.id, OK: true, UI: &r})
}

// reply reads the client's answer to the prompt just sent.
func (u *relayUI) reply() (*ipc.UIReply, []*memguard.LockedBuffer, error) {
	req, sec, err := u.cs.c.ReadRequest()
	if err != nil {
		return nil, nil, vault.ErrCancelled
	}
	if req.Op != ipc.OpUIReply || req.UIReply == nil || req.UIReply.Seq != u.seq {
		destroyAll(sec)
		return nil, nil, vault.ErrCancelled
	}
	return req.UIReply, sec, nil
}

// Display shows a line on the requester's terminal; a terminal-less
// requester gets the text with the pinentry dialog instead.
func (u *relayUI) Display(msg string) error {
	if !u.tty {
		return nil
	}
	return u.send(ipc.UIRequest{Kind: ipc.UIDisplay, Prompt: msg})
}

// Secret asks for a passphrase or PIN. The prompt names the folder; the
// factor's own wording is kept after it.
func (u *relayUI) Secret(prompt string) (*memguard.LockedBuffer, error) {
	text := ui.Format(ui.MsgUnlockPassphrase, ui.Vars{Folder: u.folder})
	if prompt != "" && !isPassphrasePrompt(prompt) {
		text = "precinto: " + u.folder + ": " + prompt
	}
	if u.tty {
		if err := u.send(ipc.UIRequest{Kind: ipc.UISecret, Prompt: text}); err != nil {
			return nil, vault.ErrCancelled
		}
		r, sec, err := u.reply()
		if err != nil {
			return nil, err
		}
		if !r.OK || !r.HasSecret || len(sec) != 1 {
			destroyAll(sec)
			return nil, vault.ErrCancelled
		}
		return sec[0], nil
	}
	if u.pin != nil {
		b, err := u.pin(u.ctx, u.desc, text)
		if err != nil {
			if errors.Is(err, errPinentryCancelled) {
				return nil, vault.ErrCancelled
			}
			return nil, vault.ErrNoUI
		}
		return b, nil
	}
	return nil, vault.ErrNoUI
}

// isPassphrasePrompt reports a generic passphrase prompt that the daemon's
// C2.passphrase text replaces: the passphrase factor's own prompt
// (internal/vault promptPassphrase, "precinto passphrase") and the usual
// generic wordings.
func isPassphrasePrompt(p string) bool {
	switch strings.TrimSpace(p) {
	case "precinto passphrase", "precinto passphrase:",
		"passphrase", "Passphrase", "Enter passphrase", "Enter passphrase:", "passphrase:":
		return true
	}
	return false
}

// Confirm asks a question on the requester's terminal (pinentry has no
// confirm here: ErrNoUI).
func (u *relayUI) Confirm(prompt, yes, no string) (bool, error) {
	if !u.tty {
		return false, vault.ErrNoUI
	}
	if err := u.send(ipc.UIRequest{Kind: ipc.UIConfirm, Prompt: prompt, Yes: yes, No: no}); err != nil {
		return false, vault.ErrCancelled
	}
	r, sec, err := u.reply()
	destroyAll(sec)
	if err != nil {
		return false, err
	}
	if !r.OK {
		return false, vault.ErrCancelled
	}
	return r.Choice, nil
}

func (u *relayUI) Interactive() bool { return u.tty || u.pin != nil }
func (u *relayUI) GUI() bool         { return u.gui }

// newRelayUI builds the UI of one vault unwrap for a request.
func (d *daemon) newRelayUI(ctx context.Context, cs *connState, reqID uint64, tty bool, id string) *relayUI {
	u := &relayUI{ctx: ctx, cs: cs, id: reqID, tty: tty, folder: d.folder(id)}
	v := d.snap.Load()
	u.gui = !v.screenLocked && d.daemonGUI()
	if !tty {
		u.pin = d.o.Pinentry
		exe := cs.peer.Proc.Exe
		if exe == "" {
			exe = "pid " + strconv.Itoa(cs.peer.PID)
		}
		u.desc = "precinto: " + exe + " asks to unlock " + u.folder + "."
	}
	return u
}

// daemonGUI reports whether the daemon's own session can show a dialog.
func (d *daemon) daemonGUI() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.screenOK
}

// unlockTargets resolves which vaults a request unlocks.
func (d *daemon) unlockTargets(r ipc.UnlockReq, eff config.Config) ([]string, *ipc.Error) {
	var roots []string
	for _, rt := range eff.Roots {
		roots = append(roots, rt.ID)
	}
	switch {
	case r.Global:
		return []string{vault.GlobalID}, nil
	case r.All:
		if len(roots) == 0 {
			return nil, &ipc.Error{Code: ipc.CodeBadRequest, Msg: "precinto: no folder is protected"}
		}
		return roots, nil
	case len(r.RootIDs) > 0:
		for _, id := range r.RootIDs {
			if _, ok := eff.RootByID(id); !ok && id != vault.GlobalID {
				return nil, &ipc.Error{Code: ipc.CodeBadRequest, Msg: "precinto: that folder is not protected"}
			}
		}
		ids := dedupe(r.RootIDs)
		if !eff.Policy.PerRootAuth && r.TTY {
			// per_root_auth = false: unlock covers every folder, one
			// prompt each (D40).
			return dedupe(append(ids, roots...)), nil
		}
		return ids, nil
	}
	return nil, &ipc.Error{Code: ipc.CodeBadRequest, Msg: "precinto: name a folder (--root DIR) or use --all"}
}

// unlock runs an unlock request (SPEC §12.8).
func (d *daemon) unlock(ctx context.Context, cs *connState, req ipc.Request) ipc.Response {
	r := *req.Unlock
	if !cs.same {
		return errResp(ipc.CodeUnauthorized, "precinto: only precinto itself can unlock folders")
	}
	eff := d.effective()
	targets, e := d.unlockTargets(r, eff)
	if e != nil {
		return ipc.Response{Err: e}
	}
	f := d.peerFacts(cs.peer, r.AgentMarkers)
	sessRoots := d.sessionRoots(f, cs.peer)
	if r.Test && (f.agent || f.noCTTY) && !f.self && !f.worker {
		// `precinto factor test` is a factor operation: never from an
		// agent context or a peer without a terminal (D28, D59).
		return ipc.Response{Err: refuse("test a factor of", d.folder(targets[0]), "factor test")}
	}
	if e := authorizeFacts(f, ipc.OpUnlock, "", targets, sessRoots, d.folder); e != nil {
		return ipc.Response{Err: e}
	}
	if len(targets) > 1 && (!r.TTY || !r.Confirmed) {
		return errResp(ipc.CodeBadRequest, ui.Format(ui.MsgUnlockConfirmAll, ui.Vars{N: len(targets), Folder: d.folder(targets[0])}))
	}
	if (!r.TTY || f.noCTTY) && !f.self && !f.worker {
		// Without a terminal only the folder of the requester's cwd (or of
		// the session it runs in) can be unlocked (SPEC §12.8). A peer with
		// no controlling terminal at all counts as an agent context for
		// this refusal (D59: setsid and double forks defeat ancestry).
		allowed := append([]string(nil), sessRoots...)
		if cwd, err := d.procs.Cwd(cs.peer.Proc.ID); err == nil && cwd != "" {
			allowed = append(allowed, d.rootsOf(nil, cwd)...)
		}
		for _, id := range targets {
			if slices.Contains(allowed, id) {
				continue
			}
			if f.noCTTY {
				return ipc.Response{Err: refuse("unlock", d.folder(id), "unlock "+targetArg(id, d.folder))}
			}
			return errResp(ipc.CodeNoUI, ui.Format(ui.MsgPromptBlocked, ui.Vars{Folder: d.folder(id), Reason: ui.ReasonStart}))
		}
	}
	if r.FromHook {
		if r.Test {
			return errResp(ipc.CodeBadRequest, "precinto: a factor test runs in a terminal (precinto factor test)")
		}
		if e := d.hookUnlockAllowed(r, targets); e != nil {
			return ipc.Response{Err: e}
		}
	}
	wait := ttyUnlockWait
	if !r.TTY {
		wait = hookUnlockWait
	}
	deadline := time.Now().Add(wait)
	if !r.Deadline.IsZero() && r.Deadline.Before(deadline) {
		deadline = r.Deadline
	}
	uctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// A client that stops answering while a prompt waits is dropped when
	// the deadline passes.
	stop := context.AfterFunc(uctx, func() {
		if errors.Is(uctx.Err(), context.DeadlineExceeded) {
			_ = cs.c.Close()
		}
	})
	defer stop()
	if r.Test {
		// A factor test (CC-50): one unwrap with the named factor and the
		// recipient check per vault, then the identity is dropped. No
		// grant, no restore worker, no policy re-pin, nothing unlocked.
		for _, id := range targets {
			if e := d.testOne(uctx, cs, req.ID, r, id); e != nil {
				return ipc.Response{Err: e}
			}
		}
		return ipc.Response{Unlock: &ipc.UnlockResp{Unlocked: []string{}}}
	}
	var unlocked []string
	for _, id := range targets {
		if e := d.unlockOne(uctx, cs, req.ID, r, id); e != nil {
			return ipc.Response{Err: e}
		}
		unlocked = append(unlocked, id)
	}
	if r.TTY && !f.agent && !f.noCTTY && !f.worker {
		cs.ttyUnlocked = true
		if err := d.pinPolicy(ctx, r.ConfirmDiff); err != nil && !errors.Is(err, errPending) {
			d.logf("pin policy: %v", err)
		}
	}
	resp := ipc.UnlockResp{Unlocked: unlocked}
	v := d.view()
	for _, id := range unlocked {
		if vs, ok := v.vaults[id]; ok && (resp.Until.IsZero() || vs.AbsDeadline.Before(resp.Until)) {
			resp.Until = vs.AbsDeadline
		}
	}
	d.mu.Lock()
	resp.Pending = pendingText(d.pol.pending)
	d.mu.Unlock()
	if len(resp.Pending) == 0 && cs.ttyUnlocked {
		// D91: the pin waits for an authenticated re-pin; the user
		// confirms the settings that weaken the defaults instead.
		resp.Pending = pendingText(d.unverifiedPending())
	}
	return ipc.Response{Unlock: &resp}
}

// hookUnlockAllowed applies the conditions of a hook-raised unlock (SPEC
// §12.8): unlock_on_prompt, a human origin recorded for the session's
// prompt, the screen known and not locked, a factor that can prompt
// without a terminal. Automated or unknown origins never raise a dialog
// (D26, D54).
func (d *daemon) hookUnlockAllowed(r ipc.UnlockReq, targets []string) *ipc.Error {
	eff := d.effective()
	noUI := func() *ipc.Error {
		return &ipc.Error{Code: ipc.CodeNoUI, Msg: ui.Format(ui.MsgPromptBlocked, ui.Vars{Folder: d.folder(targets[0]), Reason: ui.ReasonStart})}
	}
	if !eff.Policy.UnlockOnPrompt || r.SID == "" {
		return noUI()
	}
	now := d.now()
	d.mu.Lock()
	at, ok := d.humanGate[r.SID]
	d.mu.Unlock()
	if !ok || at.elapsed(now, hookUnlockWait) {
		return noUI()
	}
	v := d.snap.Load()
	if !v.screenKnown || v.screenLocked {
		return noUI()
	}
	for _, id := range targets {
		if !d.guiFactor(id) {
			return noUI()
		}
	}
	return nil
}

// unlockOne unlocks one vault: rate limits (D27), single flight (concurrent
// requesters share the result), one fresh presence unwrap, recipient
// verification (D5), pinned-policy MAC check (D55), then the grant.
func (d *daemon) unlockOne(ctx context.Context, cs *connState, reqID uint64, r ipc.UnlockReq, id string) *ipc.Error {
	if vs, ok := d.view().vaults[id]; ok && vs.State == VaultUnlocked && !r.Extend {
		return nil
	}
	fl, leader := d.limiter.join(id)
	if !leader {
		return d.unlockErr(id, fl.wait(ctx))
	}
	if ok, wait, why := d.limiter.check(id, r.FromHook, true); !ok {
		err := errRateLimited{wait: wait, why: why}
		d.limiter.finish(id, fl, err)
		return d.unlockErr(id, err)
	}
	err := d.unwrapAndGrant(ctx, cs, reqID, r, id)
	if errors.Is(err, vault.ErrCancelled) || errors.Is(err, vault.ErrBadSecret) {
		// A wrong secret counts toward the prompt rate limit like a
		// cancel (D27), never as a tamper alert.
		d.limiter.cancelled(id, r.FromHook)
	}
	d.limiter.finish(id, fl, err)
	return d.unlockErr(id, err)
}

// testOne is one vault of a factor test (CC-50): the prompt rate limits
// apply as for an unlock, but a test never joins or blocks an unlock's
// single flight and never grants: the identity is checked against the
// vault (recipient and MAC, D5) and destroyed.
func (d *daemon) testOne(ctx context.Context, cs *connState, reqID uint64, r ipc.UnlockReq, id string) *ipc.Error {
	if ok, wait, why := d.limiter.check(id, false, true); !ok {
		return d.unlockErr(id, errRateLimited{wait: wait, why: why})
	}
	err := d.unwrapAndCheck(ctx, cs, reqID, r, id)
	if errors.Is(err, vault.ErrCancelled) || errors.Is(err, vault.ErrBadSecret) {
		d.limiter.cancelled(id, false)
	}
	return d.unlockErr(id, err)
}

// unwrapAndCheck unwraps vault id with the requested factor, verifies the
// identity and destroys it (the body of a factor test).
func (d *daemon) unwrapAndCheck(ctx context.Context, cs *connState, reqID uint64, r ipc.UnlockReq, id string) error {
	if !d.vaultExists(id) {
		return errNoVault
	}
	identity, err := d.deps.vaults.unwrap(ctx, id, r.Factor, d.newRelayUI(ctx, cs, reqID, r.TTY, id))
	if err != nil {
		return err
	}
	defer identity.Destroy()
	if err := d.deps.vaults.verify(id, identity); err != nil {
		if isVerifyErr(err) {
			d.setAttention(ipc.Attention{Code: ipc.AttnVaultTampered, Folder: d.folder(id), Fix: "precinto vault repair " + targetArg(id, d.folder)}, true)
		}
		return err
	}
	d.logf("factor test of %s passed", id)
	return nil
}

// errRateLimited carries the wait of a refused prompt and the rule that
// refused it.
type errRateLimited struct {
	wait time.Duration
	why  limitWhy
}

func (e errRateLimited) Error() string { return "agent: unlock prompts rate-limited" }

func (d *daemon) unwrapAndGrant(ctx context.Context, cs *connState, reqID uint64, r ipc.UnlockReq, id string) error {
	if !d.vaultExists(id) {
		return errNoVault
	}
	u := d.newRelayUI(ctx, cs, reqID, r.TTY, id)
	if !r.TTY {
		// The hook has no terminal: tell the session's terminal who asks
		// before the dialog appears (D60).
		d.notifySession(r.SID, id)
	}
	identity, err := d.deps.vaults.unwrap(ctx, id, r.Factor, u)
	if err != nil {
		return err
	}
	if err := d.deps.vaults.verify(id, identity); err != nil {
		identity.Destroy()
		if isVerifyErr(err) {
			d.setAttention(ipc.Attention{Code: ipc.AttnVaultTampered, Folder: d.folder(id), Fix: "precinto vault repair " + targetArg(id, d.folder)}, true)
		}
		return err
	}
	if err := d.deps.keyring.Put(id, identity); err != nil {
		return err
	}
	d.setAttention(ipc.Attention{Code: ipc.AttnVaultTampered, Folder: d.folder(id)}, false)
	d.verifyPinnedMAC(ctx, id)
	d.apply(ctx, Input{Kind: InUnlock, Vaults: []string{id}, TTL: r.TTL, Extend: r.Extend})
	if !d.deps.keyring.Has(id) {
		// A lock arrived between storing the key and the grant: the lock
		// wins (I15). Re-lock so state and key holder agree.
		d.apply(ctx, Input{Kind: InLock, Vaults: []string{id}})
		return vault.ErrCancelled
	}
	d.logf("unlocked %s", id)
	return nil
}

// notifySession sends the OSC 9 notice (C2.hook) to the terminal of the
// session asking for a hook-raised unlock.
func (d *daemon) notifySession(sid, id string) {
	ss, ok := d.snap.Load().snap.Sessions[sid]
	if !ok || ss.Info.TTY == "" {
		return
	}
	harnessName := ss.Info.Harness
	if harnessName == "claude-code" {
		harnessName = "claude"
	}
	_ = d.deps.notify(ss.Info.TTY, ui.Format(ui.MsgUnlockHook, ui.Vars{Harness: harnessName, Folder: d.folder(id)}))
}

// isVerifyErr reports the failures that mean "the vault was tampered with".
func isVerifyErr(err error) bool {
	return errors.Is(err, vault.ErrMACMismatch) || errors.Is(err, vault.ErrWrongIdentity) ||
		errors.Is(err, vault.ErrRecipientsChanged) || errors.Is(err, vault.ErrPluginPin)
}

// noUIText says why no prompt could unlock vault id (UX-15): the Secure
// Enclave's dialog cannot appear (C2.nogui: tmux, SSH, no GUI session) for
// a folder that has that factor; a passphrase or a security key needs a
// terminal (C2.needtty).
func (d *daemon) noUIText(id, folder string) string {
	kinds := d.factorKinds(id)
	if slices.Contains(kinds, string(vault.FactorSE)) {
		return ui.Format(ui.MsgUnlockNoGUI, ui.Vars{Folder: folder})
	}
	if f := ui.FactorName(kinds, false); f != "" {
		return ui.Format(ui.MsgUnlockNeedTTY, ui.Vars{Folder: folder, Factor: f})
	}
	return ui.Format(ui.MsgUnlockNeedTTYPlain, ui.Vars{Folder: folder})
}

// unlockErr maps an unlock failure to a protocol error with catalog text.
func (d *daemon) unlockErr(id string, err error) *ipc.Error {
	if err == nil {
		return nil
	}
	folder := d.folder(id)
	var rl errRateLimited
	switch {
	case errors.As(err, &rl):
		// UX-08: catalog text that says why precinto waits (D27) and how
		// long is left, in whole seconds rounded up.
		wait := (rl.wait + time.Second - 1).Truncate(time.Second)
		if wait < time.Second {
			wait = time.Second
		}
		switch rl.why {
		case limitOff:
			// prompt_rate_per_minute = 0 turns prompts off: no wait ends
			// it, so say which setting and what to change.
			return &ipc.Error{Code: ipc.CodeRateLimited, Msg: ui.Format(ui.MsgUnlockPromptsOff, ui.Vars{Folder: folder})}
		case limitRate:
			return &ipc.Error{Code: ipc.CodeRateLimited, Msg: ui.Format(ui.MsgUnlockTooMany, ui.Vars{Folder: folder, N: d.limiter.perMinuteLimit(), Wait: wait})}
		}
		return &ipc.Error{Code: ipc.CodeRateLimited, Msg: ui.Format(ui.MsgUnlockWait, ui.Vars{Folder: folder, Wait: wait})}
	case errors.Is(err, vault.ErrBadSecret):
		return &ipc.Error{Code: ipc.CodeBadSecret, Msg: ui.Format(ui.MsgUnlockBadSecret, ui.Vars{Folder: folder})}
	case errors.Is(err, vault.ErrCancelled), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return &ipc.Error{Code: ipc.CodeCancelled, Msg: ui.Format(ui.MsgUnlockCancelled, ui.Vars{Folder: folder})}
	case errors.Is(err, vault.ErrNoUI):
		return &ipc.Error{Code: ipc.CodeNoUI, Msg: d.noUIText(id, folder)}
	case isVerifyErr(err):
		return &ipc.Error{Code: ipc.CodeVerify, Msg: ui.Format(ui.MsgVaultTampered, ui.Vars{Folder: folder, Global: id == vault.GlobalID})}
	case errors.Is(err, errNoVault), errors.Is(err, vault.ErrNotFound):
		return &ipc.Error{Code: ipc.CodeBadRequest, Msg: "precinto: " + folder + " has no vault; run precinto protect"}
	}
	d.logf("unlock %s failed: %v", id, err)
	return &ipc.Error{Code: ipc.CodeInternal, Msg: "precinto: unlocking " + folder + " failed; run precinto doctor"}
}
