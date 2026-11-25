package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/ledger"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/ui"
)

// D37 thresholds for prompt origins.
const (
	enterWindow  = 3 * time.Second // wrapped: Enter reached the PTY this recently
	hidHumanIdle = 5 * time.Second // unwrapped: HID idle at gate time at most this
	hidPollLimit = 60 * time.Millisecond
)

// connState is one client connection.
type connState struct {
	c           *ipc.Conn
	peer        platform.Peer
	same        bool // PeerSameExecutable at accept time
	hello       bool
	ttyUnlocked bool           // a TTY unlock succeeded on this connection (policy confirmation)
	repair      *pendingRepair // a vault_repair dry run's identity, bound to this connection (CC-32; d.mu)
}

func errResp(code ipc.Code, msg string) ipc.Response {
	return ipc.Response{Err: &ipc.Error{Code: code, Msg: msg}}
}

// serveConn reads requests until the client goes away. A protocol error
// closes the connection: its framing can no longer be trusted.
func (d *daemon) serveConn(ctx context.Context, c *ipc.Conn) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	peer, same := d.deps.peer(c)
	cs := &connState{c: c, peer: peer, same: same}
	defer func() {
		d.mu.Lock()
		p := cs.repair
		d.mu.Unlock()
		if p != nil {
			d.dropRepair(cs, p) // the identity never outlives its connection
		}
	}()
	for {
		req, sec, err := c.ReadRequest()
		if err != nil {
			var e *ipc.Error
			if errors.As(err, &e) {
				_ = c.WriteResponse(ipc.Response{ID: req.ID, Err: e})
			}
			return
		}
		if !cs.hello && req.Op != ipc.OpHello {
			destroyAll(sec)
			_ = c.WriteResponse(ipc.Response{ID: req.ID, Err: &ipc.Error{Code: ipc.CodeBadRequest, Msg: "hello first"}})
			return
		}
		if req.Op == ipc.OpSubscribe {
			destroyAll(sec)
			d.subscribe(ctx, cs, req)
			return
		}
		resp, out := d.dispatch(ctx, cs, req, sec)
		destroyAll(sec)
		resp.ID, resp.OK = req.ID, resp.Err == nil
		err = c.WriteResponse(resp, out...)
		destroyAll(out)
		if req.Op == ipc.OpShutdown {
			d.stop()
			return
		}
		if err != nil {
			return
		}
	}
}

func destroyAll(bs []*memguard.LockedBuffer) {
	for _, b := range bs {
		if b != nil {
			b.Destroy()
		}
	}
}

// stop ends the daemon (shutdown request): keys are wiped by serve.
func (d *daemon) stop() { d.shutOnce.Do(func() { close(d.shutdown) }) }

// dispatch answers one request.
func (d *daemon) dispatch(ctx context.Context, cs *connState, req ipc.Request, sec []*memguard.LockedBuffer) (ipc.Response, []*memguard.LockedBuffer) {
	switch req.Op {
	case ipc.OpHello:
		cs.hello = true
		return ipc.Response{Hello: &ipc.HelloResp{Version: d.o.Version, PID: os.Getpid(), Started: d.started, Protocol: ipc.Version}}, nil
	case ipc.OpStatus:
		st := d.status()
		return ipc.Response{Status: &st}, nil
	case ipc.OpGate:
		g := d.gate(ctx, cs, *req.Gate)
		return ipc.Response{Gate: &g}, nil
	case ipc.OpActivity:
		d.activity(cs, *req.Activity)
		return ipc.Response{}, nil
	case ipc.OpRegister:
		if e := d.register(ctx, cs, *req.Register); e != nil {
			return ipc.Response{Err: e}, nil
		}
		return ipc.Response{}, nil
	case ipc.OpUnregister:
		d.unregister(cs, *req.Unregister)
		return ipc.Response{}, nil
	case ipc.OpUnlock:
		return d.unlock(ctx, cs, req), nil
	case ipc.OpLock:
		r := d.lock(ctx, *req.Lock)
		return ipc.Response{Lock: &r}, nil
	case ipc.OpKeys:
		return d.keys(ctx, cs, *req.Keys)
	case ipc.OpVaultCreate:
		return d.vaultCreate(ctx, cs, req), nil
	case ipc.OpFactorAdd:
		return d.factorAdd(ctx, cs, req), nil
	case ipc.OpVaultRepair:
		return d.vaultRepair(ctx, cs, req, sec), nil
	case ipc.OpPolicy:
		return d.policyOp(cs, *req.Policy), nil
	case ipc.OpShutdown:
		d.logf("shutdown requested by pid %d", cs.peer.PID)
		return ipc.Response{}, nil
	case ipc.OpUIReply:
		return errResp(ipc.CodeBadRequest, "no prompt is waiting for an answer"), nil
	}
	return errResp(ipc.CodeBadRequest, "unknown operation"), nil
}

// gateEvent normalizes a harness event name (Claude, Codex and the
// experimental hosts' spellings).
func gateEvent(name string) GateEvent {
	switch strings.ToLower(name) {
	case "userpromptsubmit", "beforesubmitprompt", "userpromptsubmitted", "prompt":
		return GatePrompt
	case "pretooluse", "beforeshellexecution", "beforemcpexecution", "beforereadfile", "tool":
		return GateTool
	case "precompact", "compact":
		return GateCompact
	case "permissionrequest", "permission":
		return GatePermission
	case "sessionstart", "start":
		return GateStart
	}
	return GateEvent(name)
}

// rootsOf resolves the folders a set of paths touches in the effective
// configuration, plus advisory root ids that the configuration knows.
func (d *daemon) rootsOf(advisory []string, ps ...string) []string {
	eff := d.effective()
	var clean []string
	for _, p := range ps {
		if p != "" && filepath.IsAbs(p) {
			clean = append(clean, filepath.Clean(p))
		}
	}
	var roots []string
	for _, r := range eff.RootsFor(clean...) {
		roots = append(roots, r.ID)
	}
	for _, id := range advisory {
		if _, ok := eff.RootByID(id); ok {
			roots = append(roots, id)
		}
	}
	return dedupe(roots)
}

// gateRoots is the session's root set (SPEC §13.4): ledger taint ∪
// roots(project dir) ∪ roots(cwd) ∪ roots(paths), plus what the daemon
// already knows of the session.
func (d *daemon) gateRoots(q ipc.GateReq) []string {
	roots := d.rootsOf(q.Roots, append([]string{q.Cwd, q.ProjectDir}, q.Paths...)...)
	d.mu.Lock()
	roots = append(roots, d.taint[q.SID]...)
	d.mu.Unlock()
	if ss, ok := d.snap.Load().snap.Sessions[q.SID]; ok {
		roots = append(roots, ss.Info.RootIDs...)
	}
	return dedupe(roots)
}

// gate answers a hook (SPEC §13.4) from the published snapshot.
func (d *daemon) gate(ctx context.Context, cs *connState, q ipc.GateReq) ipc.GateResp {
	ev := gateEvent(q.Event)
	roots := d.gateRoots(q)
	now := d.now()
	eff := d.effective()
	host := q.Host
	if host == "" {
		host = q.Harness
	}
	if host == string(harness.Codex) && ev != GateStart {
		if resp, wrong := d.codexHome(q, codexRoots(eff, roots)); wrong {
			d.afterGate(q, roots)
			return resp
		}
	}
	if host == string(harness.ClaudeCode) && ev != GateStart {
		if resp, refused := d.claudeOnDrive(q, harnessRoots(eff, roots, harness.ClaudeCode)); refused {
			d.afterGate(q, roots)
			return resp
		}
	}
	var origin ipc.PromptOrigin
	if ev == GatePrompt {
		origin = d.origin(ctx, q, now)
		if id := promptID(q.PromptID, q.TurnID); q.SID != "" && id != "" {
			// Recorded before the response is written (D54).
			d.post(Input{Kind: InGateOrigin, SID: q.SID, PromptID: id, Origin: origin})
		}
		if origin == ipc.OriginHuman && q.SID != "" {
			d.mu.Lock()
			d.humanGate[q.SID] = now
			d.mu.Unlock()
		}
	}
	resp := decide(d.view(), eff.Policy, GateQuery{Event: ev, SID: q.SID, RootIDs: roots, Origin: origin, Trigger: q.Trigger}, d.folder)
	if resp.UnlockEligible {
		resp.UnlockEligible = d.hookUnlockPossible(roots)
	}
	d.afterGate(q, roots)
	return resp
}

func promptID(prompt, turn string) string {
	if prompt != "" {
		return prompt
	}
	return turn
}

// codexRoots are the roots of the gate that manage Codex (D72): their
// harness list names codex, an empty list being the default of both
// built-ins (config's effective harnesses, doctor's rootProtects).
func codexRoots(eff config.Config, roots []string) []string {
	return harnessRoots(eff, roots, harness.Codex)
}

// harnessRoots are the roots of the gate that manage harness h: their
// harness list names it, an empty list being the default of both
// built-ins.
func harnessRoots(eff config.Config, roots []string, h harness.ID) []string {
	var out []string
	for _, id := range roots {
		r, ok := eff.RootByID(id)
		if ok && (len(r.Harnesses) == 0 || slices.Contains(r.Harnesses, string(h))) {
			out = append(out, id)
		}
	}
	return out
}

// claudeOnDrive blocks, under WSL, a Claude session in a folder that
// manages Claude when its config folder (from its transcript path) or its
// temporary folder (from its scratchpad) is on a Windows drive, or one
// precinto cannot place (D156, C3.windrive): its transcripts and task
// files would hold the folder's content where Windows programs write
// unseen and no sweep seals; roots are the gate's roots that manage
// Claude. With none, or outside WSL (checkDrive returns nil at once),
// the session is answered by the lock state alone.
func (d *daemon) claudeOnDrive(q ipc.GateReq, roots []string) (ipc.GateResp, bool) {
	if len(roots) == 0 || d.deps.checkDrive == nil {
		return ipc.GateResp{}, false
	}
	for _, p := range []string{q.ConfigDir, q.TmpDir} {
		if p == "" || !filepath.IsAbs(p) || d.deps.checkDrive(filepath.Clean(p)) == nil {
			continue
		}
		msg := ui.Format(ui.MsgClaudeOnDrive, ui.Vars{Folder: d.folder(roots[0])})
		resp := ipc.GateResp{Verdict: ipc.VerdictBlock, Reason: "windows-drive", UserMessage: msg, ModelMessage: msg, State: gateStateLocked, RootIDs: roots}
		if ev := gateEvent(q.Event); ev == GateTool || ev == GatePermission {
			resp.Verdict = ipc.VerdictDeny
		}
		return resp, true
	}
	return ipc.GateResp{}, false
}

// codexHome blocks a Codex session in a folder that manages Codex whose
// CODEX_HOME is not that folder's sealed home (D31, D72, C3.codexhome);
// roots are the gate's roots that manage Codex. With none, the session is
// answered by the lock state alone.
func (d *daemon) codexHome(q ipc.GateReq, roots []string) (ipc.GateResp, bool) {
	if len(roots) == 0 {
		return ipc.GateResp{}, false
	}
	home := filepath.Clean(q.CodexHome)
	for _, id := range roots {
		if q.CodexHome != "" && filepath.IsAbs(q.CodexHome) && home == filepath.Clean(d.l.CodexHome(id)) {
			return ipc.GateResp{}, false
		}
	}
	msg := ui.Format(ui.MsgCodexWrongHome, ui.Vars{Folder: d.folder(roots[0])})
	resp := ipc.GateResp{Verdict: ipc.VerdictBlock, Reason: "codex-home", UserMessage: msg, ModelMessage: msg, State: gateStateLocked, RootIDs: roots}
	if ev := gateEvent(q.Event); ev == GateTool || ev == GatePermission {
		resp.Verdict = ipc.VerdictDeny
	}
	return resp, true
}

// afterGate records what a gate taught the daemon, off the response path:
// sticky taint, hook presence, and the harness process (re-measured here,
// never taken from the client, SPEC §9.1).
func (d *daemon) afterGate(q ipc.GateReq, roots []string) {
	d.mu.Lock()
	known := len(d.taint[q.SID]) > 0
	if q.SID != "" && len(roots) > 0 {
		d.taint[q.SID] = dedupe(append(d.taint[q.SID], roots...))
	}
	if q.SID != "" {
		d.sessSeen[q.SID] = d.now()
	}
	d.mu.Unlock()
	if q.SID == "" {
		return
	}
	harnessID := q.Harness
	if q.Host == string(harness.Codex) || q.Host == string(harness.ClaudeCode) {
		harnessID = q.Host
	}
	sid, pid := q.SID, q.PID
	d.goBackground(func() {
		taint := roots
		if !known {
			if s, err := d.deps.ledgerGet(harnessID, sid); err == nil {
				taint = dedupe(append(append([]string(nil), roots...), s.RootIDs...))
				d.mu.Lock()
				d.taint[sid] = dedupe(append(d.taint[sid], s.RootIDs...))
				d.mu.Unlock()
			} else if !errors.Is(err, ledger.ErrNotFound) {
				d.logf("ledger of a session: %v", err)
			}
		}
		info := SessionInfo{Harness: harnessID, SID: sid, RootIDs: taint, HooksSeen: true}
		if pid > 1 {
			if p, err := d.procs.Lookup(pid); err == nil && p.State != platform.StateZombie {
				if matchHarness(d.invs, d.effective(), harnessID, p) {
					info.Proc = p.ID
					d.mu.Lock()
					d.hookSeen[p.ID] = d.now()
					d.mu.Unlock()
				}
			}
		}
		if len(info.RootIDs) > 0 || !info.Proc.IsZero() {
			d.post(Input{Kind: InRegister, Session: &info})
		}
	})
}

// origin computes the origin of a prompt gate (D37, D54): a wrapped session
// is human iff its verified wrapper reported an Enter at most 3 s ago; an
// unwrapped one iff the system HID idle is at most 5 s; unknown when HID
// idle cannot be read.
func (d *daemon) origin(ctx context.Context, q ipc.GateReq, now instant) ipc.PromptOrigin {
	ss, ok := d.snap.Load().snap.Sessions[q.SID]
	if ok && ss.Info.Wrapper {
		d.mu.Lock()
		at, has := d.enterAt[sessionKey(ss.Info)]
		d.mu.Unlock()
		if has && !at.elapsed(now, enterWindow) {
			return ipc.OriginHuman
		}
		return ipc.OriginAutomated
	}
	return d.hidOrigin(ctx, now)
}

// hidOrigin classifies by HID idle: the cached console sample proves
// "human" when even its extrapolation stays within the bound; otherwise one
// bounded fresh poll decides.
func (d *daemon) hidOrigin(ctx context.Context, now instant) ipc.PromptOrigin {
	d.mu.Lock()
	h := d.hid
	d.mu.Unlock()
	if h.known {
		if _, m := h.at.since(now); h.idle+m <= hidHumanIdle {
			return ipc.OriginHuman
		}
	}
	pctx, cancel := context.WithTimeout(ctx, hidPollLimit)
	s, err := d.o.Screen(pctx)
	cancel()
	if err == nil && s.IdleKnown {
		d.mu.Lock()
		d.hid = hidSample{known: true, idle: s.HIDIdle, at: d.now()}
		d.mu.Unlock()
		if s.HIDIdle <= hidHumanIdle {
			return ipc.OriginHuman
		}
		return ipc.OriginAutomated
	}
	return ipc.OriginUnknown
}

// hookUnlockPossible refines UnlockEligible: every locked folder is within
// its hook rate limits and has a factor that can prompt without a
// terminal (D27).
func (d *daemon) hookUnlockPossible(roots []string) bool {
	v := d.view()
	for _, id := range roots {
		if vs, ok := v.vaults[id]; ok && vs.State == VaultUnlocked {
			continue
		}
		if ok, _, _ := d.limiter.check(id, true, false); !ok {
			return false
		}
		if !d.guiFactor(id) {
			return false
		}
	}
	return true
}

// activity applies an activity report (D23, D54). Input/Enter count only
// from the verified wrapper of the session; everything else is hook
// activity, which never moves the idle clock by itself.
func (d *daemon) activity(cs *connState, r ipc.ActivityReq) {
	now := d.now()
	in := Input{Kind: InActivity, SID: r.SID, PromptID: promptID(r.PromptID, r.TurnID), Activity: r.Kind}
	snap := d.snap.Load().snap
	switch r.Kind {
	case ipc.ActInput, ipc.ActEnter:
		var sess *SessionSnapshot
		if ss, ok := snap.Sessions[r.SID]; ok && r.SID != "" {
			sess = &ss
		} else {
			for _, ss := range snap.Sessions {
				if ss.Info.Wrapper && ss.Info.WrapperPID == cs.peer.Proc.ID {
					s := ss
					sess = &s
					break
				}
			}
		}
		if sess == nil || !sess.Info.Wrapper || !cs.same || sess.Info.WrapperPID.IsZero() || sess.Info.WrapperPID != cs.peer.Proc.ID {
			return // dropped (SEC-27)
		}
		key := sessionKey(sess.Info)
		in.SID, in.FromWrapper = key, true
		if r.Kind == ipc.ActEnter {
			d.mu.Lock()
			d.enterAt[key] = now
			d.mu.Unlock()
		}
	default:
		if r.SID == "" {
			return
		}
		ss, ok := snap.Sessions[r.SID]
		d.mu.Lock()
		if ok && !ss.Info.Proc.IsZero() {
			d.hookSeen[ss.Info.Proc] = now
		}
		d.sessSeen[r.SID] = now
		taint := append([]string(nil), d.taint[r.SID]...)
		d.mu.Unlock()
		if !ok {
			in.Session = &SessionInfo{Harness: r.Harness, SID: r.SID, RootIDs: taint, HooksSeen: true}
		}
		if r.Kind == ipc.ActSessionEnd && (!ok || ss.Info.Proc.IsZero()) {
			// No process to watch: the record would never go away.
			d.post(in)
			d.post(Input{Kind: InUnregister, SID: r.SID})
			return
		}
	}
	d.post(in)
}

// register measures and verifies a harness process (SPEC §9.1, S14): the
// pid must be a live process whose executable is the named harness.
// Wrapper=true is accepted only from the wrapper itself (D54).
func (d *daemon) register(ctx context.Context, cs *connState, r ipc.RegisterReq) *ipc.Error {
	if r.PID <= 1 {
		return &ipc.Error{Code: ipc.CodeBadRequest, Msg: "register: no harness process"}
	}
	p, err := d.procs.Lookup(r.PID)
	if err != nil || p.State == platform.StateZombie {
		return &ipc.Error{Code: ipc.CodeBadRequest, Msg: "register: the harness process is not running"}
	}
	eff := d.effective()
	if !harnessEnabled(eff, r.Harness) || !d.knownInventory(r.Harness) {
		return &ipc.Error{Code: ipc.CodeUnauthorized, Msg: "register: that harness is not enabled (precinto integrate)"}
	}
	if !matchHarness(d.invs, eff, r.Harness, p) {
		// The executable must match the harness's inventory (S14, CC-12).
		return &ipc.Error{Code: ipc.CodeUnauthorized, Msg: "register: the process is not a " + r.Harness + " process"}
	}
	now := d.now()
	info := SessionInfo{Harness: r.Harness, SID: r.SID, Proc: p.ID, Background: r.Background, Registered: true}
	d.mu.Lock()
	taint := append([]string(nil), d.taint[r.SID]...)
	d.mu.Unlock()
	info.RootIDs = dedupe(append(d.rootsOf(r.RootIDs, r.Cwd, r.ProjectDir), taint...))
	switch {
	case p.TTY != "":
		info.TTY = p.TTY // measured beats claimed
	case strings.HasPrefix(r.TTY, "/dev/") && filepath.Clean(r.TTY) == r.TTY:
		info.TTY = r.TTY
	}
	if r.Wrapper && cs.same && r.WrapperPID > 1 && r.WrapperPID == cs.peer.PID && !cs.peer.Proc.ID.IsZero() {
		info.Wrapper, info.WrapperPID = true, cs.peer.Proc.ID
	} else {
		info.HooksSeen = !r.Wrapper // a hook's registration is a hook event
	}
	d.mu.Lock()
	d.signalable[p.ID] = true
	if v := cleanVersion(r.Version); v != "" {
		d.versions[p.ID] = v // SessionStatus.Version (CC-49)
	}
	if info.HooksSeen || info.Wrapper {
		d.hookSeen[p.ID] = now
	}
	if r.SID != "" && len(info.RootIDs) > 0 {
		d.taint[r.SID] = dedupe(append(d.taint[r.SID], info.RootIDs...))
	}
	delete(d.ungated, p.ID)
	for k, a := range d.attention {
		if a.Code == ipc.AttnUngatedSession && a.PID == p.ID.PID {
			delete(d.attention, k)
		}
	}
	d.mu.Unlock()
	d.apply(ctx, Input{Kind: InRegister, Session: &info})
	return nil
}

// knownInventory reports whether an inventory exists for harness id.
func (d *daemon) knownInventory(id string) bool {
	for _, inv := range d.invs {
		if inv.ID == id {
			return true
		}
	}
	return false
}

// cleanVersion keeps a harness version string from register only when it
// looks like one (digits, letters, '.', '-', '+', '_', at most 64 bytes):
// status prints it, so a client can never inject text or sequences.
func cleanVersion(v string) string {
	if v == "" || len(v) > 64 {
		return ""
	}
	for _, c := range v {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '.', c == '-', c == '+', c == '_':
		default:
			return ""
		}
	}
	return v
}

// unregister removes a session. A wrapped session can only be removed by
// its own wrapper; anyone may report a session whose process is gone.
func (d *daemon) unregister(cs *connState, r ipc.UnregisterReq) {
	for _, ss := range d.snap.Load().snap.Sessions {
		match := (r.SID != "" && ss.Info.SID == r.SID) || (r.PID > 0 && ss.Info.Proc.PID == r.PID)
		if !match {
			continue
		}
		if ss.Info.Wrapper && (!cs.same || ss.Info.WrapperPID != cs.peer.Proc.ID) && d.procs.Alive(ss.Info.Proc) {
			continue
		}
		info := ss.Info
		d.post(Input{Kind: InUnregister, SID: info.SID, Session: &info})
	}
}

// lock locks folders now (SPEC §12.7): keys are wiped before the response
// is written; ending and sealing continue in the background (I15).
func (d *daemon) lock(ctx context.Context, r ipc.LockReq) ipc.LockResp {
	eff := d.effective()
	var ids []string
	for _, id := range r.RootIDs {
		if _, ok := eff.RootByID(id); ok || id == globalVault() {
			ids = append(ids, id)
		}
	}
	all := r.All || len(r.RootIDs) == 0
	acts := d.apply(ctx, Input{Kind: InLock, Vaults: ids, All: all, End: r.End, Force: r.Force, LetFinish: r.LetFinish})
	resp := ipc.LockResp{Locked: []string{}}
	if all {
		resp.Locked = vaultIDs(eff)
	} else {
		resp.Locked = ids
	}
	sort.Strings(resp.Locked)
	for _, a := range acts {
		if a.Kind == ActEndSessions {
			for _, s := range a.Sessions {
				if s.SID != "" && !slices.Contains(resp.Ended, s.SID) {
					resp.Ended = append(resp.Ended, s.SID)
				}
			}
		}
	}
	return resp
}
