package hook

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/ui"
)

// Timing constants of the hook's own daemon traffic.
const (
	// activityBudget bounds fire-and-forget activity reports.
	activityBudget = ipc.GateBudget
	// sessionEndBudget bounds the best-effort session_end report: SessionEnd
	// must return within 100 ms (HOOKS-IO §2.5).
	sessionEndBudget = 50 * time.Millisecond
	// sweepEvery is the age of state/sweep.last after which SessionStart
	// spawns an opportunistic sweep (SPEC §10.1).
	sweepEvery = 10 * time.Minute
	// codexSealDeadline is how long a Codex seal request may wait for the
	// writer lock and the codex process (HA17).
	codexSealDeadline = 6 * time.Hour
)

// Gate states the daemon reports (ipc.GateResp.State).
const stateUnlocked = "unlocked"

// Workers the hook starts (argv after the precinto executable).
var (
	sealWorker  = []string{"seal", "--queue"}
	sweepWorker = []string{"sweep", "--quiet"}
)

// session is what handle knows about the session before deciding.
type session struct {
	harness string          // ledger and daemon harness name (the argv label)
	ledger  ledger.Session  // folded ledger; zero when none exists
	found   bool            // a ledger exists
	unknown bool            // the ledger could not be read: managed-ness unknown
	static  []config.Root   // roots the payload's dirs and paths touch, deepest first
	rootIDs []string        // ledger taint first (the primary root), then static
	managed bool            // taint, a static root, or an unreadable ledger
	folder  string          // display folder for messages
	proc    platform.ProcID // the harness process, measured by precinto
	home    string          // HOME, for ~-shortened folders
	cfg     config.Config   // effective policy
	now     time.Time       // decision time
}

// handle implements Handle; prog (may be nil) receives what Main needs to
// fail closed if handle panics or overruns the deadline.
func handle(ctx context.Context, d Deps, p Payload, prog *progress) Decision {
	s := prepare(d, p)
	prog.learned(s.managed, s.folder)
	if !s.managed {
		// Unmanaged sessions fail open and leave no trace (SPEC §14.3);
		// SessionStart still starts the opportunistic sweep (SPEC §10.1).
		if p.Event == SessionStart {
			maybeSweep(d, p, s)
		}
		return Decision{Verdict: ipc.VerdictAllow}
	}
	if !isGate(p.Host, p.Event) && duplicate(d, p) {
		// The same non-gate event of an experimental host already ran
		// through the other hooks file (HA21): its side effects are done.
		return Decision{Verdict: ipc.VerdictAllow}
	}
	recordFacts(d, p, s)

	switch p.Event {
	case SessionStart:
		return sessionStart(ctx, d, p, s)
	case UserPromptSubmit, PreToolUse, PermissionRequest, PreCompact:
		if isGate(p.Host, p.Event) {
			return gate(ctx, d, p, s)
		}
		// A host that cannot block this event (Copilot prompts, Cursor
		// compaction): observe only.
		report(ctx, d, p, s, observeKind(p.Event))
	case PostToolUse:
		report(ctx, d, p, s, ipc.ActTool)
	case PostCompact:
		report(ctx, d, p, s, ipc.ActCompactEnd)
	case Stop:
		report(ctx, d, p, s, ipc.ActStop)
	case StopFailure:
		report(ctx, d, p, s, ipc.ActStopFailure)
	case Interrupt:
		report(ctx, d, p, s, ipc.ActInterrupt)
	case Notification:
		switch p.Notification {
		case "idle_prompt":
			report(ctx, d, p, s, ipc.ActIdlePrompt)
		case "permission_prompt", "elicitation_dialog", "elicitation_url_dialog":
			report(ctx, d, p, s, ipc.ActPermission)
		}
	case SessionEnd:
		sessionEnd(ctx, d, p, s)
	}
	return Decision{Verdict: ipc.VerdictAllow}
}

// observeKind is the activity a non-blocking gate-like event reports.
func observeKind(ev Event) ipc.ActivityKind {
	switch ev {
	case UserPromptSubmit:
		return ipc.ActPrompt
	case PreCompact:
		return ipc.ActCompactBegin
	case PermissionRequest:
		return ipc.ActPermission
	}
	return ipc.ActTool
}

// prepare folds what is known about the session: its ledger, the roots the
// payload touches, the harness process and the display folder.
func prepare(d Deps, p Payload) *session {
	s := &session{harness: harnessName(p), cfg: d.Cfg, now: nowOf(d)}
	if h, err := paths.UserHome(d.Env); err == nil {
		s.home = h
	}
	if p.SID != "" && d.Ledger != nil {
		ls, err := d.Ledger.Get(s.harness, p.SID)
		switch {
		case err == nil:
			s.ledger, s.found = ls, true
		case errors.Is(err, ledger.ErrNotFound):
		default:
			// An unreadable ledger may hold a taint: treat the session as
			// managed (fail closed).
			s.unknown = true
		}
	}
	s.static = ledger.Taint(d.Cfg, taintCandidates(p)...)
	s.rootIDs = append([]string(nil), s.ledger.RootIDs...)
	for _, r := range s.static {
		if r.ID != "" && !slices.Contains(s.rootIDs, r.ID) {
			s.rootIDs = append(s.rootIDs, r.ID)
		}
	}
	s.managed = len(s.ledger.RootIDs) > 0 || len(s.static) > 0 || s.unknown
	s.proc = p.HarnessProc
	if s.proc.IsZero() && p.HarnessPID > 1 && d.Identify != nil {
		if id, err := d.Identify(p.HarnessPID); err == nil {
			s.proc = id
		}
	}
	s.folder = s.folderFor(nil, p)
	return s
}

// taintCandidates are the directories and paths that make a session
// managed: start/payload cwd, CLAUDE_PROJECT_DIR, cwd changes, added
// directories and tool paths (SPEC §14.3, HA10).
func taintCandidates(p Payload) []string {
	c := []string{p.Cwd, p.ProjectDir, p.OldCwd, p.NewCwd}
	c = append(c, p.AddedDirs...)
	return append(c, p.Paths...)
}

// harnessName is the harness the ledger, the queue and the daemon see: the
// argv label (a Claude-format hook in another host keeps claude-code and
// records the real host separately, HA21).
func harnessName(p Payload) string {
	if _, ok := labelHosts[p.Label]; ok {
		return p.Label
	}
	return string(p.Host)
}

func nowOf(d Deps) time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// folderFor returns the ~-shortened path of the first configured root among
// ids (the daemon's answer), else the session's deepest static root, else
// its primary (ledger) root, else the payload cwd or project directory.
func (s *session) folderFor(ids []string, p Payload) string {
	for _, id := range ids {
		if r, ok := s.cfg.RootByID(id); ok {
			return paths.Tilde(s.home, r.Path)
		}
	}
	if len(s.static) > 0 {
		return paths.Tilde(s.home, s.static[0].Path)
	}
	for _, id := range s.ledger.RootIDs {
		if r, ok := s.cfg.RootByID(id); ok {
			return paths.Tilde(s.home, r.Path)
		}
	}
	for _, dir := range []string{p.Cwd, p.ProjectDir} {
		if dir != "" {
			return paths.Tilde(s.home, dir)
		}
	}
	return ""
}

// recordFacts appends the content-free ledger facts of the event (SPEC
// §14.2): a start at the first managed contact, new taints, cwd changes,
// tool touches, agent-written Markdown, compaction and the end. Ledger
// write errors never change the decision.
func recordFacts(d Deps, p Payload, s *session) {
	if d.Ledger == nil || p.SID == "" {
		return
	}
	base := ledger.Event{
		V:       ledger.Version,
		T:       s.now,
		Harness: s.harness,
		SID:     p.SID,
		Proc:    s.proc,
	}
	if p.Host != hostOfLabel(p.Label) {
		base.Host = string(p.Host)
	}
	add := func(e ledger.Event) { _ = d.Ledger.Append(e) }
	with := func(t ledger.Type, f func(*ledger.Event)) {
		e := base
		e.Type = t
		if f != nil {
			f(&e)
		}
		add(e)
	}

	if p.Event == SessionStart || !s.found {
		with(ledger.TypeStart, func(e *ledger.Event) {
			if p.Event == SessionStart {
				e.Source = p.Source
			}
			e.Cwd = p.Cwd
			e.ProjectDir = p.ProjectDir
			e.Transcript = p.TranscriptPath
			e.ConfigDir = p.ConfigDir
			e.TmpDir = tmpBase(p)
			e.HarnessVersion = p.HarnessVersion
			e.Entrypoint = p.Entrypoint
			e.Background = codexDaemonHeld(d, p)
		})
	} else if p.Cwd != "" && p.Event != CwdChanged && lastCwd(s.ledger) != p.Cwd {
		with(ledger.TypeCwd, func(e *ledger.Event) { e.Cwd = p.Cwd })
	}
	var fresh []string
	for _, r := range s.static {
		if r.ID != "" && !slices.Contains(s.ledger.RootIDs, r.ID) && !slices.Contains(fresh, r.ID) {
			fresh = append(fresh, r.ID)
		}
	}
	if len(fresh) > 0 {
		with(ledger.TypeTaint, func(e *ledger.Event) { e.Roots = fresh })
	}
	if s.ledger.Wrapper && !s.ledger.HooksSeen {
		with(ledger.TypeHooksSeen, nil)
	}

	inRoot := func(path string) bool { return len(s.cfg.RootsFor(path)) > 0 }
	switch p.Event {
	case SessionStart:
		if p.Source == "compact" {
			with(ledger.TypeCompactEnd, nil)
		}
	case UserPromptSubmit, Stop, StopFailure, Interrupt:
		// A pending compaction ends with the turn or the next prompt (R20).
		if s.ledger.Compacting {
			with(ledger.TypeCompactEnd, nil)
		}
	case PreToolUse:
		for _, tp := range p.Paths {
			if inRoot(tp) {
				with(ledger.TypeTouch, func(e *ledger.Event) { e.Path = tp })
			}
		}
	case PostToolUse:
		for _, md := range p.MarkdownPaths {
			if inRoot(md) {
				with(ledger.TypeMarkdown, func(e *ledger.Event) { e.Path = md })
			}
		}
	case PostCompact:
		with(ledger.TypeCompactEnd, nil)
	case CwdChanged:
		if p.NewCwd != "" {
			with(ledger.TypeCwd, func(e *ledger.Event) { e.Cwd = p.NewCwd })
		}
	case DirectoryAdded:
		for _, dir := range p.AddedDirs {
			with(ledger.TypeDir, func(e *ledger.Event) { e.Path = dir })
		}
	case SessionEnd:
		with(ledger.TypeEnd, func(e *ledger.Event) {
			e.Reason = p.Reason
			e.Transcript = p.TranscriptPath
		})
	}
}

// hostOfLabel is the host a label's hooks file is written for.
func hostOfLabel(label string) Host {
	if h, ok := labelHosts[label]; ok {
		return h
	}
	return HostUnknown
}

// lastCwd is the most recent cwd the ledger knows.
func lastCwd(s ledger.Session) string {
	if n := len(s.Cwds); n > 0 {
		return s.Cwds[n-1]
	}
	return ""
}

// tmpBase is Claude's $TMP: the base of scratchpad_dir
// (<TMP>/<P>/<sid>/scratchpad), else CLAUDE_CODE_TMPDIR (SPEC §7.0).
func tmpBase(p Payload) string {
	if sp := p.ScratchpadDir; sp != "" && filepath.Base(sp) == "scratchpad" && filepath.Base(filepath.Dir(sp)) == p.SID && p.SID != "" {
		return filepath.Dir(filepath.Dir(filepath.Dir(sp)))
	}
	return ""
}

// codexDaemonHeld reports whether the Codex session runs in `codex
// app-server`, which holds its home (HOOKS-IO §3.3; recorded as a
// supervised session).
func codexDaemonHeld(d Deps, p Payload) bool {
	if p.Host != HostCodex || p.HarnessPID <= 1 || d.Procs == nil {
		return false
	}
	info, err := d.Procs.Lookup(p.HarnessPID)
	return err == nil && appServer(info)
}

// dialDaemon connects within the gate budget (no autostart).
func dialDaemon(ctx context.Context, d Deps) (Daemon, error) {
	if d.Dial == nil {
		return nil, ipc.ErrNoDaemon
	}
	cl, err := d.Dial(ctx)
	if err != nil {
		return nil, err
	}
	if cl == nil {
		return nil, ipc.ErrNoDaemon
	}
	return cl, nil
}

// gateRequest is the daemon gate query for p.
func gateRequest(p Payload, s *session) ipc.GateReq {
	return ipc.GateReq{
		Harness:    s.harness,
		Host:       string(p.Host),
		Event:      string(p.Event),
		SID:        p.SID,
		PromptID:   p.PromptID,
		TurnID:     p.TurnID,
		Cwd:        p.Cwd,
		ProjectDir: p.ProjectDir,
		Paths:      append(append([]string(nil), p.AddedDirs...), p.Paths...),
		Roots:      s.rootIDs,
		ToolName:   p.ToolName,
		Trigger:    p.Trigger,
		PID:        p.HarnessPID,
		CodexHome:  p.CodexHome,
	}
}

// gate asks the daemon for a gate event of a managed session (SPEC §13.4)
// and fails closed on every error (I5).
func gate(ctx context.Context, d Deps, p Payload, s *session) Decision {
	gctx, cancel := context.WithTimeout(ctx, ipc.GateBudget)
	defer cancel()
	cl, err := dialDaemon(gctx, d)
	if err != nil {
		return failDecision(p.Event, s.folder)
	}
	defer cl.Close()
	req := gateRequest(p, s)
	resp, err := cl.Gate(gctx, req)
	if err != nil {
		var ie *ipc.Error
		if errors.As(err, &ie) && ie.Code == ipc.CodeLocked {
			// A refusal by error code is still a locked folder.
			return blocked(p, s, ipc.GateResp{Verdict: ipc.VerdictBlock, State: "locked"})
		}
		return failDecision(p.Event, s.folder)
	}
	switch resp.Verdict {
	case ipc.VerdictAllow:
		allowed(ctx, d, cl, p, s)
		return Decision{Verdict: ipc.VerdictAllow}
	case ipc.VerdictBlock, ipc.VerdictDeny:
		if p.Event == UserPromptSubmit && unlockAllowed(d, p, resp) {
			return unlockOnPrompt(ctx, d, p, s, req, resp)
		}
		return blocked(p, s, resp)
	}
	// An unknown verdict is no allow.
	return failDecision(p.Event, s.folder)
}

// allowed reports the activity that follows an allowed gate event.
func allowed(ctx context.Context, d Deps, cl Daemon, p Payload, s *session) {
	switch p.Event {
	case UserPromptSubmit:
		activity(ctx, cl, p, s, ipc.ActPrompt)
	case PreCompact:
		if d.Ledger != nil && p.SID != "" {
			_ = d.Ledger.Append(ledger.Event{V: ledger.Version, T: s.now, Type: ledger.TypeCompactBegin,
				Harness: s.harness, SID: p.SID, Proc: s.proc, Host: hostField(p)})
		}
		activity(ctx, cl, p, s, ipc.ActCompactBegin)
	case PermissionRequest:
		// The permission dialog is about to wait for the user: idle (SPEC §12.4).
		activity(ctx, cl, p, s, ipc.ActPermission)
	}
}

func hostField(p Payload) string {
	if p.Host != hostOfLabel(p.Label) {
		return string(p.Host)
	}
	return ""
}

// blocked renders the daemon's block or deny. Texts come from the daemon
// (rendered from the catalog with verified data) or from the catalog.
func blocked(p Payload, s *session, resp ipc.GateResp) Decision {
	folder := displayFolder(s.folderFor(resp.RootIDs, p))
	v := ui.Vars{
		Folder: folder,
		Reason: ui.Reason(resp.Reason),
		Idle:   s.cfg.Policy.IdleSoft.D(),
		Limit:  s.cfg.Policy.MaxUnlock.D(),
	}
	if v.Reason == "" {
		v.Reason = ui.ReasonStart
	}
	switch p.Event {
	case UserPromptSubmit:
		msg := oneLine(resp.UserMessage)
		if msg == "" {
			msg = ui.Format(ui.MsgPromptBlocked, v)
		}
		return Decision{Verdict: ipc.VerdictBlock, UserMessage: msg}
	case PreCompact:
		return Decision{Verdict: ipc.VerdictBlock, UserMessage: ui.Format(ui.MsgCompactPaused, v)}
	}
	model := oneLine(resp.ModelMessage)
	if model == "" {
		model = ui.Format(ui.MsgToolDenied, v)
	}
	return Decision{Verdict: ipc.VerdictDeny, UserMessage: lockedLine(folder), ModelMessage: model}
}

// unlockAllowed reports whether a blocked prompt may raise a GUI unlock
// (SPEC §12.8, D26, D27, D37): the daemon says it is eligible, the prompt
// is human by the daemon's own measure, unlock_on_prompt is on in the
// policy the hook sees, and the host can wait for it.
func unlockAllowed(d Deps, p Payload, resp ipc.GateResp) bool {
	return resp.UnlockEligible && resp.Origin == ipc.OriginHuman && d.Cfg.Policy.UnlockOnPrompt &&
		d.DialUnlock != nil && timings(p.Host, p.Event).UnlockWait > 0
}

// unlockOnPrompt raises the hook unlock (the daemon shows the dialog) and,
// once it succeeds, asks the gate again. Every failure keeps the prompt
// blocked; a cancelled dialog says so (C3.cancelled).
func unlockOnPrompt(ctx context.Context, d Deps, p Payload, s *session, req ipc.GateReq, resp ipc.GateResp) Decision {
	wait := timings(p.Host, p.Event).UnlockWait
	if dl, ok := ctx.Deadline(); ok {
		// Leave room to re-gate and answer before the hook's own deadline.
		if room := time.Until(dl) - 2*ipc.GateBudget; room < wait {
			wait = room
		}
	}
	if wait <= 0 {
		return blocked(p, s, resp)
	}
	uctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	cl, err := d.DialUnlock(uctx)
	if err != nil || cl == nil {
		return blocked(p, s, resp)
	}
	defer cl.Close()
	roots := resp.RootIDs
	if len(roots) == 0 {
		roots = s.rootIDs
	}
	_, err = cl.Unlock(uctx, ipc.UnlockReq{
		RootIDs:  roots,
		FromHook: true,
		SID:      p.SID,
		TTY:      false,
		Deadline: s.now.Add(wait),
	}, headlessUI{})
	if err != nil {
		var ie *ipc.Error
		if errors.As(err, &ie) && ie.Code == ipc.CodeCancelled {
			return Decision{Verdict: ipc.VerdictBlock, UserMessage: ui.Format(ui.MsgPromptUnlockCxl, ui.Vars{})}
		}
		return blocked(p, s, resp)
	}
	gctx, gcancel := context.WithTimeout(ctx, ipc.GateBudget)
	defer gcancel()
	again, err := cl.Gate(gctx, req)
	if err != nil {
		return blocked(p, s, resp)
	}
	if again.Verdict == ipc.VerdictAllow {
		activity(ctx, cl, p, s, ipc.ActPrompt)
		return Decision{Verdict: ipc.VerdictAllow}
	}
	return blocked(p, s, again)
}

// sessionStart registers the session and, in a locked folder, tells a
// Claude model what a precinto denial means (C3.start.model). It never
// blocks and never prompts. An unreachable daemon means every folder is
// locked (no daemon holds a key).
func sessionStart(ctx context.Context, d Deps, p Payload, s *session) Decision {
	locked := true
	gctx, cancel := context.WithTimeout(ctx, ipc.GateBudget)
	defer cancel()
	if cl, err := dialDaemon(gctx, d); err == nil {
		defer cl.Close()
		_ = cl.Register(gctx, registerRequest(d, p, s))
		if resp, err := cl.Gate(gctx, gateRequest(p, s)); err == nil && resp.State == stateUnlocked && resp.Verdict == ipc.VerdictAllow {
			locked = false
		}
		if p.Source == "compact" {
			activity(ctx, cl, p, s, ipc.ActCompactEnd)
		}
	}
	maybeSweep(d, p, s)
	if locked {
		return failDecision(SessionStart, s.folder)
	}
	return Decision{Verdict: ipc.VerdictAllow}
}

// registerRequest announces the harness process; the daemon measures the
// ProcID itself and verifies the executable (S14). Hooks never register as
// a wrapper.
func registerRequest(d Deps, p Payload, s *session) ipc.RegisterReq {
	r := ipc.RegisterReq{
		Harness:    s.harness,
		SID:        p.SID,
		PID:        p.HarnessPID,
		Cwd:        p.Cwd,
		ProjectDir: p.ProjectDir,
		RootIDs:    s.rootIDs,
		ConfigDir:  p.ConfigDir,
		Version:    p.HarnessVersion,
		Background: codexDaemonHeld(d, p),
		TermITerm:  d.Env.Get("TERM_PROGRAM") == "iTerm.app" || d.Env.Get("LC_TERMINAL") == "iTerm2",
	}
	if p.HarnessPID > 1 && d.Procs != nil {
		if info, err := d.Procs.Lookup(p.HarnessPID); err == nil {
			r.TTY = info.TTY
		}
	}
	return r
}

// maybeSweep starts the opportunistic sweep of SPEC §10.1: SessionStart
// with source startup or resume, precinto protecting at least one folder,
// state/sweep.last older than 10 minutes, and the sweep lock free.
func maybeSweep(d Deps, p Payload, s *session) {
	if d.Spawn == nil || (p.Source != "startup" && p.Source != "resume") || len(d.Cfg.Roots) == 0 || d.Layout.StateDir == "" {
		return
	}
	if st, err := fsx.Lstat(d.Layout.SweepLast); err == nil && s.now.Sub(time.Unix(0, st.MtimeNS)) < sweepEvery {
		return
	}
	lock, err := fsx.TryLock(d.Layout.LockFile("sweep"), false)
	if err != nil {
		return // held by a running sweep, or the state directory is unusable
	}
	_ = lock.Unlock()
	_ = d.Spawn(sweepWorker)
}

// sessionEnd enqueues the seal request and starts the detached worker,
// then reports the end to the daemon if it answers at once (SPEC §10.6).
func sessionEnd(ctx context.Context, d Deps, p Payload, s *session) {
	// Only Claude Code and Codex sessions have units to seal (the other
	// hosts are gate-only, D41).
	if p.SID != "" && d.Enqueue != nil && (p.Host == HostClaude || p.Host == HostCodex) {
		r := queue.Request{
			V:         queue.Version,
			Harness:   s.harness,
			SID:       p.SID,
			Reason:    p.Reason,
			WaitFor:   s.proc,
			Warm:      p.Reason == "clear" || p.Reason == "resume",
			ConfigDir: p.ConfigDir,
			Cwd:       p.Cwd,
			At:        s.now,
		}
		if p.Host == HostCodex {
			r.Deadline = s.now.Add(codexSealDeadline)
		}
		if _, err := d.Enqueue(r); err == nil && d.Spawn != nil {
			_ = d.Spawn(sealWorker)
		}
	}
	ectx, cancel := context.WithTimeout(ctx, sessionEndBudget)
	defer cancel()
	if cl, err := dialDaemon(ectx, d); err == nil {
		defer cl.Close()
		activity(ectx, cl, p, s, ipc.ActSessionEnd)
	}
}

// report sends one activity of a managed session over a fresh connection.
func report(ctx context.Context, d Deps, p Payload, s *session, kind ipc.ActivityKind) {
	actx, cancel := context.WithTimeout(ctx, activityBudget)
	defer cancel()
	cl, err := dialDaemon(actx, d)
	if err != nil {
		return
	}
	defer cl.Close()
	activity(actx, cl, p, s, kind)
}

// activity is fire-and-forget: the daemon trusts no origin from a client
// (D54), so the report carries none.
func activity(ctx context.Context, cl Daemon, p Payload, s *session, kind ipc.ActivityKind) {
	actx, cancel := context.WithTimeout(ctx, activityBudget)
	defer cancel()
	_ = cl.Activity(actx, ipc.ActivityReq{
		Harness:  s.harness,
		SID:      p.SID,
		Kind:     kind,
		PromptID: p.PromptID,
		TurnID:   p.TurnID,
		At:       s.now,
	})
}
