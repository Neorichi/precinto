package wrapper

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
)

// Timing of Run.
const (
	requestTimeout  = 5 * time.Second  // register, unregister
	activityTimeout = 2 * time.Second  // one activity report
	unlockTimeout   = 2 * time.Minute  // unlock from the lock screen (user presence)
	postExitTimeout = 10 * time.Minute // Finish, release, seal after exit
	bgStopWait      = 30 * time.Second // background restore after the child exited
	eventBuffer     = 64
)

// D32: settings a managed Claude launch runs with (SPEC §7.1.5).
const (
	claudeSettings  = `{"idleCompaction":false,"awaySummaryEnabled":false,"precomputeCompactionEnabled":false}`
	claudeAwayEnv   = "CLAUDE_CODE_ENABLE_AWAY_SUMMARY"
	claudeConfigEnv = paths.EnvClaudeConfigDir
)

// abortCh is a channel closed once.
type abortCh struct {
	once sync.Once
	ch   chan struct{}
}

func newAbort() *abortCh { return &abortCh{ch: make(chan struct{})} }

func (a *abortCh) fire() { a.once.Do(func() { close(a.ch) }) }

func (a *abortCh) fired() bool {
	select {
	case <-a.ch:
		return true
	default:
		return false
	}
}

// runner is one `precinto run`.
type runner struct {
	o      Options
	b      Backend
	plan   harness.LaunchPlan
	stderr io.Writer
	msgs   ui.Writer

	managed     bool
	rootIDs     []string
	folder      string
	sid         string
	cwd         string
	harnessName string
	factor      string
	iterm       bool
	tty         string
	configDir   string

	ctx     context.Context // ends when the run is over
	ctl     *ctlConn
	events  chan subMsg
	act     *activity
	abortBG *abortCh

	px    *Proxy
	dc    *directChild
	child platform.ProcID
	pid   int

	// Event-loop state (one goroutine at a time).
	locked     map[string]bool
	lockCode   ui.Reason
	lockReason string // rendered for the overlay
	busy       bool
	lost       bool
	unlocking  bool
	ending     bool
	endCode    ui.Reason
	endedByUs  bool
	cancelled  bool
	unlockDone chan error
	termDone   chan error
}

func run(ctx context.Context, o Options) (int, error) {
	if o.Backend == nil {
		return ExitNotStarted, errors.New("wrapper: no backend")
	}
	if len(o.Argv) == 0 || o.Argv[0] == "" {
		return ExitNotStarted, errNoCommand
	}
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	plan, err := o.Backend.Plan(ctx, o.Harness, o.Cwd, o.Argv)
	if err != nil {
		return ExitNotStarted, err
	}
	r := newRunner(o, plan)
	if plan.Mode == harness.LaunchPassthrough {
		return r.passthrough(ctx)
	}
	return r.launch(ctx)
}

func newRunner(o Options, plan harness.LaunchPlan) *runner {
	r := &runner{
		o: o, b: o.Backend, plan: plan,
		stderr:     o.Stderr,
		msgs:       ui.Writer{W: o.Stderr},
		ctl:        &ctlConn{b: o.Backend},
		locked:     map[string]bool{},
		unlockDone: make(chan error, 1),
		termDone:   make(chan error, 1),
		abortBG:    newAbort(),
	}
	if plan.Harness == "" {
		r.plan.Harness = o.Harness
	}
	seen := map[string]bool{}
	for _, root := range plan.Roots {
		if root.ID != "" && !seen[root.ID] {
			seen[root.ID] = true
			r.rootIDs = append(r.rootIDs, root.ID)
		}
	}
	r.managed = len(r.rootIDs) > 0
	if len(plan.Roots) > 0 {
		home, _ := paths.UserHome(o.Env)
		r.folder = paths.Tilde(home, plan.Roots[0].Path)
	}
	if plan.Resume.Kind == harness.ResumeSID {
		r.sid = plan.Resume.Value
	}
	r.cwd = o.Cwd
	if r.cwd == "" {
		r.cwd, _ = os.Getwd()
	}
	r.harnessName = displayName(r.plan.Harness, o.Argv[0])
	r.factor = factorHint(o.Env)
	r.iterm = o.Env.Get("TERM_PROGRAM") == "iTerm.app"
	return r
}

// displayName is the harness name users know (C4.busy, C6.deferred).
func displayName(h harness.ID, argv0 string) string {
	switch h {
	case harness.ClaudeCode:
		return "Claude"
	case harness.Codex:
		return "Codex"
	case "":
		return filepath.Base(argv0)
	}
	return string(h)
}

// factorHint names the factor the overlay's Enter will ask for. The wrapper
// cannot list the enrolled factors; the Mac password dialog is impossible
// in tmux, screen and SSH (D27, D60).
func factorHint(e paths.Env) string {
	if runtime.GOOS == "darwin" {
		remote := false
		for _, k := range []string{"TMUX", "STY", "SSH_CONNECTION", "SSH_TTY"} {
			if _, ok := e.Lookup(k); ok {
				remote = true
			}
		}
		if !remote {
			return "Mac password"
		}
	}
	return "passphrase"
}

func (r *runner) reasonText(code ui.Reason) string {
	if code == "" {
		return ""
	}
	d := r.o.Policy.IdleSoft.D()
	if code == ui.ReasonLimit {
		d = r.o.Policy.MaxUnlock.D()
	}
	return ui.ReasonText(code, d)
}

// planVars maps LaunchPlan.MsgVars (keys without braces) to ui.Vars.
func planVars(m map[string]string) ui.Vars {
	v := ui.Vars{Folder: m["folder"], Harness: m["harness"], SID: m["sid"], Other: m["other"], File: m["file"], Command: m["command"]}
	if pid, err := strconv.Atoi(m["pid"]); err == nil {
		v.PID = pid
	}
	if n, err := strconv.Atoi(m["n"]); err == nil {
		v.N = n
	}
	if d, err := strconv.Atoi(m["days"]); err == nil {
		v.Days = d
	}
	return v
}

func (r *runner) printNotices(lines []string) {
	for _, l := range lines {
		if l = strings.TrimSpace(string(ui.SanitizeTerminal([]byte(l)))); l != "" {
			_, _ = io.WriteString(r.stderr, l+"\n")
		}
	}
}

func (r *runner) passthrough(ctx context.Context) (int, error) {
	cmd, err := r.command(nil)
	if err != nil {
		return ExitNotStarted, err
	}
	cmd.Stdin, cmd.Stdout = r.o.Stdin, r.o.Stdout
	cmd.Stderr = r.childStderr()
	return runPassthrough(ctx, cmd)
}

func (r *runner) childStderr() io.Writer {
	if f, ok := r.o.Stderr.(*os.File); ok {
		return f
	}
	return r.o.Stderr
}

// childEnv is the child's environment: the invoking environment, the
// plan's additions, PRECINTO_ACTIVE=1 (SPEC §15.1 step 6) and, for a
// managed Claude launch whose argv carries no --settings (the adapter did
// not prepare it), D32's variable.
func (r *runner) childEnv(argv []string) paths.Env {
	e := r.o.Env
	for _, kv := range r.plan.Env {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			e = e.With(k, v)
		}
	}
	if r.claudeManaged() && !hasSettingsFlag(argv) {
		e = e.With(claudeAwayEnv, "0")
	}
	return e.With(paths.EnvActive, "1")
}

func (r *runner) claudeManaged() bool {
	return r.managed && r.plan.Harness == harness.ClaudeCode && r.plan.Mode != harness.LaunchPassthrough
}

// hasSettingsFlag reports a --settings option before any "--".
func hasSettingsFlag(argv []string) bool {
	for i, a := range argv {
		if i == 0 {
			continue
		}
		if a == "--" {
			return false
		}
		if a == "--settings" || strings.HasPrefix(a, "--settings=") {
			return true
		}
	}
	return false
}

// command builds the child's exec.Cmd from the plan: its final argv
// (argv[0] resolved through the child's PATH when the plan left it
// relative), D32 for a managed Claude launch whose plan carries no
// --settings (the adapter injects it; a user's own --settings wins), the
// environment, the working directory and the lease descriptors.
func (r *runner) command(lease Lease) (*exec.Cmd, error) {
	argv := append([]string(nil), r.plan.Argv...)
	if len(argv) == 0 || argv[0] == "" {
		argv = append([]string(nil), r.o.Argv...)
	}
	env := r.childEnv(argv)
	if !filepath.IsAbs(argv[0]) {
		p, err := paths.LookPath(env, argv[0])
		if err != nil {
			return nil, &os.PathError{Op: "exec", Path: argv[0], Err: exec.ErrNotFound}
		}
		argv[0] = p
	}
	if r.claudeManaged() && !hasSettingsFlag(argv) {
		argv = append([]string{argv[0], "--settings", claudeSettings}, argv[1:]...)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env.Environ()
	cmd.Dir = r.o.Cwd
	if lease != nil {
		// The child holds the lease too, so it survives a wrapper killed
		// before its child (R4; live.Held.Inheritable).
		cmd.ExtraFiles = lease.Inheritable()
	}
	if d := env.Get(claudeConfigEnv); r.plan.Harness == harness.ClaudeCode && d != "" {
		r.configDir = d
	} else if d := env.Get(paths.EnvCodexHome); r.plan.Harness == harness.Codex && d != "" {
		r.configDir = d
	}
	return cmd, nil
}

func isTerminalFile(f *os.File) bool {
	fd, err := fdOf(f)
	return err == nil && term.IsTerminal(fd)
}

func (r *runner) sessionTTY() string {
	for _, f := range []*os.File{r.o.Stdin, r.o.Stdout} {
		if isTerminalFile(f) {
			if fd, err := fdOf(f); err == nil {
				if name := ttyName(fd); name != "" {
					return name
				}
			}
		}
	}
	return ""
}

func (r *runner) launch(parent context.Context) (int, error) {
	// Plan notices and the confirm question are ui.MsgID values with
	// MsgVars (the adapter cannot import internal/ui, CC-20).
	vars := planVars(r.plan.MsgVars)
	for _, id := range r.plan.Notices {
		r.printNotices([]string{ui.Format(ui.MsgID(id), vars)})
	}
	pre := &lazyUI{open: openPromptUI}
	if r.plan.Confirm != "" {
		question := ui.Format(ui.MsgID(r.plan.Confirm), vars)
		ok, err := pre.YesNo(question, strings.Contains(question, "[Y/n]"))
		if err == nil && !ok {
			err = ui.ErrCancelled
		}
		if err != nil {
			_ = pre.Close()
			return ExitNotStarted, err
		}
	}
	if r.managed {
		if err := r.b.EnsureUnlocked(parent, r.plan.Roots, pre); err != nil {
			_ = pre.Close()
			return ExitNotStarted, err
		}
	}
	_ = pre.Close()

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	r.ctx = ctx
	if r.managed {
		// Subscribe before the restore: RestoreSync must stop when the
		// folder locks (abort), and nothing exposes plaintext yet.
		d, ch, err := r.dialSub(ctx)
		if err != nil {
			return ExitNotStarted, err
		}
		r.events = make(chan subMsg, eventBuffer)
		go r.watchSub(ctx, d, ch)
	}
	if r.plan.Prepare != nil {
		if err := r.plan.Prepare(ctx); err != nil {
			return ExitNotStarted, err
		}
	}
	lease, err := r.b.AcquireLease(ctx, r.plan)
	if err != nil {
		return ExitNotStarted, err
	}
	releaseLease := func() {
		if lease != nil {
			_ = lease.Release()
		}
	}

	sum, err := r.restoreSync(ctx)
	if r.lost || len(r.locked) > 0 {
		releaseLease()
		return ExitNotStarted, &ipc.Error{Code: ipc.CodeLocked, Msg: ui.Format(ui.MsgEnterNotify, ui.Vars{Folder: r.folder})}
	}
	if err != nil {
		releaseLease()
		return ExitNotStarted, err
	}
	r.printNotices(sum.Notices)

	cmd, err := r.command(lease)
	if err != nil {
		releaseLease()
		return ExitNotStarted, err
	}
	r.tty = r.sessionTTY()
	if r.managed {
		r.act = newActivity()
	}
	if err := r.startChild(cmd); err != nil {
		releaseLease()
		return ExitNotStarted, err
	}
	if lease != nil {
		_ = lease.SetChild(r.child)
	}
	_ = r.b.RecordLaunch(ctx, r.plan, r.child)
	if r.managed {
		r.register(ctx)
		go r.activityLoop(ctx)
	}
	bgCtx, bgCancel := context.WithCancel(ctx)
	bgDone := make(chan struct{})
	go func() {
		defer close(bgDone)
		r.b.RestoreBackground(bgCtx, r.plan, r.abortBG.ch)
	}()

	r.loop(ctx, r.childExited())
	code, werr := r.waitChild()
	bgCancel()
	waitClosed(bgDone, bgStopWait)
	cancel() // ends the subscription and the activity reports
	r.afterExit(parent, lease, code)
	return code, werr
}

// restoreSync runs RestoreSync while watching for a lock: a lock (or a
// lost subscription) closes abort, and the launch is then refused.
func (r *runner) restoreSync(ctx context.Context) (RestoreSummary, error) {
	abort := newAbort()
	stop := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		for {
			select {
			case m := <-r.events:
				r.applyPrelaunch(m)
				if r.lost || len(r.locked) > 0 {
					abort.fire()
				}
			case <-stop:
				return
			}
		}
	}()
	sum, err := r.b.RestoreSync(ctx, r.plan, abort.ch)
	close(stop)
	<-watched
	return sum, err
}

// applyPrelaunch records lock state before the child exists.
func (r *runner) applyPrelaunch(m subMsg) {
	switch {
	case m.lost:
		r.lost = true
		for _, id := range r.rootIDs {
			r.locked[id] = true
		}
	case m.reconnected:
		r.lost = false
	case m.isEvent:
		aff := r.affected(m.ev.RootIDs)
		switch m.ev.Kind {
		case ipc.EventLocked, ipc.EventEnd:
			for _, id := range aff {
				r.locked[id] = true
			}
		case ipc.EventUnlocked:
			for _, id := range aff {
				delete(r.locked, id)
			}
		}
	}
}

func (r *runner) startChild(cmd *exec.Cmd) error {
	usePTY := !r.o.NoPTY && r.plan.Mode == harness.LaunchInteractive &&
		isTerminalFile(r.o.Stdin) && isTerminalFile(r.o.Stdout)
	if usePTY {
		po := ProxyOptions{ITerm: r.iterm, ClearScrollback: r.o.Policy.ClearScrollbackLock}
		if r.act != nil {
			po.OnHuman = r.act.human
		}
		px, err := startProxy(cmd, r.o.Stdin, r.o.Stdout, po)
		if err != nil {
			return err
		}
		r.px, r.child, r.pid = px, px.s.child, px.s.pid
		return nil
	}
	cmd.Stdin, cmd.Stdout = r.o.Stdin, r.o.Stdout
	cmd.Stderr = r.childStderr()
	dc, err := startDirect(cmd)
	if err != nil {
		return err
	}
	r.dc, r.child, r.pid = dc, dc.id, dc.pid
	return nil
}

func (r *runner) childExited() <-chan struct{} {
	if r.px != nil {
		return r.px.s.exited
	}
	return r.dc.exited
}

func (r *runner) waitChild() (int, error) {
	if r.px != nil {
		return r.px.Wait()
	}
	return r.dc.wait()
}

// loop handles lock events and overlay keys until the child exits.
func (r *runner) loop(ctx context.Context, exited <-chan struct{}) {
	var keys <-chan byte
	if r.px != nil {
		keys = r.px.s.keys
	}
	ctxDone := ctx.Done()
	for {
		select {
		case m := <-r.events:
			r.onMsg(m)
		case k := <-keys:
			r.onKey(k)
		case err := <-r.unlockDone:
			r.onUnlockDone(err)
		case <-r.termDone:
		case <-ctxDone:
			ctxDone = nil
			r.cancelled = true
			r.startEnd("")
		case <-exited:
			return
		}
	}
}

func (r *runner) onMsg(m subMsg) {
	switch {
	case m.lost:
		r.lost = true
		for _, id := range r.rootIDs {
			r.locked[id] = true
		}
		r.abortBG.fire()
		r.showLock()
	case m.reconnected:
		r.lost = false
		if r.px != nil && r.px.Locked() && !r.ending {
			r.px.s.setStatus("")
		}
		go r.register(r.ctx)
	case m.isEvent:
		r.onEvent(m.ev)
	}
}

func (r *runner) onEvent(ev ipc.Event) {
	aff := r.affected(ev.RootIDs)
	if len(aff) == 0 {
		return
	}
	switch ev.Kind {
	case ipc.EventLocked:
		for _, id := range aff {
			r.locked[id] = true
		}
		r.lockCode = ui.Reason(ev.Reason)
		r.lockReason = r.reasonText(r.lockCode)
		r.busy = ev.Busy
		r.abortBG.fire()
		r.showLock()
	case ipc.EventUnlocked:
		for _, id := range aff {
			delete(r.locked, id)
		}
		if len(r.locked) == 0 && !r.lost {
			r.hideLock()
		}
	case ipc.EventEnd:
		if len(ev.SIDs) == 0 || r.sid == "" || contains(ev.SIDs, r.sid) {
			code := ui.Reason(ev.Reason)
			if code == "" {
				code = r.lockCode
			}
			r.startEnd(code)
		}
	case ipc.EventExpiring:
		if r.px != nil {
			r.px.s.notify(ui.Format(ui.MsgExpiry, ui.Vars{Folder: r.folder, Limit: r.o.Policy.MaxUnlock.D()}))
		}
	}
}

// affected returns which of the session's folders an event names (all of
// them when it names none).
func (r *runner) affected(ids []string) []string {
	if len(ids) == 0 {
		return r.rootIDs
	}
	var out []string
	for _, id := range r.rootIDs {
		if contains(ids, id) {
			out = append(out, id)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func (r *runner) overlay() Overlay {
	o := Overlay{Folder: r.folder, Reason: r.lockReason, Factor: r.factor, Busy: r.busy, Harness: r.harnessName}
	if r.lost {
		// The subscription is gone: the overlay says why (CC-38), and no
		// unlock can be in flight through a daemon that is not answering.
		o.Reason, o.Busy = r.reasonText(ui.ReasonAgent), false
	}
	return o
}

func (r *runner) showLock() {
	if r.px == nil {
		return // direct mode: the gate hooks pause the session
	}
	_ = r.px.Lock(r.overlay())
	if r.lost && !r.ending {
		r.px.s.setStatus(ui.Format(ui.MsgAgentDown, ui.Vars{Folder: r.folder}))
	}
}

func (r *runner) hideLock() {
	if r.px == nil || r.ending {
		return
	}
	_ = r.px.Unlock()
}

func (r *runner) onKey(k byte) {
	if r.px == nil || r.ending || !r.px.Locked() {
		return
	}
	switch k {
	case '\r':
		r.startUnlock()
	case 0x04:
		r.startEnd(r.lockCode) // Ctrl-D: end the session and seal it
	}
}

// startUnlock unlocks the session's folders from the lock screen. The
// overlay goes away only on the daemon's "unlocked" event (SPEC §15.3).
func (r *runner) startUnlock() {
	if r.unlocking {
		return
	}
	r.unlocking = true
	roots := make([]string, 0, len(r.locked))
	for id := range r.locked {
		roots = append(roots, id)
	}
	sort.Strings(roots)
	if len(roots) == 0 {
		roots = r.rootIDs
	}
	s := r.px.s
	ctx := r.ctx
	go func() {
		c, cancel := context.WithTimeout(ctx, unlockTimeout)
		defer cancel()
		h := &overlayUI{s: s, cancel: c.Done()}
		req := ipc.UnlockReq{RootIDs: roots, TTY: true, Deadline: time.Now().Add(unlockTimeout)}
		err := r.ctl.do(c, func(d Daemon) error {
			_, err := d.Unlock(c, req, h)
			return err
		})
		r.unlockDone <- err
	}()
}

func (r *runner) onUnlockDone(err error) {
	r.unlocking = false
	if err == nil || r.px == nil || r.ending {
		return
	}
	var ie *ipc.Error
	msg := ui.Format(ui.MsgAgentDown, ui.Vars{Folder: r.folder})
	switch {
	case errors.As(err, &ie) && ie.Code == ipc.CodeCancelled, errors.Is(err, ui.ErrCancelled),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		msg = ui.Format(ui.MsgUnlockCancelled, ui.Vars{Folder: r.folder})
	case errors.As(err, &ie) && ie.Msg != "":
		msg = ie.Msg // catalog text from the daemon (rate limit, agent context…)
	}
	r.px.s.setStatus(msg)
}

// startEnd terminates the child (SPEC §12.7 step 4, §15.1 step 7): quit
// keys first for Codex, then SIGTERM, SIGKILL after the grace, then the
// child's own session.
func (r *runner) startEnd(code ui.Reason) {
	if r.ending {
		return
	}
	r.ending = true
	r.endCode = code
	r.endedByUs = !r.cancelled
	if r.px != nil {
		if !r.px.Locked() {
			_ = r.px.Lock(r.overlay())
		}
		r.px.s.setEnding()
	}
	opts := terminateOptions(r.plan)
	px, dc := r.px, r.dc
	go func() {
		var err error
		if px != nil {
			err = px.Terminate(opts)
		} else {
			err = dc.terminate(opts)
		}
		r.termDone <- err
	}()
}

// terminateOptions are the termination parameters of a plan: the adapter
// knows its harness, so its quit keys (Codex: Ctrl-C twice) and its
// harness.KillGrace come from the plan (CC-24); a plan without a grace
// gets the 8 s floor.
func terminateOptions(plan harness.LaunchPlan) TerminateOptions {
	grace := plan.KillGrace
	if grace <= 0 {
		grace = defaultGrace
	}
	return TerminateOptions{QuitKeys: plan.QuitKeys, KeysWait: defaultKeysWt, Grace: grace}
}

// afterExit is SPEC §15.1 step 9 after the child was reaped.
func (r *runner) afterExit(parent context.Context, lease Lease, code int) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), postExitTimeout)
	defer cancel()
	if r.managed {
		r.unregister(ctx)
	}
	r.ctl.close()
	// Reset the terminal; clear it too when precinto ended the session
	// (clear_terminal_on_end), so nothing of it stays on screen.
	clearIt := r.endedByUs && r.o.Policy.ClearTerminalOnEnd
	if r.px != nil || (clearIt && isTerminalFile(r.o.Stdout)) {
		_, _ = r.o.Stdout.Write(resetSequence(clearIt, r.iterm))
	}
	if r.plan.Finish != nil {
		_ = r.plan.Finish(ctx, code)
	}
	if lease != nil {
		_ = lease.Release()
	}
	sum, err := r.b.SealAfterExit(ctx, r.plan, r.child)
	if sum.SID != "" && r.sid == "" {
		r.sid = sum.SID
	}
	if r.endedByUs {
		r.msgs.Line(ui.MsgEnded, ui.Vars{
			Folder: r.folder, N: 1, Reason: r.endCode,
			Idle: r.o.Policy.IdleSoft.D(), Limit: r.o.Policy.MaxUnlock.D(),
			Resume: r.resumeCommand(),
		})
	}
	// Hook presence (UX10, SPEC §14.4): asked for every harness whose plan
	// declares a check, so the backend can mark the session ungated; only
	// Claude has an exit message (C9.claude).
	if r.plan.HookCheck.Event != "" {
		seen, herr := r.b.HooksSeen(ctx, r.plan, r.child)
		if herr == nil && !seen && r.plan.Harness == harness.ClaudeCode {
			r.msgs.Line(ui.MsgClaudeNoHooks, ui.Vars{})
		}
	}
	r.sealLine(sum, err)
}

// sealLine prints the one C6 line of SPEC §15.1 step 9.
func (r *runner) sealLine(sum SealSummary, err error) {
	sid := sum.SID
	if sid == "" {
		sid = r.sid
	}
	switch {
	case err != nil || sum.Failed != "":
		cause := sum.Failed
		if cause == "" {
			cause = errorClass(err)
		}
		r.msgs.Line(ui.MsgSealFailed, ui.Vars{SID: sid, Cause: cause})
	case sum.Deferred:
		r.msgs.Line(ui.MsgSealDeferred, ui.Vars{Harness: r.harnessName})
	case (sum.Files > 0 || sum.SID != "") && r.managed && !r.endedByUs && len(r.locked) == 0:
		r.msgs.Line(ui.MsgSealedOK, ui.Vars{
			SID: sid, Files: sum.Files, Bytes: sum.Bytes,
			Folder: r.folder, Idle: r.o.Policy.IdleSoft.D(),
		})
	}
}

// errorClass is a short, content-free cause ({cause} never carries OS
// error text).
func errorClass(err error) string {
	var ie *ipc.Error
	switch {
	case err == nil:
		return "error"
	case errors.As(err, &ie):
		return string(ie.Code)
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	return "error"
}

// resumeCommand is C5's {resume}.
func (r *runner) resumeCommand() string {
	switch r.plan.Harness {
	case harness.ClaudeCode:
		if r.sid != "" {
			return "claude --resume " + r.sid
		}
		return "claude --continue"
	case harness.Codex:
		if r.sid != "" {
			return "codex resume " + r.sid
		}
		return "codex resume --last"
	}
	return "precinto run -- " + filepath.Base(r.o.Argv[0])
}

func selfPID() int { return os.Getpid() }
