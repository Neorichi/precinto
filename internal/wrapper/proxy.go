package wrapper

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/awnumar/memguard"
	"github.com/creack/pty"
	"golang.org/x/term"

	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
)

// Errors of the proxy.
var (
	errNoCommand   = errors.New("wrapper: no command to run")
	errStarted     = errors.New("wrapper: command already started")
	errNoEnv       = errors.New("wrapper: command without an explicit environment")
	errNotTerminal = errors.New("wrapper: not a terminal")
	errFinished    = errors.New("wrapper: the session has ended")
	errNotLocked   = errors.New("wrapper: the lock screen is not shown")
	errPromptBusy  = errors.New("wrapper: another prompt is active")
	errNoLockedMem = errors.New("wrapper: cannot allocate locked memory")
	errStillAlive  = errors.New("wrapper: the child did not exit after SIGKILL")
)

// Timing of the proxy.
const (
	inputPoll     = 100 * time.Millisecond // input loop wake-up (stop checks, idle resets)
	outputPoll    = 50 * time.Millisecond
	drainQuiet    = 100 * time.Millisecond // output silence that ends the drain after exit
	drainMax      = time.Second            // longest drain after exit (helpers may keep the PTY open)
	loopStopWait  = 2 * time.Second
	repaintPause  = 50 * time.Millisecond // between the cols−1 and cols resizes (D30)
	quitKeyGap    = 150 * time.Millisecond
	defaultKeysWt = 3 * time.Second // TerminateOptions.KeysWait default (R20)
	defaultGrace  = 8 * time.Second // TerminateOptions.Grace default: harness.KillGrace's floor
	killWait      = 5 * time.Second // after SIGKILL
	contWait      = time.Second     // longest wait for SIGCONT after stopping ourselves
	flushWait     = 500 * time.Millisecond
	resumeQuiet   = 2 * time.Second // a SIGCONT this soon after our own resume is ours
	maxSecret     = 4096
	maxLine       = 1024
	keysBuffer    = 8
)

// proxyState is the unexported state of a Proxy.
type proxyState struct {
	cmd     *exec.Cmd
	opts    ProxyOptions
	in, out *os.File
	inFD    int
	outFD   int
	ptmx    *os.File
	ptmxFD  int
	pid     int
	child   platform.ProcID

	// mu guards writes to the user's terminal and everything drawn on it:
	// the overlay, the prompt editor, raw mode, the ring and the modes.
	mu        sync.Mutex
	locked    atomic.Bool // input gate; set before the overlay is drawn
	overlayOn bool
	ov        overlayText
	editor    *promptState
	sb        *Scrollback
	modes     *Modes
	saved     *term.State
	raw       bool
	outDead   bool

	keys   chan byte
	filter *inputFilter // input goroutine only
	ovScan scanner      // input goroutine only

	sigMu    sync.Mutex // guards signals to the child against its reaping
	reaped   bool
	exitedAt time.Time
	exited   chan struct{}
	code     int
	errW     error

	ptyMu     sync.RWMutex // guards ptmx use against its close
	ptyClosed bool

	draining   atomic.Bool
	flushc     chan chan struct{} // output-loop handshake: drain what is pending
	stopIn     atomic.Bool
	inDone     chan struct{}
	outDone    chan struct{}
	sigc       chan os.Signal
	sigDone    chan struct{}
	finishOnce sync.Once
	done       atomic.Bool

	jobMu      sync.Mutex
	inJob      atomic.Bool
	lastResume atomic.Int64

	termMu sync.Mutex // serialises Terminate
}

// promptState is one line read on the lock screen.
type promptState struct {
	ed     *lineEditor
	secret bool
	text   string
	done   chan struct{}
	closed bool
}

// startProxy implements StartProxy with separate input and output files
// (both must be terminals, normally the same one).
func startProxy(cmd *exec.Cmd, in, out *os.File, o ProxyOptions) (*Proxy, error) {
	switch {
	case cmd == nil || cmd.Path == "":
		return nil, errNoCommand
	case cmd.Process != nil:
		return nil, errStarted
	case cmd.Env == nil:
		return nil, errNoEnv
	}
	inFD, err := fdOf(in)
	if err != nil {
		return nil, err
	}
	outFD, err := fdOf(out)
	if err != nil {
		return nil, err
	}
	if !term.IsTerminal(inFD) || !term.IsTerminal(outFD) {
		return nil, errNotTerminal
	}
	if o.ScrollbackBytes <= 0 {
		o.ScrollbackBytes = defaultScrollbackBytes
	}
	ws, err := getWinsize(outFD)
	if err != nil || ws.Row == 0 || ws.Col == 0 {
		ws = winsize{Row: 24, Col: 80}
	}
	s := &proxyState{
		cmd: cmd, opts: o, in: in, out: out, inFD: inFD, outFD: outFD,
		sb:      NewScrollback(o.ScrollbackBytes),
		modes:   NewModes(),
		keys:    make(chan byte, keysBuffer),
		filter:  newInputFilter(),
		ovScan:  scanner{input: true},
		exited:  make(chan struct{}),
		inDone:  make(chan struct{}),
		outDone: make(chan struct{}),
		sigc:    make(chan os.Signal, 8),
		sigDone: make(chan struct{}),
		flushc:  make(chan chan struct{}),
	}
	saved, err := term.MakeRaw(inFD)
	if err != nil {
		return nil, err
	}
	s.saved, s.raw = saved, true

	// The PTY child leads a new session whose controlling terminal is the
	// PTY (pty.StartWithAttrs: Setsid + Setctty), so ending "its session"
	// never reaches the user's terminal session (R11, D57).
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	setSession(cmd, true)
	ptmx, err := pty.StartWithAttrs(cmd, &pty.Winsize{Rows: ws.Row, Cols: ws.Col, X: ws.X, Y: ws.Y}, cmd.SysProcAttr)
	if err != nil {
		_ = term.Restore(inFD, saved)
		return nil, err
	}
	s.ptmx = ptmx
	if s.ptmxFD, err = fdOf(ptmx); err != nil {
		// Unreachable for a file pty.Open returned; end the child rather
		// than leave it without a reader.
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = ptmx.Close()
		_ = term.Restore(inFD, saved)
		return nil, err
	}
	s.pid = cmd.Process.Pid
	s.child = identifyChild(s.pid)

	signal.Notify(s.sigc, append([]os.Signal{sigWINCH, sigCONT}, forwarded...)...)
	go s.waitLoop()
	go s.outputLoop()
	go s.inputLoop()
	go s.sigLoop()
	return &Proxy{cmd: cmd, s: s}, nil
}

// identifyChild measures the child's ProcID; when that fails (the child
// already exited) only the pid is known.
func identifyChild(pid int) platform.ProcID {
	id, err := identifyProc(pid)
	if err != nil || id.PID != pid {
		return platform.ProcID{PID: pid}
	}
	return id
}

func (s *proxyState) isExited() bool {
	select {
	case <-s.exited:
		return true
	default:
		return false
	}
}

// waitExit waits up to d for the child to exit.
func (s *proxyState) waitExit(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.exited:
		return true
	case <-t.C:
		return false
	}
}

func (s *proxyState) waitLoop() {
	defer close(s.exited)
	for {
		r, err := wait4(s.pid, true)
		if err != nil {
			s.setExit(1, err)
			return
		}
		if r.stopped {
			s.jobStop()
			continue
		}
		s.setExit(r.code, nil)
		return
	}
}

func (s *proxyState) setExit(code int, err error) {
	s.sigMu.Lock()
	s.reaped = true
	s.exitedAt = time.Now()
	s.code, s.errW = code, err
	s.sigMu.Unlock()
	_ = s.cmd.Process.Release()
}

// signalChild signals the child itself while it has not been reaped.
func (s *proxyState) signalChild(sig os.Signal) {
	s.sigMu.Lock()
	defer s.sigMu.Unlock()
	if !s.reaped {
		_ = s.cmd.Process.Signal(sig)
	}
}

// signalChildGroup signals the child's process group (it leads one in its
// own session) while the child has not been reaped.
func (s *proxyState) signalChildGroup(sig sysSignal) {
	s.sigMu.Lock()
	defer s.sigMu.Unlock()
	if !s.reaped {
		_ = killGroup(s.pid, sig)
	}
}

func (s *proxyState) outputLoop() {
	defer close(s.outDone)
	buf := make([]byte, 32<<10)
	defer clear(buf)
	var quietSince, drainStart time.Time
	for {
		select {
		case ack := <-s.flushc:
			s.drainPending(buf)
			close(ack)
		default:
		}
		if s.draining.Load() && drainStart.IsZero() {
			drainStart = time.Now()
		}
		if !drainStart.IsZero() && time.Since(drainStart) > drainMax {
			return
		}
		ready, err := waitReadable(s.ptmxFD, outputPoll)
		if err != nil {
			return
		}
		if !ready {
			if !drainStart.IsZero() {
				if quietSince.IsZero() {
					quietSince = time.Now()
				} else if time.Since(quietSince) >= drainQuiet {
					return
				}
			}
			continue
		}
		quietSince = time.Time{}
		n, eof, err := readFD(s.ptmxFD, buf)
		if n > 0 {
			s.output(buf[:n])
			clear(buf[:n])
		}
		if eof || err != nil {
			return
		}
	}
}

// drainPending forwards everything the child already wrote (output loop
// only: it is the PTY's single reader).
func (s *proxyState) drainPending(buf []byte) {
	for i := 0; i < 64; i++ {
		ready, err := waitReadable(s.ptmxFD, 0)
		if err != nil || !ready {
			return
		}
		n, eof, err := readFD(s.ptmxFD, buf)
		if n > 0 {
			s.output(buf[:n])
			clear(buf[:n])
		}
		if eof || err != nil {
			return
		}
	}
}

// flushOutput has the output loop forward what the child wrote so far, so
// nothing it printed before stopping appears only after the resume.
func (s *proxyState) flushOutput() {
	ack := make(chan struct{})
	t := time.NewTimer(flushWait)
	defer t.Stop()
	select {
	case s.flushc <- ack:
	case <-s.outDone:
		return
	case <-t.C:
		return
	}
	select {
	case <-ack:
	case <-s.outDone:
	case <-t.C:
	}
}

// output records child output and forwards it unless the lock screen is
// shown. Every chunk is either forwarded now or part of the replay at
// unlock, never both: Unlock snapshots the ring under s.mu.
func (s *proxyState) output(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.sb.Write(b)
	s.modes.Feed(b)
	if !s.locked.Load() {
		s.writeOut(b)
	}
}

// writeOut writes to the user's terminal. Callers hold s.mu.
func (s *proxyState) writeOut(b []byte) {
	_ = s.writeOutErr(b)
}

func (s *proxyState) writeOutErr(b []byte) error {
	if s.outDead || len(b) == 0 {
		return nil
	}
	if _, err := s.out.Write(b); err != nil {
		s.outDead = true // the terminal hung up; keep draining the child
		return err
	}
	return nil
}

func (s *proxyState) inputLoop() {
	defer close(s.inDone)
	buf := make([]byte, 64<<10)
	defer clear(buf)
	for !s.stopIn.Load() {
		ready, err := waitReadable(s.inFD, inputPoll)
		if err != nil {
			return
		}
		if !ready {
			s.filter.idle()
			s.ovScan.idle(func(*token) {})
			continue
		}
		n, eof, err := readFD(s.inFD, buf)
		if n > 0 && !s.stopIn.Load() {
			s.input(buf[:n])
		}
		clear(buf[:n])
		if eof || err != nil {
			return
		}
	}
}

// input forwards keys to the child, or hands them to the lock screen.
func (s *proxyState) input(b []byte) {
	if s.locked.Load() {
		s.overlayInput(b)
		return
	}
	s.ptyWrite(b)
	if human, enter := s.filter.feed(b); human && s.opts.OnHuman != nil {
		s.opts.OnHuman(enter)
	}
}

// ptyWrite writes to the child's terminal while the PTY is open.
func (s *proxyState) ptyWrite(b []byte) {
	s.ptyMu.RLock()
	defer s.ptyMu.RUnlock()
	if !s.ptyClosed {
		_, _ = s.ptmx.Write(b)
	}
}

// overlayInput handles keys typed on the lock screen: they feed an active
// prompt, or become overlay keys (Enter, Ctrl-D); everything else is
// dropped, and nothing here is ever activity (SPEC §12.3).
func (s *proxyState) overlayInput(b []byte) {
	s.mu.Lock()
	if ps := s.editor; ps != nil && !ps.closed {
		finished := ps.ed.feed(b)
		if !ps.secret {
			s.ov.status = ps.text + " " + string(ps.ed.buf[:ps.ed.n])
			s.redraw(true)
		}
		if finished {
			ps.closed = true
			close(ps.done)
		}
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	emit := func(t *token) {
		if k, ok := overlayKey(t); ok {
			select {
			case s.keys <- k:
			default: // a burst of keys: the earlier ones are enough
			}
		}
	}
	s.ovScan.feed(b, emit)
	s.ovScan.endChunk(len(b), emit)
}

func (s *proxyState) drainKeys() {
	for {
		select {
		case <-s.keys:
		default:
			return
		}
	}
}

func (s *proxyState) sigLoop() {
	for {
		select {
		case sig := <-s.sigc:
			switch sig {
			case sigWINCH:
				s.resize()
			case sigCONT:
				s.onContinue()
			default:
				s.signalChild(sig)
			}
		case <-s.sigDone:
			return
		}
	}
}

// resize propagates the terminal size to the child (and redraws the lock
// screen at the new size).
func (s *proxyState) resize() {
	ws, err := getWinsize(s.outFD)
	if err != nil || ws.Row == 0 || ws.Col == 0 {
		return
	}
	s.setPTYSize(ws)
	s.mu.Lock()
	if s.overlayOn {
		s.redraw(s.editor != nil)
	}
	s.mu.Unlock()
}

func (s *proxyState) setPTYSize(ws winsize) {
	s.ptyMu.RLock()
	defer s.ptyMu.RUnlock()
	if !s.ptyClosed {
		_ = setWinsize(s.ptmxFD, ws)
	}
}

// repaint makes the child redraw: a same-size SIGWINCH does not repaint
// Node or ratatui TUIs, so resize to cols−1 and back (D30).
func (s *proxyState) repaint() {
	ws, err := getWinsize(s.outFD)
	if err != nil || ws.Row == 0 || ws.Col == 0 {
		return
	}
	tmp := ws
	if ws.Col > 1 {
		tmp.Col--
	} else {
		tmp.Col++
	}
	s.setPTYSize(tmp)
	time.Sleep(repaintPause)
	s.setPTYSize(ws)
}

// onContinue handles a SIGCONT that does not end our own job-control stop
// (someone stopped the wrapper with SIGSTOP): raw mode again and repaint.
func (s *proxyState) onContinue() {
	if s.inJob.Load() || time.Since(time.Unix(0, s.lastResume.Load())) < resumeQuiet {
		return
	}
	s.mu.Lock()
	s.resumeTerminal()
	s.mu.Unlock()
	s.signalChildGroup(sigCont)
	s.repaint()
}

// jobStop implements job control when the child stopped (SPEC §15.1 step
// 8, UX14): forward what it printed, restore the user's terminal, stop the
// wrapper like any job, and when continued re-enter raw mode, continue the
// child and repaint.
func (s *proxyState) jobStop() {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	if s.done.Load() {
		return
	}
	s.inJob.Store(true)
	defer s.inJob.Store(false)
	contc := make(chan os.Signal, 1)
	signal.Notify(contc, sigCONT)
	defer signal.Stop(contc)

	s.flushOutput()
	s.mu.Lock()
	s.suspendTerminal()
	s.mu.Unlock()
	if err := stopSelf(); err == nil {
		// Our job is stopped now, unless our process group is orphaned
		// (no job-control shell), where the kernel discards SIGTSTP.
		t := time.NewTimer(contWait)
		select {
		case <-contc:
		case <-t.C:
		}
		t.Stop()
	}
	s.mu.Lock()
	s.resumeTerminal()
	s.mu.Unlock()
	s.signalChildGroup(sigCont)
	s.lastResume.Store(time.Now().UnixNano())
	s.repaint()
}

// suspendTerminal gives the terminal back in the state the user's shell
// expects. Callers hold s.mu.
func (s *proxyState) suspendTerminal() {
	var b []byte
	if s.overlayOn {
		b = append(b, clearScreen+leaveAltScreen...)
	} else {
		if !s.modes.atGround() {
			b = append(b, cancelSeq...)
		}
		b = append(b, s.modes.Reset()...)
	}
	b = append(b, showCursor+sgrReset...)
	s.writeOut(b)
	if s.raw {
		_ = term.Restore(s.inFD, s.saved)
		s.raw = false
	}
}

// resumeTerminal re-enters raw mode and redraws what the terminal showed.
// The termios saved at start stays the one restored at exit. Callers hold
// s.mu.
func (s *proxyState) resumeTerminal() {
	if _, err := term.MakeRaw(s.inFD); err == nil {
		s.raw = true
	}
	if s.overlayOn {
		s.writeOut([]byte(enterAltScreen))
		s.redraw(s.editor != nil)
		return
	}
	s.writeOut(s.modes.Restore())
}

// overlayBytes renders the lock screen at the terminal's size. Callers
// hold s.mu.
func (s *proxyState) overlayBytes(cursorAfter bool) []byte {
	ws, err := getWinsize(s.outFD)
	if err != nil {
		ws = winsize{Row: 24, Col: 80}
	}
	return s.ov.render(int(ws.Col), int(ws.Row), cursorAfter)
}

// redraw draws the lock screen again. Callers hold s.mu.
func (s *proxyState) redraw(cursorAfter bool) {
	if s.overlayOn {
		s.writeOut(s.overlayBytes(cursorAfter))
	}
}

func (s *proxyState) lock(o Overlay) error {
	if s.done.Load() {
		return errFinished
	}
	s.locked.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ov.o = o
	s.ov.harness = o.Harness
	if s.overlayOn {
		return s.writeOutErr(s.overlayBytes(s.editor != nil))
	}
	var b []byte
	if !s.modes.atGround() {
		b = append(b, cancelSeq...)
	}
	// Turn off what the child enabled (mouse reports, bracketed paste,
	// kitty flags, its alternate screen…), clear the screen and, by policy,
	// the scrollback, then draw the overlay on the alternate screen.
	b = append(b, s.modes.Reset()...)
	b = append(b, resetModes...)
	b = append(b, clearScreen...)
	if s.opts.ClearScrollback {
		b = append(b, clearScrollback...)
		if s.opts.ITerm {
			b = append(b, itermClearScrollback...)
		}
	}
	b = append(b, enterAltScreen...)
	s.overlayOn = true
	b = append(b, s.overlayBytes(false)...)
	s.drainKeys()
	return s.writeOutErr(b)
}

func (s *proxyState) unlock() error {
	s.mu.Lock()
	if !s.overlayOn {
		s.locked.Store(false)
		s.mu.Unlock()
		return nil
	}
	if ps := s.editor; ps != nil && !ps.closed {
		ps.closed = true
		close(ps.done) // unlocked elsewhere: the prompt is moot
	}
	b := []byte(clearScreen + leaveAltScreen + clearScreen)
	if s.opts.ClearScrollback {
		b = append(b, clearScrollback...)
	}
	b = append(b, sgrReset...)
	raw := s.sb.Bytes()
	replay := filterReplay(raw)
	clear(raw)
	cur := NewModes()
	cur.Feed(replay)
	if s.modes.altActive() && cur.altSwitches == 0 {
		// Only full-screen frames survive in the ring: drawing them on the
		// main screen would leave them in the scrollback, and the repaint
		// redraws the alternate screen anyway.
		clear(replay)
		replay = replay[:0]
		cur = NewModes()
	}
	b = append(b, replay...)
	clear(replay)
	b = append(b, s.modes.restoreFromState(cur)...)
	err := s.writeOutErr(b)
	clear(b)
	s.overlayOn = false
	s.ov.status, s.ov.ending = "", false
	s.locked.Store(false)
	s.drainKeys()
	s.mu.Unlock()
	s.repaint()
	return err
}

// notify shows a desktop notification (OSC 9, D60) while the session is
// shown and the child's output is between sequences; terminals without
// OSC 9 ignore it.
func (s *proxyState) notify(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked.Load() || !s.modes.atGround() {
		return
	}
	t := strings.TrimSpace(strings.ReplaceAll(string(ui.SanitizeTerminal([]byte(text))), "\n", " "))
	if t != "" {
		s.writeOut([]byte("\x1b]9;" + t + "\x1b\\"))
	}
}

// setStatus shows one line under the overlay's key help.
func (s *proxyState) setStatus(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ov.status = text
	s.redraw(s.editor != nil)
}

// setEnding replaces the key help with C4.ending.
func (s *proxyState) setEnding() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ov.ending = true
	s.redraw(false)
}

// prompt reads one line on the lock screen: into locked memory for a
// secret (no echo), or as visible text. cancel, the child's exit and an
// unlock end it with ui.ErrCancelled.
func (s *proxyState) prompt(text string, secret bool, cancel <-chan struct{}) (*memguard.LockedBuffer, string, error) {
	var lb *memguard.LockedBuffer
	var work []byte
	if secret {
		lb = memguard.NewBuffer(maxSecret)
		if lb.Size() == 0 {
			return nil, "", errNoLockedMem
		}
		work = lb.Bytes()
	} else {
		work = make([]byte, maxLine)
	}
	destroy := func() {
		clear(work)
		if lb != nil {
			lb.Destroy()
		}
	}
	ps := &promptState{ed: newLineEditor(work, len(work)), secret: secret, text: text, done: make(chan struct{})}
	s.mu.Lock()
	switch {
	case !s.overlayOn:
		s.mu.Unlock()
		destroy()
		return nil, "", errNotLocked
	case s.editor != nil:
		s.mu.Unlock()
		destroy()
		return nil, "", errPromptBusy
	}
	s.editor = ps
	s.ov.status = text
	s.redraw(true)
	s.mu.Unlock()

	select {
	case <-ps.done:
	case <-cancel:
	case <-s.exited:
	}

	s.mu.Lock()
	ok := ps.closed && ps.ed.done && !ps.ed.cancel
	if !ps.closed {
		ps.closed = true
		close(ps.done)
	}
	s.editor = nil
	s.ov.status = ""
	s.redraw(false)
	s.mu.Unlock()

	if !ok {
		destroy()
		return nil, "", ui.ErrCancelled
	}
	n := ps.ed.n
	if secret {
		// NewBufferFromBytes copies into an exact-size locked buffer and
		// wipes the bytes it copied from.
		out := memguard.NewBufferFromBytes(work[:n])
		destroy()
		return out, "", nil
	}
	line := string(work[:n])
	destroy()
	return nil, line, nil
}

func (s *proxyState) terminate(o TerminateOptions) error {
	s.termMu.Lock()
	defer s.termMu.Unlock()
	if len(o.QuitKeys) > 0 && !s.isExited() {
		for i, k := range o.QuitKeys {
			if i > 0 && s.waitExit(quitKeyGap) {
				break
			}
			s.ptyWrite([]byte{k})
		}
		wait := o.KeysWait
		if wait <= 0 {
			wait = defaultKeysWt
		}
		s.waitExit(wait)
	}
	if !s.isExited() {
		s.signalChild(sigTerm)
		grace := o.Grace
		if grace <= 0 {
			grace = defaultGrace
		}
		if !s.waitExit(grace) {
			s.signalChild(sigKill)
			s.waitExit(killWait)
		}
	}
	// Helpers the child left in its session go too: a session the wrapper
	// created, never the user's (R11, D57).
	s.sigMu.Lock()
	recent := !s.reaped || time.Since(s.exitedAt) < sessionKillWindow
	s.sigMu.Unlock()
	if recent {
		killSession(s.child)
	}
	if !s.isExited() {
		return errStillAlive
	}
	return nil
}

// sessionKillWindow bounds how long after the child's exit its session id
// is still signalled: while any process of that session lives, the kernel
// never hands its id to another process, but once it is empty the id is
// free again, so a late Terminate leaves it alone.
const sessionKillWindow = 2 * time.Second

// killSession SIGKILLs what remains of the session a wrapper child leads
// (platform.SignalGroup verifies the leader identity, CC-13).
func killSession(leader platform.ProcID) {
	if err := signalSession(leader, sigKill); err != nil && !errors.Is(err, platform.ErrNoProcess) {
		// The child's process group is the part of its session the
		// wrapper can always name.
		_ = killGroup(leader.PID, sigKill)
	}
}

func (s *proxyState) wait() (int, error) {
	<-s.exited
	s.finishOnce.Do(s.finish)
	s.sigMu.Lock()
	defer s.sigMu.Unlock()
	return s.code, s.errW
}

// finish drains the child's last output, stops the loops, leaves the lock
// screen, turns off the modes the child left on, restores the saved
// termios and wipes the ring (SPEC §15.2: wiped at exit).
func (s *proxyState) finish() {
	s.draining.Store(true)
	outStopped := waitClosed(s.outDone, loopStopWait)
	s.stopIn.Store(true)
	inStopped := waitClosed(s.inDone, loopStopWait)
	signal.Stop(s.sigc)
	close(s.sigDone)
	s.jobMu.Lock()
	s.done.Store(true)
	s.jobMu.Unlock()

	s.mu.Lock()
	var b []byte
	if !s.modes.atGround() {
		b = append(b, cancelSeq...)
	}
	if s.overlayOn {
		b = append(b, clearScreen+leaveAltScreen...)
		s.overlayOn = false
	}
	b = append(b, s.modes.Reset()...)
	s.writeOut(b)
	if s.raw {
		_ = term.Restore(s.inFD, s.saved)
		s.raw = false
	}
	s.sb.Wipe()
	s.locked.Store(false)
	if ps := s.editor; ps != nil && !ps.closed {
		ps.closed = true
		close(ps.done)
	}
	s.mu.Unlock()

	if outStopped && inStopped {
		s.ptyMu.Lock()
		s.ptyClosed = true
		_ = s.ptmx.Close()
		s.ptyMu.Unlock()
	}
}

func waitClosed(c <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-c:
		return true
	case <-t.C:
		return false
	}
}
