package wrapper

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"time"

	"github.com/Neorichi/precinto/internal/platform"
)

// directChild is a child run without a PTY (SPEC §15.1 step 6, D57): it
// leads a session of its own (Setsid), so the terminal's signals reach only
// the wrapper, which forwards SIGINT, SIGQUIT, SIGTERM and SIGHUP; ending it
// may then signal its whole session without touching the user's.
type directChild struct {
	cmd *exec.Cmd
	pid int
	id  platform.ProcID

	sigMu    sync.Mutex
	reaped   bool
	exitedAt time.Time
	exited   chan struct{}
	code     int
	errW     error

	sigc   chan os.Signal
	tstpc  chan os.Signal
	done   chan struct{}
	termMu sync.Mutex
}

// startDirect starts cmd (with its stdio already set) as a session leader.
func startDirect(cmd *exec.Cmd) (*directChild, error) {
	switch {
	case cmd == nil || cmd.Path == "":
		return nil, errNoCommand
	case cmd.Process != nil:
		return nil, errStarted
	case cmd.Env == nil:
		return nil, errNoEnv
	}
	setSession(cmd, false)
	d := &directChild{
		cmd:    cmd,
		exited: make(chan struct{}),
		sigc:   make(chan os.Signal, 8),
		tstpc:  make(chan os.Signal, 2),
		done:   make(chan struct{}),
	}
	// Watch signals before the child exists so none is lost in between.
	signal.Notify(d.sigc, forwarded...)
	signal.Notify(d.tstpc, sigTSTP)
	if err := cmd.Start(); err != nil {
		signal.Stop(d.sigc)
		signal.Stop(d.tstpc)
		return nil, err
	}
	d.pid = cmd.Process.Pid
	d.id = identifyChild(d.pid)
	go d.waitLoop()
	go d.sigLoop()
	return d, nil
}

func (d *directChild) waitLoop() {
	err := d.cmd.Wait() // also finishes copying non-file stdio
	code := exitStatus(d.cmd.ProcessState)
	if _, ok := err.(*exec.ExitError); ok || d.cmd.ProcessState != nil {
		err = nil
	}
	d.sigMu.Lock()
	d.reaped = true
	d.exitedAt = time.Now()
	d.code, d.errW = code, err
	d.sigMu.Unlock()
	close(d.exited)
	signal.Stop(d.sigc)
	signal.Stop(d.tstpc)
	close(d.done)
}

func (d *directChild) sigLoop() {
	for {
		select {
		case sig := <-d.sigc:
			d.signal(sig)
		case <-d.tstpc:
			d.jobStop()
		case <-d.done:
			return
		}
	}
}

func (d *directChild) signal(sig os.Signal) {
	d.sigMu.Lock()
	defer d.sigMu.Unlock()
	if !d.reaped {
		_ = d.cmd.Process.Signal(sig)
	}
}

func (d *directChild) signalGroup(sig sysSignal) {
	d.sigMu.Lock()
	defer d.sigMu.Unlock()
	if !d.reaped {
		_ = killGroup(d.pid, sig)
	}
}

// jobStop handles Ctrl-Z: the child has no controlling terminal (and its
// orphaned process group ignores SIGTSTP), so the wrapper stops it with
// SIGSTOP, stops itself like any job, and continues the child on resume.
func (d *directChild) jobStop() {
	d.signalGroup(sigStop)
	contc := make(chan os.Signal, 1)
	signal.Notify(contc, sigCONT)
	signal.Stop(d.tstpc) // SIGTSTP takes its default action again: stop
	if err := stopSelf(); err == nil {
		t := time.NewTimer(contWait)
		select {
		case <-contc:
		case <-t.C:
		}
		t.Stop()
	}
	signal.Stop(contc)
	select {
	case <-d.done:
	default:
		signal.Notify(d.tstpc, sigTSTP)
	}
	d.signalGroup(sigCont)
}

func (d *directChild) isExited() bool {
	select {
	case <-d.exited:
		return true
	default:
		return false
	}
}

func (d *directChild) waitExit(dur time.Duration) bool {
	t := time.NewTimer(dur)
	defer t.Stop()
	select {
	case <-d.exited:
		return true
	case <-t.C:
		return false
	}
}

// terminate is Proxy.Terminate without quit keys (there is no PTY).
func (d *directChild) terminate(o TerminateOptions) error {
	d.termMu.Lock()
	defer d.termMu.Unlock()
	if !d.isExited() {
		d.signal(sigTerm)
		grace := o.Grace
		if grace <= 0 {
			grace = defaultGrace
		}
		if !d.waitExit(grace) {
			d.signal(sigKill)
			d.waitExit(killWait)
		}
	}
	d.sigMu.Lock()
	recent := !d.reaped || time.Since(d.exitedAt) < sessionKillWindow
	d.sigMu.Unlock()
	if recent {
		killSession(d.id, func() { d.signalGroup(sigKill) })
	}
	if !d.isExited() {
		return errStillAlive
	}
	return nil
}

func (d *directChild) wait() (int, error) {
	<-d.exited
	d.sigMu.Lock()
	defer d.sigMu.Unlock()
	return d.code, d.errW
}

// runPassthrough runs cmd in the wrapper's own process group with the
// user's stdio, ungated (SPEC §15.1 step 2): the terminal's signals reach
// both, so the wrapper only outlives the child (it forwards SIGTERM, which
// a terminal never sends, and stops itself on SIGTSTP like the child).
func runPassthrough(ctx context.Context, cmd *exec.Cmd) (int, error) {
	if cmd.Env == nil {
		return ExitNotStarted, errNoEnv
	}
	sigc := make(chan os.Signal, 4)
	signal.Notify(sigc, forwarded...)
	defer signal.Stop(sigc)
	if err := cmd.Start(); err != nil {
		return ExitNotStarted, err
	}
	done := make(chan struct{})
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait(); close(done) }()
	ctxDone := ctx.Done()
	for {
		select {
		case sig := <-sigc:
			if sig == os.Signal(sigTerm) {
				_ = cmd.Process.Signal(sig)
			}
		case <-ctxDone:
			ctxDone = nil
			_ = cmd.Process.Signal(sigTerm)
			t := time.NewTimer(defaultGrace)
			select {
			case <-done:
			case <-t.C:
				_ = cmd.Process.Kill()
				<-done
			}
			t.Stop()
		case err := <-waited:
			if _, ok := err.(*exec.ExitError); ok || cmd.ProcessState != nil {
				err = nil
			}
			return exitStatus(cmd.ProcessState), err
		}
	}
}
