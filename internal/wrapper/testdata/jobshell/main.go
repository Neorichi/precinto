// Command jobshell is a minimal job-control shell for the wrapper's job
// control tests. Started as the session leader of a test PTY, it runs its
// arguments as the terminal's foreground job (a process group of its own,
// like a shell job), prints "JOBSHELL stopped" when the job stops, and puts
// it back in the foreground with SIGCONT when the test writes a line on its
// control pipe ("fg"). It exits with the job's exit code.
//
// Flags, before the job's argv: -ctl FD is the control pipe (no "fg"
// without it); -lifeline FD is the test's lifeline: at EOF (the test's
// cleanup closed it, or the test process is gone) the job's process group
// is SIGKILLed and jobshell exits with 70, and the job gets it as its fd 3;
// -test-token T marks the process as the test's own; -max-life D ends it
// the same way after D (default 2 min).
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

// exitLifeline is the exit code when the lifeline ends or the hard
// lifetime runs out.
const exitLifeline = 70

// setForeground makes pgid the terminal's foreground process group.
func setForeground(pgid int) {
	p := int32(pgid)
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, 0, uintptr(syscall.TIOCSPGRP), uintptr(unsafe.Pointer(&p)))
}

// options are the flags before the job's argv.
type options struct {
	ctl      *os.File
	lifeline *os.File
	maxLife  time.Duration
}

// inherited wraps descriptor fd once: an *os.File closes its descriptor
// when it is garbage-collected, so each one is created once and kept.
func inherited(fd, name string) *os.File {
	n, err := strconv.Atoi(fd)
	if err != nil || n < 3 {
		return nil
	}
	return os.NewFile(uintptr(n), name)
}

func parse(args []string) (options, []string) {
	o := options{maxLife: 2 * time.Minute}
	for len(args) >= 2 {
		switch args[0] {
		case "-ctl":
			o.ctl = inherited(args[1], "ctl")
		case "-lifeline":
			o.lifeline = inherited(args[1], "lifeline")
		case "-test-token":
		case "-max-life":
			if d, err := time.ParseDuration(args[1]); err == nil && d > 0 {
				o.maxLife = d
			}
		default:
			return o, args
		}
		args = args[2:]
	}
	return o, args
}

// waited is one decoded wait status.
type waited struct {
	exited, stopped bool
	code            int // exit status, or 128+signal
}

// decode reads a wait status from its bits (the same on darwin and linux),
// like the wrapper's own decodeWait: low 7 bits 0 is an exit, 0x7f a stop,
// anything else death by that signal. syscall.WaitStatus.Stopped cannot be
// used: on darwin it reports a SIGSTOP stop as "continued". ok is false for
// a continue report (linux 0xffff).
func decode(w uint32) (r waited, ok bool) {
	low, high := w&0x7f, (w>>8)&0xff
	switch {
	case low == 0:
		return waited{exited: true, code: int(high)}, true
	case low == 0x7f:
		if high == 0xff {
			return waited{}, false
		}
		return waited{stopped: true}, true
	}
	return waited{exited: true, code: 128 + int(low)}, true
}

func main() {
	o, job := parse(os.Args[1:])
	if len(job) == 0 {
		os.Exit(2)
	}
	// Caught (not ignored, which the job would inherit): taking the
	// terminal back from a background group must not stop the shell.
	quiet := make(chan os.Signal, 4)
	signal.Notify(quiet, syscall.SIGTTOU, syscall.SIGTTIN, syscall.SIGTSTP)

	cmd := exec.Command(job[0], job[1:]...)
	cmd.Env = os.Environ()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if o.lifeline != nil {
		cmd.ExtraFiles = []*os.File{o.lifeline}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Foreground: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		fmt.Printf("JOBSHELL start failed\r\n")
		os.Exit(98)
	}
	pid := cmd.Process.Pid
	end := func(code int) {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		os.Exit(code)
	}
	if o.lifeline != nil {
		go func() {
			buf := make([]byte, 16)
			for {
				if _, err := o.lifeline.Read(buf); err != nil {
					end(exitLifeline)
				}
			}
		}()
	}
	time.AfterFunc(o.maxLife, func() { end(exitLifeline) })
	var ctl *bufio.Reader
	if o.ctl != nil {
		ctl = bufio.NewReader(o.ctl)
	}
	for {
		var ws syscall.WaitStatus
		_, err := syscall.Wait4(pid, &ws, syscall.WUNTRACED, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			os.Exit(99)
		}
		w, ok := decode(uint32(ws))
		switch {
		case !ok:
		case w.stopped:
			setForeground(syscall.Getpgrp())
			fmt.Printf("\r\nJOBSHELL stopped\r\n")
			if ctl == nil {
				end(97)
			}
			if _, err := ctl.ReadString('\n'); err != nil {
				end(97)
			}
			setForeground(pid)
			_ = syscall.Kill(-pid, syscall.SIGCONT)
		default:
			fmt.Printf("\r\nJOBSHELL exit %d\r\n", w.code)
			os.Exit(w.code)
		}
	}
}
