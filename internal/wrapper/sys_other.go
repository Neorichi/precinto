//go:build !darwin && !linux

package wrapper

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// errUnsupported: the wrapper runs on darwin and linux only (D34).
var errUnsupported = errors.New("wrapper: unsupported on this OS")

var (
	sigWINCH  os.Signal = syscall.Signal(28)
	sigCONT   os.Signal = syscall.Signal(19)
	sigTSTP   os.Signal = syscall.Signal(18)
	forwarded           = []os.Signal{os.Interrupt}
)

type sysSignal = syscall.Signal

const (
	sigTerm = syscall.Signal(15)
	sigKill = syscall.Signal(9)
	sigStop = syscall.Signal(17)
	sigCont = syscall.Signal(19)
)

type winsize struct {
	Row, Col, X, Y uint16
}

type waitResult struct {
	exited   bool
	stopped  bool
	code     int
	stopSign syscall.Signal
}

func fdOf(*os.File) (int, error)                    { return -1, errUnsupported }
func readFD(int, []byte) (int, bool, error)         { return 0, true, errUnsupported }
func waitReadable(int, time.Duration) (bool, error) { return false, errUnsupported }
func getWinsize(int) (winsize, error)               { return winsize{}, errUnsupported }
func setWinsize(int, winsize) error                 { return errUnsupported }
func wait4(int, bool) (waitResult, error)           { return waitResult{}, errUnsupported }
func killGroup(int, syscall.Signal) error           { return errUnsupported }
func stopSelf() error                               { return errUnsupported }
func setSession(*exec.Cmd, bool)                    {}
func ttyName(int) string                            { return "" }
func exitStatus(ps *os.ProcessState) int            { return exitCodeOr(ps) }
func exitCodeOr(ps *os.ProcessState) int {
	if ps == nil || ps.ExitCode() < 0 {
		return 1
	}
	return ps.ExitCode()
}
