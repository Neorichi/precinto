// Command jobshell is a minimal job-control shell for the wrapper's job
// control test. Started as the session leader of a test PTY, it runs its
// arguments as the terminal's foreground job (a process group of its own,
// like a shell job), prints "JOBSHELL stopped" when the job stops, and puts
// it back in the foreground with SIGCONT when the test writes a line on
// fd 3 ("fg"). It exits with the job's exit code.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"
)

// setForeground makes pgid the terminal's foreground process group.
func setForeground(pgid int) {
	p := int32(pgid)
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, 0, uintptr(syscall.TIOCSPGRP), uintptr(unsafe.Pointer(&p)))
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	// Caught (not ignored, which the job would inherit): taking the
	// terminal back from a background group must not stop the shell.
	quiet := make(chan os.Signal, 4)
	signal.Notify(quiet, syscall.SIGTTOU, syscall.SIGTTIN, syscall.SIGTSTP)

	ctl := bufio.NewReader(os.NewFile(3, "ctl"))
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Env = os.Environ()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Foreground: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		fmt.Printf("JOBSHELL start failed\r\n")
		os.Exit(98)
	}
	pid := cmd.Process.Pid
	for {
		var ws syscall.WaitStatus
		_, err := syscall.Wait4(pid, &ws, syscall.WUNTRACED, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			os.Exit(99)
		}
		if ws.Stopped() {
			setForeground(syscall.Getpgrp())
			fmt.Printf("\r\nJOBSHELL stopped\r\n")
			if _, err := ctl.ReadString('\n'); err != nil {
				_ = syscall.Kill(-pid, syscall.SIGKILL)
				os.Exit(97)
			}
			setForeground(pid)
			_ = syscall.Kill(-pid, syscall.SIGCONT)
			continue
		}
		code := ws.ExitStatus()
		if ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
		fmt.Printf("\r\nJOBSHELL exit %d\r\n", code)
		os.Exit(code)
	}
}
