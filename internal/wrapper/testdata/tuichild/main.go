// Command tuichild is the scripted TUI child of the wrapper tests. It
// reports what it observes in a line-oriented form the tests parse, and
// reacts to single-byte commands typed on its stdin:
//
//	o   print OUT-<n>                 b   print a burst of numbered lines
//	A   enter the alternate screen    a   leave it
//	M   enable SGR mouse reporting    P   enable bracketed paste
//	K   push kitty keyboard flags     H   hide the cursor
//	Q   send terminal queries         g   spawn a grandchild (same group)
//	G   spawn a grandchild in a new process group of the same session
//	z   stop itself with SIGSTOP      q   exit 0      x   exit 7
//	Ctrl-C twice                      exit 0 (Codex-style quit keys)
//
// "tuichild sleep" just sleeps (the grandchild and sibling processes).
// Flags: -ignore-term ignores SIGTERM; -burst N sets the burst size;
// -cooked leaves a terminal stdin in cooked mode.
// Every line it prints is synthetic.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/term"
)

var mu sync.Mutex

func say(format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Fprintf(os.Stdout, format+"\r\n", args...)
}

func raw(s string) {
	mu.Lock()
	defer mu.Unlock()
	_, _ = os.Stdout.WriteString(s)
}

func getsid() int {
	sid, _, _ := syscall.RawSyscall(syscall.SYS_GETSID, 0, 0, 0)
	return int(sid)
}

func winsize() (int, int) {
	var ws struct{ Row, Col, X, Y uint16 }
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, 0, uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	return int(ws.Col), int(ws.Row)
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "sleep" {
		time.Sleep(10 * time.Minute)
		return
	}
	ignoreTerm, cooked := false, false
	burst := 50
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-ignore-term":
			ignoreTerm = true
		case "-cooked":
			cooked = true
		case "-burst":
			if i+1 < len(args) {
				burst, _ = strconv.Atoi(args[i+1])
				i++
			}
		}
	}
	isTTY := term.IsTerminal(0)
	sigc := make(chan os.Signal, 8)
	signal.Notify(sigc, syscall.SIGWINCH, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGCONT)
	go func() {
		for sig := range sigc {
			switch sig {
			case syscall.SIGWINCH:
				c, r := winsize()
				say("WINCH %dx%d", c, r)
			case syscall.SIGTERM:
				if ignoreTerm {
					say("TERM-IGNORED")
					continue
				}
				say("TERM")
				os.Exit(143)
			case syscall.SIGHUP:
				os.Exit(129)
			case syscall.SIGINT:
				say("INT")
				os.Exit(130)
			case syscall.SIGCONT:
				say("CONT")
			}
		}
	}()
	active := os.Getenv("PRECINTO_ACTIVE") // the wrapper sets it in the child
	if isTTY && !cooked {
		if st, err := term.MakeRaw(0); err == nil {
			defer func() { _ = term.Restore(0, st) }()
		}
	}
	c, r := winsize()
	say("ARGV %s", strings.Join(args, " "))
	say("AWAY=%s", os.Getenv("CLAUDE_CODE_ENABLE_AWAY_SUMMARY"))
	say("READY pid=%d pgid=%d sid=%d tty=%v active=%s size=%dx%d", os.Getpid(), syscall.Getpgrp(), getsid(), isTTY, active, c, r)

	buf := make([]byte, 4096)
	outN, ctrlC := 0, 0
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			say("IN:%x", buf[:n])
			for _, b := range buf[:n] {
				switch b {
				case 'o':
					outN++
					say("OUT-%d", outN)
				case 'b':
					for i := 0; i < burst; i++ {
						say("BURST-%05d %s", i, strings.Repeat("x", 60))
					}
					say("BURST-END")
				case 'A':
					raw("\x1b[?1049h")
					say("ALT-SCREEN")
				case 'a':
					raw("\x1b[?1049l")
					say("MAIN-SCREEN")
				case 'M':
					raw("\x1b[?1000h\x1b[?1006h")
					say("MOUSE-ON")
				case 'P':
					raw("\x1b[?2004h")
					say("PASTE-ON")
				case 'K':
					raw("\x1b[>1u")
					say("KITTY-ON")
				case 'H':
					raw("\x1b[?25l")
					say("CURSOR-OFF")
				case 'Q':
					raw("\x1b[c\x1b[6n\x1b]11;?\x07")
					say("QUERIED")
				case 'g', 'G':
					spawnGrandchild(b == 'G')
				case 'z':
					say("STOPPING")
					_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP)
					say("RESUMED")
				case 'q':
					say("BYE")
					return
				case 'x':
					say("BYE-7")
					os.Exit(7)
				case 0x03:
					ctrlC++
					say("CTRL-C %d", ctrlC)
					if ctrlC >= 2 {
						say("BYE")
						return
					}
				}
			}
		}
		if err != nil {
			say("EOF")
			return
		}
	}
}

// spawnGrandchild starts "tuichild sleep" in this session, passing on fd 3
// (the test's liveness pipe) when present.
func spawnGrandchild(ownGroup bool) {
	self, err := os.Executable()
	if err != nil {
		say("GRANDCHILD-ERR")
		return
	}
	cmd := exec.Command(self, "sleep")
	cmd.Env = []string{}
	if f := os.NewFile(3, "pipe"); f != nil {
		if _, err := f.Stat(); err == nil {
			cmd.ExtraFiles = []*os.File{f}
		}
	}
	if ownGroup {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	if err := cmd.Start(); err != nil {
		say("GRANDCHILD-ERR")
		return
	}
	say("GRANDCHILD pid=%d", cmd.Process.Pid)
}
