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
//
// Flags, anywhere in argv (every other argument is the harness's own):
// -lifeline FD exits with 70 when the test's lifeline pipe on FD reaches
// EOF (the test's cleanup closed it, or the test process is gone), whatever
// signals the process ignores; -probe FD hands the test's liveness probe on
// FD to every grandchild; -test-token T marks the process as the test's own
// (passed on to grandchildren); -max-life D exits with 70 after D (default
// 2 min); -ignore-term ignores SIGTERM; -burst N sets the burst size;
// -cooked leaves a terminal stdin in cooked mode; -keylog FILE also appends
// the key events it reacts to (CTRL-C n, BYE, EOF, INT, TERM) to FILE, one
// per line, so a test can see them while a lock screen hides the terminal.
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

// exitLifeline is the exit code when the lifeline ends or the hard
// lifetime runs out.
const exitLifeline = 70

var mu sync.Mutex

// keylog is the -keylog file, nil without the flag.
var keylog *os.File

// event prints a key event and appends it to the -keylog file.
func event(format string, args ...any) {
	say(format, args...)
	if keylog != nil {
		mu.Lock()
		fmt.Fprintf(keylog, format+"\n", args...)
		mu.Unlock()
	}
}

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

// options are the flags of one tuichild.
type options struct {
	lifeline   *os.File // the test's lifeline (read end), nil without -lifeline
	probe      *os.File // the test's liveness probe (write end), nil without -probe
	token      string
	maxLife    time.Duration
	ignoreTerm bool
	cooked     bool
	burst      int
	sleep      bool
	keylog     string
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

func parse(args []string) options {
	o := options{maxLife: 2 * time.Minute, burst: 50}
	var positional []string
	for i := 0; i < len(args); i++ {
		value := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "-lifeline":
			o.lifeline = inherited(value(), "lifeline")
		case "-probe":
			o.probe = inherited(value(), "probe")
		case "-test-token":
			o.token = value()
		case "-max-life":
			if d, err := time.ParseDuration(value()); err == nil && d > 0 {
				o.maxLife = d
			}
		case "-ignore-term":
			o.ignoreTerm = true
		case "-cooked":
			o.cooked = true
		case "-keylog":
			o.keylog = value()
		case "-burst":
			if n, err := strconv.Atoi(value()); err == nil {
				o.burst = n
			}
		default:
			positional = append(positional, args[i])
		}
	}
	o.sleep = len(positional) > 0 && positional[0] == "sleep"
	return o
}

// watchLifeline exits once the lifeline reaches EOF: only the test process
// holds its write end and nobody writes to it, so a read returns only when
// that end is closed. A read error counts the same.
func watchLifeline(f *os.File) {
	if f == nil {
		return
	}
	go func() {
		buf := make([]byte, 16)
		for {
			if _, err := f.Read(buf); err != nil {
				os.Exit(exitLifeline)
			}
		}
	}()
}

func main() {
	args := os.Args[1:]
	o := parse(args)
	watchLifeline(o.lifeline)
	if o.sleep {
		time.Sleep(o.maxLife)
		os.Exit(exitLifeline)
	}
	time.AfterFunc(o.maxLife, func() { os.Exit(exitLifeline) })
	if o.keylog != "" {
		f, err := os.OpenFile(o.keylog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			say("KEYLOG-ERR")
			os.Exit(exitLifeline)
		}
		keylog = f
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
				if o.ignoreTerm {
					say("TERM-IGNORED")
					continue
				}
				event("TERM")
				os.Exit(143)
			case syscall.SIGHUP:
				os.Exit(129)
			case syscall.SIGINT:
				event("INT")
				os.Exit(130)
			case syscall.SIGCONT:
				say("CONT")
			}
		}
	}()
	active := os.Getenv("PRECINTO_ACTIVE") // the wrapper sets it in the child
	if isTTY && !o.cooked {
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
					for i := 0; i < o.burst; i++ {
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
					spawnGrandchild(o, b == 'G')
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
					event("CTRL-C %d", ctrlC)
					if ctrlC >= 2 {
						event("BYE")
						return
					}
				}
			}
		}
		if err != nil {
			event("EOF")
			return
		}
	}
}

// spawnGrandchild starts "tuichild sleep" in this session with this
// process's lifeline (fd 3), probe (fd 4) and token.
func spawnGrandchild(o options, ownGroup bool) {
	self, err := os.Executable()
	if err != nil {
		say("GRANDCHILD-ERR")
		return
	}
	args := []string{"sleep", "-max-life", o.maxLife.String()}
	if o.token != "" {
		args = append(args, "-test-token", o.token)
	}
	var files []*os.File
	if o.lifeline != nil {
		files = append(files, o.lifeline)
		args = append(args, "-lifeline", strconv.Itoa(2+len(files)))
	}
	if o.probe != nil {
		files = append(files, o.probe)
	}
	cmd := exec.Command(self, args...)
	cmd.Env = []string{}
	cmd.ExtraFiles = files
	if ownGroup {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	if err := cmd.Start(); err != nil {
		say("GRANDCHILD-ERR")
		return
	}
	say("GRANDCHILD pid=%d", cmd.Process.Pid)
}
