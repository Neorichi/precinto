//go:build darwin || linux

package shellinit_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/precinto/precinto/internal/shellinit"
	"github.com/precinto/precinto/internal/ui"
)

// hostileName is a folder name made of everything a shell could take for
// code: quotes, command substitutions of both kinds, variables, globs,
// braces, operators, a backslash escape and a trailing space. A protected
// folder may have any of them (config.Validate refuses only control
// characters), and the scripts must treat it as data (D69).
const hostileName = `it's "$(touch pwned-1)" ` + "`touch pwned-2`" + ` $HOME;id|cat&*?[x]{a,b} ~ \t `

// ptyShell is an interactive shell on a pseudo-terminal of its own. It is
// the test's child in a session of its own; closing the master hangs it up
// (its lifeline), and the cleanup kills and reaps it whatever happened.
type ptyShell struct {
	t      *testing.T
	cmd    *exec.Cmd
	master *os.File

	mu   sync.Mutex
	out  bytes.Buffer
	done chan struct{}
}

func startPTYShell(t *testing.T, argv []string, dir string, env []string) *ptyShell {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = env
	master, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 40, Cols: 400})
	if err != nil {
		t.Fatalf("start %v on a pty: %v", argv, err)
	}
	s := &ptyShell{t: t, cmd: cmd, master: master, done: make(chan struct{})}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				s.mu.Lock()
				s.out.Write(buf[:n])
				s.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		_ = cmd.Wait()
		close(s.done)
	}()
	t.Cleanup(func() {
		select {
		case <-s.done:
		default:
			// The shell leads its own session (pty.Start uses Setsid): kill
			// that whole process group, which this test created.
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-s.done
		}
		_ = master.Close()
	})
	return s
}

func (s *ptyShell) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.String()
}

func (s *ptyShell) send(text string) {
	s.t.Helper()
	if _, err := io.WriteString(s.master, text); err != nil {
		s.t.Fatalf("write to the pty: %v", err)
	}
}

// expect waits until sub appears after offset from and returns the offset
// just past it.
func (s *ptyShell) expect(sub string, from int) int {
	s.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if i := strings.Index(s.text()[from:], sub); i >= 0 {
			return from + i + len(sub)
		}
		select {
		case <-s.done:
			if i := strings.Index(s.text()[from:], sub); i >= 0 {
				return from + i + len(sub)
			}
			s.t.Fatalf("the shell exited before %q appeared:\n%q", sub, s.text()[from:])
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("timed out waiting for %q:\n%q", sub, s.text()[from:])
		}
	}
}

func (s *ptyShell) wait() {
	s.t.Helper()
	select {
	case <-s.done:
	case <-time.After(20 * time.Second):
		s.t.Fatalf("the shell did not exit:\n%q", s.text())
	}
}

// argvLog is a fake precinto that appends each invocation's arguments to
// a log (every argument ends with a unit separator, every invocation with
// a record separator, so any argument text is kept exactly) and answers
// `shell-hook --pwd $HOSTILE_DIR` with the result file.
func argvLog(t *testing.T, dir string) (exe, log, result string) {
	t.Helper()
	exe = filepath.Join(dir, "bin", "precinto")
	log = filepath.Join(dir, "argv.log")
	result = filepath.Join(dir, "result.txt")
	if err := os.MkdirAll(filepath.Dir(exe), 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\037' \"$a\"; done >>'" + log + "'\n" +
		"printf '\\036' >>'" + log + "'\n" +
		"if [ \"$1\" = shell-hook ] && [ \"$5\" = \"$HOSTILE_DIR\" ]; then cat '" + result + "'; fi\n"
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return exe, log, result
}

// readCalls returns the logged invocations, each as its argument list.
func readCalls(t *testing.T, log string) [][]string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	var calls [][]string
	for _, rec := range strings.Split(string(b), "\x1e") {
		if rec == "" {
			continue
		}
		calls = append(calls, strings.Split(strings.TrimSuffix(rec, "\x1f"), "\x1f"))
	}
	return calls
}

// waitCalls polls the log until it holds n invocations.
func waitCalls(t *testing.T, log string, n int) [][]string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		calls := readCalls(t, log)
		if len(calls) >= n || time.Now().After(deadline) {
			return calls
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestFolderEntryHookOnATerminal runs the zsh and bash integration on a
// pseudo-terminal, as a user's interactive shell (D29, D69): entering a
// folder whose name is made of shell syntax prints its C1 message
// verbatim; Enter runs `precinto unlock --root <path>` with that exact path
// as one argument; any other key and Ctrl-C skip, and the shell keeps
// working; the skip key is remembered; nothing in the name ever runs.
func TestFolderEntryHookOnATerminal(t *testing.T) {
	type run struct {
		name  string
		argv  []string
		shell string
	}
	var runs []run
	if zsh := lookShell("zsh"); zsh != "" {
		runs = append(runs, run{"zsh", []string{zsh, "-f", "-i"}, shellinit.Zsh})
	}
	for _, b := range bashes() {
		runs = append(runs, run{"bash" + strings.ReplaceAll(b, "/", "_"), []string{b, "--norc", "--noprofile", "-i"}, shellinit.Bash})
	}
	if len(runs) == 0 {
		t.Skip("neither zsh nor bash installed")
	}
	for _, r := range runs {
		t.Run(r.name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			home := filepath.Join(dir, "home")
			hostile := filepath.Join(home, hostileName)
			if err := os.MkdirAll(hostile, 0o700); err != nil {
				t.Fatal(err)
			}
			exe, log, result := argvLog(t, dir)
			folder := "~/" + hostileName
			res := shellinit.EnterResult{Action: shellinit.EnterPrompt, RootID: "root-x", Path: hostile, Folder: folder, Epoch: 7,
				Message: ui.Format(ui.MsgEnterPromptPlain, ui.Vars{Folder: folder})}
			if err := os.WriteFile(result, []byte(res.Lines()), 0o600); err != nil {
				t.Fatal(err)
			}
			s, err := shellinit.Script(shellinit.Options{Shell: r.shell, Exe: exe})
			if err != nil {
				t.Fatal(err)
			}
			init := filepath.Join(dir, "init.sh")
			if err := os.WriteFile(init, []byte(s), 0o600); err != nil {
				t.Fatal(err)
			}
			env := []string{"HOME=" + home, "ZDOTDIR=" + home, "PATH=" + filepath.Dir(exe) + ":/usr/bin:/bin", "TERM=dumb",
				"PS1=$ ", "BASH_SILENCE_DEPRECATION_WARNING=1", "HOSTILE_DIR=" + hostile}
			sh := startPTYShell(t, r.argv, home, env)

			sh.send(". '" + init + "'\r")
			waitCalls(t, log, 1) // the first prompt after sourcing: --first, outside the folder

			// Enter unlocks the exact folder.
			m := len(sh.text())
			sh.send("cd -- \"$HOSTILE_DIR\"\r")
			sh.expect(res.Message+" ", m)
			time.Sleep(200 * time.Millisecond) // the key read has started
			sh.send("\r")
			waitCalls(t, log, 3)

			// Any other key skips; the folder and epoch were remembered.
			sh.send("cd ..\r")
			waitCalls(t, log, 4)
			m = len(sh.text())
			sh.send("cd -- \"$HOSTILE_DIR\"\r")
			sh.expect(res.Message+" ", m)
			time.Sleep(200 * time.Millisecond)
			sh.send("n")
			waitCalls(t, log, 5)

			// Ctrl-C skips too, and the shell still runs commands.
			sh.send("cd ..\r")
			waitCalls(t, log, 6)
			m = len(sh.text())
			sh.send("cd -- \"$HOSTILE_DIR\"\r")
			sh.expect(res.Message+" ", m)
			time.Sleep(200 * time.Millisecond)
			sh.send("\x03")
			time.Sleep(200 * time.Millisecond)
			m = len(sh.text())
			sh.send("echo still-$((6*7))\r")
			sh.expect("still-42", m)
			sh.send("exit\r")
			sh.wait()

			calls := readCalls(t, log)
			hook := func(pwd, prev, skip string, first bool) []string {
				c := []string{"shell-hook", "--shell", r.shell, "--pwd", pwd, "--prev", prev, "--skip", skip}
				if first {
					c = append(c, "--first")
				}
				return c
			}
			want := [][]string{
				hook(home, "", "", true),
				hook(hostile, home, "", false),
				{"unlock", "--root", hostile},
				hook(home, hostile, "root-x:7", false),
				hook(hostile, home, "root-x:7", false),
				hook(home, hostile, "root-x:7", false),
				hook(hostile, home, "root-x:7", false),
			}
			if !equalCalls(calls, want) {
				t.Errorf("precinto invocations:\n%s\nwant:\n%s\nterminal:\n%q", formatCalls(calls), formatCalls(want), sh.text())
			}
			// The message reached the terminal byte for byte (no escape
			// interpretation, no expansion).
			if !strings.Contains(sh.text(), res.Message) {
				t.Errorf("the message was altered on the terminal:\n%q", sh.text())
			}
			for _, d := range []string{dir, home, hostile} {
				for _, f := range []string{"pwned-1", "pwned-2"} {
					if _, err := os.Lstat(filepath.Join(d, f)); err == nil {
						t.Errorf("the folder name was executed: %s exists in %s", f, d)
					}
				}
			}
		})
	}
}

func equalCalls(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.Join(a[i], "\x00") != strings.Join(b[i], "\x00") {
			return false
		}
	}
	return true
}

func formatCalls(calls [][]string) string {
	var b strings.Builder
	for _, c := range calls {
		b.WriteString("  ")
		for _, a := range c {
			b.WriteString("[" + a + "]")
		}
		b.WriteString("\n")
	}
	return b.String()
}
