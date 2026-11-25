//go:build darwin || linux

package ui_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/ui"
)

// Synthetic test values only (TESTPLAN §1).
const (
	testPrompt = "test passphrase for ~/work/acme (Ctrl-C to cancel):"
	testSecret = "synthetic-passphrase-0001"
)

// ptyTTY returns a pty and a TTY over its slave with the real terminal
// modes (golang.org/x/term).
func ptyTTY(t *testing.T) (*pty, *ui.TTY) {
	t.Helper()
	p := newPTY(t)
	return p, ui.NewTestTTY(p.slave, p.slave, true)
}

func secretOf(t *testing.T, b *memguard.LockedBuffer) string {
	t.Helper()
	if b == nil {
		t.Fatal("nil secret buffer")
	}
	return string(b.Bytes())
}

func TestSecretOverPTY(t *testing.T) {
	cases := []struct{ name, keys, want string }{
		{"plain", testSecret + "\r", testSecret},
		{"line feed ends the line", testSecret + "\n", testSecret},
		{"backspace", "abcd\x7f\x7fxy\r", "abxy"},
		{"ctrl-h", "abc\x08d\r", "abd"},
		{"backspace on empty line", "\x7f\x7fok\r", "ok"},
		{"ctrl-u", "wrong\x15right\r", "right"},
		{"arrow keys ignored", "ab\x1b[Dc\x1b[1;5C\x1bOA\r", "abc"},
		{"bracketed paste markers ignored", "\x1b[200~pasted\x1b[201~\r", "pasted"},
		{"other controls ignored", "x\x00\x01\x02\x1a\x11\x13y\r", "xy"},
		{"utf-8 backspace removes a whole character", "añ\x7fb€\r", "ab€"},
		{"ctrl-d on a non-empty line is ignored", "a\x04b\r", "ab"},
		{"empty", "\r", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, tty := ptyTTY(t)
			before := p.termios()
			ch := async(func() (*memguard.LockedBuffer, error) { return tty.Secret(testPrompt) })
			p.waitOutput(testPrompt + " ")
			p.waitEcho(false)
			p.typeKeys(c.keys)
			buf, err := await(t, ch)
			if err != nil {
				t.Fatalf("Secret: %v", err)
			}
			defer buf.Destroy()
			if got := secretOf(t, buf); got != c.want {
				t.Errorf("Secret = %q, want %q", got, c.want)
			}
			if c.want != "" && (!buf.IsAlive() || buf.IsMutable()) {
				t.Errorf("Secret buffer alive=%v mutable=%v, want a live read-only locked buffer", buf.IsAlive(), buf.IsMutable())
			}
			p.checkRestored(before)
			if c.want != "" && strings.Contains(p.output(), c.want) {
				t.Errorf("the secret was echoed: %q", p.output())
			}
		})
	}
}

func TestSecretLimit(t *testing.T) {
	p, tty := ptyTTY(t)
	ch := async(func() (*memguard.LockedBuffer, error) { return tty.Secret(testPrompt) })
	p.waitOutput(testPrompt)
	p.typeKeys(strings.Repeat("s", ui.MaxSecret+300) + "\r")
	buf, err := await(t, ch)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	defer buf.Destroy()
	if buf.Size() != ui.MaxSecret || strings.Trim(secretOf(t, buf), "s") != "" {
		t.Errorf("Secret kept %d bytes, want the first %d", buf.Size(), ui.MaxSecret)
	}
}

func TestSecretDiscardsTypeahead(t *testing.T) {
	p, tty := ptyTTY(t)
	p.typeKeys("typed-too-early")
	time.Sleep(50 * time.Millisecond) // let the kernel queue it
	ch := async(func() (*memguard.LockedBuffer, error) { return tty.Secret(testPrompt) })
	p.waitOutput(testPrompt)
	p.typeKeys(testSecret + "\r")
	buf, err := await(t, ch)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	defer buf.Destroy()
	if got := secretOf(t, buf); got != testSecret {
		t.Errorf("Secret = %q, want %q (typeahead must be discarded)", got, testSecret)
	}
}

func TestSecretCancel(t *testing.T) {
	for name, keys := range map[string]string{
		"ctrl-c":               "partial\x03",
		"ctrl-backslash":       "partial\x1c",
		"ctrl-d on empty line": "\x04",
	} {
		t.Run(name, func(t *testing.T) {
			p, tty := ptyTTY(t)
			before := p.termios()
			ch := async(func() (*memguard.LockedBuffer, error) { return tty.Secret(testPrompt) })
			p.waitOutput(testPrompt)
			p.typeKeys(keys)
			buf, err := await(t, ch)
			if !errors.Is(err, ui.ErrCancelled) || buf != nil {
				t.Fatalf("Secret = %v, %v; want nil, ErrCancelled", buf, err)
			}
			p.checkRestored(before)
			if strings.Contains(p.output(), "partial") {
				t.Errorf("cancelled input was echoed: %q", p.output())
			}
		})
	}
}

func TestCloseCancelsRunningPrompt(t *testing.T) {
	p, tty := ptyTTY(t)
	before := p.termios()
	ch := async(func() (*memguard.LockedBuffer, error) { return tty.Secret(testPrompt) })
	p.waitOutput(testPrompt)
	p.waitEcho(false)
	p.typeKeys("half")
	start := time.Now()
	if err := tty.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Close took %v", d)
	}
	if _, err := await(t, ch); !errors.Is(err, ui.ErrCancelled) {
		t.Errorf("Secret after Close = %v, want ErrCancelled", err)
	}
	p.checkRestored(before)
	if err := tty.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := tty.Secret(testPrompt); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Secret after Close = %v, want os.ErrClosed", err)
	}
	if err := tty.Display("x"); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Display after Close = %v, want os.ErrClosed", err)
	}
	tty.Printf("ignored %d", 1) // must not panic
}

func TestReadLineOverPTY(t *testing.T) {
	p, tty := ptyTTY(t)
	before := p.termios()
	prompt := ui.Format(ui.MsgConfirmTyped, ui.Vars{Action: "prune", Command: "prune"})
	ch := async(func() (string, error) { return tty.ReadLine(prompt) })
	p.waitOutput(prompt + " ")
	p.typeKeys("prx\x7fune\x1b[A\r")
	line, err := await(t, ch)
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if line != "prune" {
		t.Errorf("ReadLine = %q, want %q", line, "prune")
	}
	if !strings.Contains(p.output(), "prx\b \bune\r\n") {
		t.Errorf("typed text not echoed as edited: %q", p.output())
	}
	p.checkRestored(before)

	ch = async(func() (string, error) { return tty.ReadLine(prompt) })
	p.waitOutputN(prompt, 2)
	p.typeKeys("pru\x03")
	if _, err := await(t, ch); !errors.Is(err, ui.ErrCancelled) {
		t.Errorf("ReadLine + Ctrl-C = %v, want ErrCancelled", err)
	}
}

func TestReadLineLimit(t *testing.T) {
	p, tty := ptyTTY(t)
	ch := async(func() (string, error) { return tty.ReadLine("long:") })
	p.waitOutput("long: ")
	p.typeKeys(strings.Repeat("x", ui.MaxLine+50) + "\r")
	line, err := await(t, ch)
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if len(line) != ui.MaxLine {
		t.Errorf("ReadLine kept %d bytes, want %d", len(line), ui.MaxLine)
	}
}

func TestConfirmOverPTY(t *testing.T) {
	cases := []struct {
		name, prompt, yes, no, keys, hint string
		want                              bool
	}{
		{"yes", "Insert your YubiKey", "yes", "no", "yes\r", "Insert your YubiKey [yes/no] ", true},
		{"case and spaces", "Continue", "yes", "no", "  YES \r", "[yes/no]", true},
		{"no", "Continue", "yes", "no", "no\r", "[yes/no]", false},
		{"abbreviation is not yes", "Continue", "yes", "no", "y\r", "[yes/no]", false},
		{"anything else is no", "Continue", "yes", "no", "sure\r", "[yes/no]", false},
		{"empty answer is no", "Continue", "yes", "no", "\r", "[yes/no]", false},
		{"relayed words", "Touch failed", "Retry", "Cancel", "retry\r", "Touch failed [Retry/Cancel] ", true},
		{"relayed no word", "Touch failed", "Retry", "Cancel", "Cancel\r", "[Retry/Cancel]", false},
		{"missing words default", "Acknowledge", "", "", "yes\r", "Acknowledge [yes/no] ", true},
		{"identical words never confirm", "Pick", "same", "same", "same\r", "[same/same]", false},
		{"control characters in relayed text", "Plugin\x1b[2J says", "o\x1bk", "", "ok\r", "Plugin[2J says [ok/no] ", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, tty := ptyTTY(t)
			ch := async(func() (bool, error) { return tty.Confirm(c.prompt, c.yes, c.no) })
			p.waitOutput(c.hint)
			p.typeKeys(c.keys)
			got, err := await(t, ch)
			if err != nil {
				t.Fatalf("Confirm: %v", err)
			}
			if got != c.want {
				t.Errorf("Confirm(%q) typed %q = %v, want %v", c.prompt, c.keys, got, c.want)
			}
			if strings.Contains(p.output(), "\x1b[2J") {
				t.Errorf("relayed escape sequence reached the terminal: %q", p.output())
			}
		})
	}
}

func TestYesNoOverPTY(t *testing.T) {
	cases := []struct {
		name, prompt string
		def          bool
		answers      []string
		shown        string // the prompt as shown
		want         bool
	}{
		{"enter takes the default no", "Continue?", false, []string{"\r"}, "Continue? [y/N] ", false},
		{"enter takes the default yes", "Continue?", true, []string{"\r"}, "Continue? [Y/n] ", true},
		{"y", "Continue?", false, []string{"y\r"}, "[y/N]", true},
		{"YES", "Continue?", false, []string{"YES\r"}, "[y/N]", true},
		{"n", "Continue?", true, []string{"n\r"}, "[Y/n]", false},
		{"no", "Continue?", true, []string{" no \r"}, "[Y/n]", false},
		{"catalog hint kept", ui.Format(ui.MsgResumeTwice, ui.Vars{SID: "0123456789", PID: 7}), true, []string{"\r"}, "(--fork-session)? [Y/n] ", true},
		{"visible hint decides the default", "Open a copy? [Y/n]", false, []string{"\r"}, "Open a copy? [Y/n] ", true},
		{"visible no hint decides the default", ui.Format(ui.MsgBareWarning, ui.Vars{}), true, []string{"\r"}, "Continue? [y/N] ", false},
		{"asked again after an unclear answer", "Continue?", false, []string{"maybe\r", "y\r"}, "Continue? [y/N] ", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, tty := ptyTTY(t)
			ch := async(func() (bool, error) { return tty.YesNo(c.prompt, c.def) })
			for i, a := range c.answers {
				p.waitOutputN(c.shown, i+1)
				p.typeKeys(a)
			}
			got, err := await(t, ch)
			if err != nil {
				t.Fatalf("YesNo: %v", err)
			}
			if got != c.want {
				t.Errorf("YesNo = %v, want %v", got, c.want)
			}
			if strings.Contains(p.output(), "[Y/n] [") || strings.Contains(p.output(), "[y/N] [") {
				t.Errorf("hint shown twice: %q", p.output())
			}
		})
	}

	t.Run("unclear answers cancel", func(t *testing.T) {
		p, tty := ptyTTY(t)
		ch := async(func() (bool, error) { return tty.YesNo("Continue?", true) })
		for i := 1; i <= 3; i++ {
			p.waitOutputN("Continue? [Y/n] ", i)
			p.typeKeys("perhaps\r")
		}
		if got, err := await(t, ch); got || !errors.Is(err, ui.ErrCancelled) {
			t.Errorf("YesNo after 3 unclear answers = %v, %v; want false, ErrCancelled", got, err)
		}
	})
	t.Run("ctrl-c", func(t *testing.T) {
		p, tty := ptyTTY(t)
		ch := async(func() (bool, error) { return tty.YesNo("Continue?", true) })
		p.waitOutput("[Y/n]")
		p.typeKeys("\x03")
		if got, err := await(t, ch); got || !errors.Is(err, ui.ErrCancelled) {
			t.Errorf("YesNo + Ctrl-C = %v, %v; want false, ErrCancelled", got, err)
		}
	})
}

func TestDisplayAndPrintf(t *testing.T) {
	p, tty := ptyTTY(t)
	if err := tty.Display(ui.Format(ui.MsgUnlockTouch, ui.Vars{})); err != nil {
		t.Fatal(err)
	}
	if err := tty.Display("plugin\x1b]0;title\x07 message\n\n"); err != nil {
		t.Fatal(err)
	}
	tty.Printf("%s: %d folder(s)\x1b[2K\n", "~/work/acme", 2)
	p.waitOutput("[2K\r\n")
	want := "Touch your YubiKey...\r\nplugin]0;title message\r\n~/work/acme: 2 folder(s)[2K\r\n"
	if got := p.output(); got != want {
		t.Errorf("terminal output = %q, want %q", got, want)
	}
}

func TestPromptsOverPipes(t *testing.T) {
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer outR.Close()
	defer outW.Close()
	tty := ui.NewTestTTY(inR, outW, false)
	var mu sync.Mutex
	var out strings.Builder
	go func() {
		b := make([]byte, 1024)
		for {
			n, err := outR.Read(b)
			mu.Lock()
			out.Write(b[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	output := func() string {
		mu.Lock()
		defer mu.Unlock()
		return out.String()
	}
	waitFor := func(want string) {
		t.Helper()
		deadline := time.Now().Add(waitTimeout)
		for !strings.Contains(output(), want) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %q; output %q", want, output())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Keys typed before the secret prompt is shown are discarded.
	if _, err := inW.Write([]byte("early")); err != nil {
		t.Fatal(err)
	}
	secretCh := async(func() (*memguard.LockedBuffer, error) { return tty.Secret("pipe secret:") })
	waitFor("pipe secret: ")
	if _, err := inW.Write([]byte(testSecret + "\r")); err != nil {
		t.Fatal(err)
	}
	buf, err := await(t, secretCh)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if got := secretOf(t, buf); got != testSecret {
		t.Errorf("Secret = %q", got)
	}
	buf.Destroy()

	lineCh := async(func() (string, error) { return tty.ReadLine("type unlock:") })
	waitFor("type unlock: ")
	if _, err := inW.Write([]byte("unlock\r")); err != nil {
		t.Fatal(err)
	}
	if line, err := await(t, lineCh); err != nil || line != "unlock" {
		t.Errorf("ReadLine = %q, %v", line, err)
	}

	// End of input is an error, not a confirmation.
	confirmCh := async(func() (bool, error) { return tty.Confirm("Proceed", "yes", "no") })
	waitFor("Proceed [yes/no] ")
	_ = inW.Close()
	if ok, err := await(t, confirmCh); ok || !errors.Is(err, io.EOF) {
		t.Errorf("Confirm at end of input = %v, %v; want false, io.EOF", ok, err)
	}

	got := output()
	if strings.Contains(got, testSecret) || strings.Contains(got, "early") {
		t.Errorf("secret or typeahead echoed: %q", got)
	}
	if !strings.Contains(got, "pipe secret: \r\n") || !strings.Contains(got, "type unlock: unlock\r\n") {
		t.Errorf("unexpected output %q", got)
	}
}

func TestZeroAndNilTTY(t *testing.T) {
	var zero ui.TTY
	if err := zero.Display("x"); err == nil {
		t.Error("Display on a zero TTY succeeded")
	}
	if b, err := zero.Secret("x"); err == nil || b != nil {
		t.Error("Secret on a zero TTY succeeded")
	}
	if _, err := zero.ReadLine("x"); err == nil {
		t.Error("ReadLine on a zero TTY succeeded")
	}
	if _, err := zero.YesNo("x", true); err == nil {
		t.Error("YesNo on a zero TTY succeeded")
	}
	if _, err := zero.Confirm("x", "yes", "no"); err == nil {
		t.Error("Confirm on a zero TTY succeeded")
	}
	zero.Printf("x")
	if err := zero.Close(); err != nil {
		t.Errorf("Close on a zero TTY: %v", err)
	}

	var nilTTY *ui.TTY
	nilTTY.Printf("x")
	if err := nilTTY.Close(); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("Close on nil = %v", err)
	}
	if err := nilTTY.Display("x"); err == nil {
		t.Error("Display on nil succeeded")
	}
	if _, err := nilTTY.Secret("x"); err == nil {
		t.Error("Secret on nil succeeded")
	}
	if err := nilTTY.ShowSecretScreen(nil, nil, 4); err == nil {
		t.Error("ShowSecretScreen on nil succeeded")
	}
}

func TestOpenTTYAtPTY(t *testing.T) {
	p := newPTY(t)
	tty, err := ui.OpenTTYAt(p.name)
	if err != nil {
		t.Fatalf("open %s: %v", p.name, err)
	}
	ch := async(func() (string, error) { return tty.ReadLine("name:") })
	p.waitOutput("name: ")
	p.typeKeys("acme\r")
	if line, err := await(t, ch); err != nil || line != "acme" {
		t.Errorf("ReadLine = %q, %v", line, err)
	}
	if err := tty.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	if tty, err := ui.OpenTTYAt(os.DevNull); err == nil {
		_ = tty.Close()
		t.Errorf("OpenTTY on %s (not a terminal) succeeded", os.DevNull)
	}
	if tty, err := ui.OpenTTYAt(t.TempDir() + "/missing"); err == nil {
		_ = tty.Close()
		t.Error("OpenTTY on a missing device succeeded")
	}
}

func TestInteractive(t *testing.T) {
	p := newPTY(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	cases := []struct {
		name        string
		stdin, outp *os.File
		want        bool
	}{
		{"both terminals", p.slave, p.slave, true},
		{"pipes", r, w, false},
		{"stdin redirected", r, p.slave, false},
		{"stdout redirected", p.slave, w, false},
		{"nil", nil, nil, false},
	}
	for _, c := range cases {
		if got := ui.Interactive(c.stdin, c.outp); got != c.want {
			t.Errorf("%s: Interactive = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSecretRestoresTerminalOnSignal runs Secret through OpenTTY in a child
// whose controlling terminal is a pty, signals it mid-prompt and checks that
// the prompt was cancelled and the terminal attributes restored.
func TestSecretRestoresTerminalOnSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		t.Run(sig.String(), func(t *testing.T) {
			if signal.Ignored(sig) {
				t.Skipf("%v is ignored by this test process; the child would inherit that", sig)
			}
			p := newPTY(t)
			before := p.termios()
			h := startHelper(t, "secret", p, true)
			p.waitOutput(helperPrompt + " ")
			p.waitEcho(false)
			p.typeKeys("partial-input")
			time.Sleep(100 * time.Millisecond)
			h.signal(sig)
			if got, want := h.result(), "result=cancelled restored=true"; got != want {
				t.Errorf("helper reported %q, want %q", got, want)
			}
			p.checkRestored(before)
			if strings.Contains(p.output(), "partial-input") {
				t.Errorf("secret input was echoed: %q", p.output())
			}
			h.finish()
		})
	}
}

func TestOpenTTYSecretInSession(t *testing.T) {
	p := newPTY(t)
	before := p.termios()
	h := startHelper(t, "secret", p, true)
	p.waitOutput(helperPrompt + " ")
	p.waitEcho(false)
	p.typeKeys(testSecret + "\r")
	want := fmt.Sprintf("result=ok restored=true sha256=%x", sha256.Sum256([]byte(testSecret)))
	if got := h.result(); got != want {
		t.Errorf("helper reported %q, want %q", got, want)
	}
	p.checkRestored(before)
	if strings.Contains(p.output(), testSecret) {
		t.Errorf("secret echoed: %q", p.output())
	}
	h.finish()
}

func TestOpenTTYNeedsControllingTerminal(t *testing.T) {
	if got := startHelperResult(t, "opentty", nil, false); got != "open=error" {
		t.Errorf("OpenTTY without a controlling terminal: %q, want open=error", got)
	}
	p := newPTY(t)
	if got := startHelperResult(t, "opentty", p, true); got != "open=ok" {
		t.Errorf("OpenTTY with a controlling terminal: %q, want open=ok", got)
	}
}

// TestAgentContextControllingTerminal checks the D59 rule with the real
// /dev/tty probe in children started in a new session.
func TestAgentContextControllingTerminal(t *testing.T) {
	if got, want := startHelperResult(t, "ctty", nil, false), "ctty=false agent=true evidence=no controlling terminal"; got != want {
		t.Errorf("without a controlling terminal: %q, want %q", got, want)
	}
	p := newPTY(t)
	if got, want := startHelperResult(t, "ctty", p, true), "ctty=true agent=false evidence="; got != want {
		t.Errorf("with a controlling terminal: %q, want %q", got, want)
	}
}

func startHelperResult(t *testing.T, mode string, p *pty, ctty bool) string {
	t.Helper()
	h := startHelper(t, mode, p, ctty)
	got := h.result()
	h.finish()
	return got
}
