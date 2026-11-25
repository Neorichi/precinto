//go:build darwin || linux

package ui_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/ui"
)

// TestSecretReappliesRawModeAfterStop stops the helper mid-prompt, lets
// "the shell" restore an echoing mode meanwhile, continues it and checks
// that the prompt switched echo off again before the secret was typed.
func TestSecretReappliesRawModeAfterStop(t *testing.T) {
	p := newPTY(t)
	before := p.termios()
	h := startHelper(t, "secret", p, true)
	p.waitOutput(helperPrompt + " ")
	p.waitEcho(false)
	h.signal(syscall.SIGSTOP)
	time.Sleep(100 * time.Millisecond)
	p.setTermios(before) // cooked mode with ECHO, as a shell leaves it
	h.signal(syscall.SIGCONT)
	p.waitEcho(false)
	p.typeKeys(testSecret + "\r")
	want := fmt.Sprintf("result=ok restored=true sha256=%x", sha256.Sum256([]byte(testSecret)))
	if got := h.result(); got != want {
		t.Errorf("helper reported %q, want %q", got, want)
	}
	p.checkRestored(before)
	if strings.Contains(p.output(), testSecret) {
		t.Errorf("secret echoed after SIGCONT: %q", p.output())
	}
	h.finish()
}

func TestPromptOnNonTerminalFails(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()
	tty := ui.NewTestTTY(r, outW, true) // real terminal modes over pipes
	if b, err := tty.Secret("secret:"); err == nil || b != nil {
		t.Errorf("Secret over a pipe = %v, %v; want an error", b, err)
	}
	if _, err := tty.ReadLine("line:"); err == nil {
		t.Error("ReadLine over a pipe succeeded")
	}
	_ = outW.Close()
	buf := make([]byte, 64)
	if n, _ := outR.Read(buf); n != 0 {
		t.Errorf("prompt written although raw mode failed: %q", buf[:n])
	}
}

func TestClosedFilesFail(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	defer w.Close()
	tty := ui.NewTestTTY(r, w, false)
	done := make(chan error, 1)
	go func() {
		_, err := tty.Secret("secret:")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Secret on a closed input succeeded")
		}
	case <-time.After(waitTimeout):
		t.Fatal("Secret on a closed input hung")
	}

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = outR.Close() // nobody reads the terminal output any more
	defer outW.Close()
	tty = ui.NewTestTTY(inR, outW, false)
	if err := tty.Display("lost"); err == nil {
		t.Error("Display to a broken pipe succeeded")
	}
	tty.Printf("lost too") // errors are dropped, never a panic
}
