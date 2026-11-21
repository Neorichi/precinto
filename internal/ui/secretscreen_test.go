//go:build darwin || linux

package ui_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/ui"
)

const (
	enterAlt    = "\x1b[?1049h"
	clearScreen = "\x1b[2J"
	clearScroll = "\x1b[3J"
	iTermClear  = "\x1b]1337;ClearScrollback\x1b\\"
	leaveAlt    = "\x1b[?1049l"
	retryPrompt = "\x1b[1A\r\x1b[2K> "
)

// syntheticKey is shaped like an age identity but is not one.
var syntheticKey = "AGE-SECRET-KEY-1" + strings.Repeat("TESTKEY", 8) + "QXZW"

func lockedCopy(s string) *memguard.LockedBuffer {
	return memguard.NewBufferFromBytes([]byte(s))
}

func TestShowSecretScreen(t *testing.T) {
	p, tty := ptyTTY(t)
	before := p.termios()
	secret := lockedCopy(syntheticKey)
	defer secret.Destroy()
	header := []string{"precinto recovery key for ~/work/acme", "Write it down, then type its last 4 characters."}
	ch := async(func() (struct{}, error) { return struct{}{}, tty.ShowSecretScreen(header, secret, 4) })
	p.waitOutput("> ")
	p.typeKeys("ZZZZ\r")       // wrong
	p.waitOutput(retryPrompt)  // asked again on the same line
	p.typeKeys("q x\x7fxzw\r") // right: case and spaces do not matter
	if _, err := await(t, ch); err != nil {
		t.Fatalf("ShowSecretScreen: %v", err)
	}
	// The terminal reader polls the master: wait until the cleanup the
	// screen wrote before returning has been read, never just the bytes
	// read so far (a loaded machine delays the reader).
	p.waitOutput(clearScreen + clearScroll + iTermClear + leaveAlt)
	out := p.output()

	if !strings.HasPrefix(out, enterAlt) {
		t.Errorf("does not start on the alternate screen: %q", out)
	}
	for _, h := range header {
		if !strings.Contains(out, h+"\r\n") {
			t.Errorf("header line %q missing from %q", h, out)
		}
	}
	grouped := "  AGE-SE CRET-K EY-1TE STKEYT"
	if !strings.Contains(out, grouped) {
		t.Errorf("secret not shown in groups of 6 (%q) in %q", grouped, out)
	}
	if !strings.Contains(out, "\r\x1b[2K> q xzw") {
		t.Errorf("typed characters not shown on the prompt line: %q", out)
	}
	keyAt := strings.Index(out, "AGE-SE")
	cleanup := strings.LastIndex(out, clearScreen+clearScroll+iTermClear+leaveAlt)
	if keyAt < 0 || cleanup < keyAt {
		t.Errorf("screen and scrollback not cleared after the secret: %q", out)
	}
	if !strings.HasSuffix(out, leaveAlt) {
		t.Errorf("the alternate screen is not left last: %q", out)
	}
	p.checkRestored(before)
	if !secret.IsAlive() || string(secret.Bytes()) != syntheticKey {
		t.Errorf("the caller's buffer was destroyed or changed")
	}
}

func TestShowSecretScreenLayout(t *testing.T) {
	cases := []struct {
		name, secret, wantShown, typeBack string
		last                              int
	}{
		{"pre-grouped secret keeps its groups", "ABCDEF GHIJKL MN", "  ABCDEF GHIJKL MN\r\n", "kl mn", 4},
		{"short last group", "ABCDEFGH", "  ABCDEF GH\r\n", "efgh", 4},
		{"more characters asked than exist", "ABC", "  ABC\r\n", "abc", 10},
		{"non-ASCII characters", "äöüßéè", "  äöüßéè\r\n", "éè", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, tty := ptyTTY(t)
			secret := lockedCopy(c.secret)
			defer secret.Destroy()
			ch := async(func() (struct{}, error) { return struct{}{}, tty.ShowSecretScreen(nil, secret, c.last) })
			p.waitOutput("> ")
			p.typeKeys(c.typeBack + "\r")
			if _, err := await(t, ch); err != nil {
				t.Fatalf("ShowSecretScreen: %v", err)
			}
			if out := p.output(); !strings.Contains(out, c.wantShown) {
				t.Errorf("shown %q, want it to contain %q", out, c.wantShown)
			}
		})
	}
}

func TestShowSecretScreenWraps(t *testing.T) {
	p, tty := ptyTTY(t)
	secret := lockedCopy(strings.Repeat("ABCDEF", 20))
	defer secret.Destroy()
	ch := async(func() (struct{}, error) { return struct{}{}, tty.ShowSecretScreen(nil, secret, 4) })
	p.waitOutput("> ")
	p.typeKeys("cdef\r")
	if _, err := await(t, ch); err != nil {
		t.Fatalf("ShowSecretScreen: %v", err)
	}
	for _, line := range strings.Split(p.output(), "\r\n") {
		if strings.HasPrefix(line, "  ABCDEF") && len(line) > 79 {
			t.Errorf("line of %d columns on an 80-column terminal: %q", len(line), line)
		}
	}
}

func TestShowSecretScreenCancel(t *testing.T) {
	for name, keys := range map[string]string{"ctrl-c": "AB\x03", "ctrl-d": "\x04"} {
		t.Run(name, func(t *testing.T) {
			p, tty := ptyTTY(t)
			before := p.termios()
			secret := lockedCopy(syntheticKey)
			defer secret.Destroy()
			ch := async(func() (struct{}, error) { return struct{}{}, tty.ShowSecretScreen([]string{"key"}, secret, 4) })
			p.waitOutput("> ")
			p.typeKeys(keys)
			if _, err := await(t, ch); !errors.Is(err, ui.ErrCancelled) {
				t.Fatalf("ShowSecretScreen + %s = %v, want ErrCancelled", name, err)
			}
			p.waitOutput(clearScreen + clearScroll + iTermClear + leaveAlt) // read by the terminal reader
			if out := p.output(); !strings.HasSuffix(out, clearScreen+clearScroll+iTermClear+leaveAlt) {
				t.Errorf("screen not cleared after cancel: %q", out)
			}
			p.checkRestored(before)
		})
	}
}

func TestShowSecretScreenRefusesBadInput(t *testing.T) {
	p, tty := ptyTTY(t)
	good := lockedCopy(syntheticKey)
	defer good.Destroy()
	destroyed := lockedCopy(syntheticKey)
	destroyed.Destroy()
	controls := lockedCopy("ABCD\x1b[2JEFGH")
	defer controls.Destroy()
	spaces := lockedCopy("   ")
	defer spaces.Destroy()
	invalid := lockedCopy("AB\xffCD")
	defer invalid.Destroy()
	cases := []struct {
		name   string
		secret *memguard.LockedBuffer
		last   int
	}{
		{"confirmLast 0", good, 0},
		{"negative confirmLast", good, -4},
		{"nil secret", nil, 4},
		{"destroyed secret", destroyed, 4},
		{"control characters", controls, 4},
		{"only separators", spaces, 4},
		{"invalid UTF-8", invalid, 4},
	}
	for _, c := range cases {
		if err := tty.ShowSecretScreen([]string{"header"}, c.secret, c.last); err == nil {
			t.Errorf("%s: ShowSecretScreen succeeded", c.name)
		}
	}
	if out := p.output(); out != "" {
		t.Errorf("something was written for invalid arguments: %q", out)
	}
}

func TestShowSecretScreenNeedsATerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	tty := ui.NewTestTTY(r, w, true) // real terminal modes over a pipe
	secret := lockedCopy(syntheticKey)
	defer secret.Destroy()
	if err := tty.ShowSecretScreen(nil, secret, 4); err == nil {
		t.Fatal("ShowSecretScreen to a pipe succeeded")
	}
	_ = w.Close()
	buf := make([]byte, 64)
	if n, _ := r.Read(buf); n != 0 {
		t.Errorf("wrote %q to a pipe", buf[:n])
	}
}
