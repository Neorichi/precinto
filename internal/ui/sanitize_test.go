package ui_test

import (
	"bytes"
	"testing"
	"unicode/utf8"

	"github.com/Neorichi/precinto/internal/ui"
)

func TestSanitizeTerminal(t *testing.T) {
	allC0 := make([]byte, 0, 0x20)
	for c := byte(0); c < 0x20; c++ {
		allC0 = append(allC0, c)
	}
	cases := []struct{ name, in, want string }{
		{"plain text", "hello, world", "hello, world"},
		{"newline and tab kept", "a\tb\nc\n", "a\tb\nc\n"},
		{"CSI colour", "\x1b[31mred\x1b[0m", "[31mred[0m"},
		{"clear screen", "\x1b[2J\x1b[3Jtext", "[2J[3Jtext"},
		{"OSC title with BEL", "\x1b]0;title\x07after", "]0;titleafter"},
		{"OSC with ST", "\x1b]1337;ClearScrollback\x1b\\x", "]1337;ClearScrollback\\x"},
		{"carriage return and backspace", "abc\rX\bY", "abcXY"},
		{"every C0 control", string(allC0), "\t\n"},
		{"NUL", "a\x00b", "ab"},
		{"DEL", "a\x7fb", "ab"},
		{"C1 encoded as UTF-8", "a\u009b31mb\u0085c\u0080d\u009fe", "a31mbcde"},
		{"raw 8-bit CSI", "a\x9b31mb", "a31mb"},
		{"raw 8-bit OSC and ST", "\x9d0;x\x9cy", "0;xy"},
		{"UTF-8 text", "café · ↑ … 😀 ∑ 日本語", "café · ↑ … 😀 ∑ 日本語"},
		{"no-break space", "a b", "a b"},
		{"replacement character", "�", "�"},
		{"invalid bytes outside C1 kept", "\xe9t\xe9\xff", "\xe9t\xe9\xff"},
		{"truncated sequence then control", "\xe2\x82\x1b[0m", "\xe2[0m"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := string(ui.SanitizeTerminal([]byte(c.in))); got != c.want {
				t.Errorf("SanitizeTerminal(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
	if got := ui.SanitizeTerminal(nil); len(got) != 0 {
		t.Errorf("SanitizeTerminal(nil) = %q", got)
	}
}

func TestSanitizeTerminalCopies(t *testing.T) {
	in := []byte("clean text")
	out := ui.SanitizeTerminal(in)
	out[0] = 'X'
	if string(in) != "clean text" {
		t.Errorf("SanitizeTerminal aliased its input: %q", in)
	}
	dirty := []byte("a\x1bb")
	ui.SanitizeTerminal(dirty)
	if string(dirty) != "a\x1bb" {
		t.Errorf("SanitizeTerminal modified its input: %q", dirty)
	}
}

// checkSanitized asserts the output invariants: no C0 control except '\n'
// and '\t', no DEL, no C1 control (encoded or as a raw byte), output a
// subsequence of the input, and idempotence.
func checkSanitized(t *testing.T, in, out []byte) {
	t.Helper()
	for i := 0; i < len(out); {
		r, size := utf8.DecodeRune(out[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			if out[i] >= 0x80 && out[i] < 0xa0 {
				t.Fatalf("raw C1 byte %#x at %d in %q (input %q)", out[i], i, out, in)
			}
		case r < 0x20 && r != '\n' && r != '\t', r == 0x7f, r >= 0x80 && r <= 0x9f:
			t.Fatalf("control %U at %d in %q (input %q)", r, i, out, in)
		}
		i += size
	}
	j := 0
	for i := 0; i < len(in) && j < len(out); i++ {
		if in[i] == out[j] {
			j++
		}
	}
	if j != len(out) {
		t.Fatalf("output %q is not a subsequence of input %q", out, in)
	}
	if again := ui.SanitizeTerminal(out); !bytes.Equal(again, out) {
		t.Fatalf("not idempotent: %q then %q", out, again)
	}
}

func FuzzSanitizeTerminal(f *testing.F) {
	for _, seed := range []string{
		"", "plain", "\x1b[31mred\x1b[0m", "\u009b2J", "\x9b2J", "\xc2\x01\x9b",
		"\xe2\x01\xa0\xa0", "\xc2\x1b\x80", "é\x00è", "\xed\xa0\x80", "😀\x7f",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		orig := bytes.Clone(in)
		out := ui.SanitizeTerminal(in)
		if !bytes.Equal(in, orig) {
			t.Fatalf("input modified: %q -> %q", orig, in)
		}
		checkSanitized(t, in, out)
	})
}
