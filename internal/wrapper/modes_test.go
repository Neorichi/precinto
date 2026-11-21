package wrapper_test

import (
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/wrapper"
)

func feed(m *wrapper.Modes, parts ...string) {
	for _, p := range parts {
		m.Feed([]byte(p))
	}
}

func TestModesUntouchedIsEmpty(t *testing.T) {
	m := wrapper.NewModes()
	feed(m, "plain text\r\n\x1b[31mcolour\x1b[0m\x1b[2J\x1b[H")
	if r := m.Reset(); len(r) != 0 {
		t.Fatalf("Reset of untouched modes = %q, want nothing", r)
	}
	if r := m.Restore(); len(r) != 0 {
		t.Fatalf("Restore of untouched modes = %q, want nothing", r)
	}
}

func TestModesTrackingTable(t *testing.T) {
	cases := []struct {
		name    string
		input   []string
		reset   []string // substrings Reset must contain, in order
		restore []string // substrings Restore must contain, in order
		absent  []string // substrings neither may contain
	}{
		{
			name:    "mouse and SGR encoding",
			input:   []string{"\x1b[?1000h\x1b[?1006h"},
			reset:   []string{"\x1b[?1000l", "\x1b[?1006l"},
			restore: []string{"\x1b[?1006h", "\x1b[?1000h"}, // encoding before tracking
		},
		{
			name:    "several modes in one sequence",
			input:   []string{"\x1b[?1002;1006;2004;1004h"},
			reset:   []string{"\x1b[?1002l", "\x1b[?1006l", "\x1b[?1004l", "\x1b[?2004l"},
			restore: []string{"\x1b[?1004h", "\x1b[?2004h", "\x1b[?1006h", "\x1b[?1002h"},
		},
		{
			name:    "set then reset is untracked",
			input:   []string{"\x1b[?2004h", "text", "\x1b[?2004l"},
			absent:  []string{"2004"},
			reset:   nil,
			restore: nil,
		},
		{
			name:    "hidden cursor: reset shows it, restore hides it",
			input:   []string{"\x1b[?25l"},
			reset:   []string{"\x1b[?25h"},
			restore: []string{"\x1b[?25l"},
		},
		{
			name:    "application cursor keys and keypad",
			input:   []string{"\x1b[?1h\x1b="},
			reset:   []string{"\x1b[?1l", "\x1b>"},
			restore: []string{"\x1b[?1h", "\x1b="},
		},
		{
			name:    "alternate screen",
			input:   []string{"\x1b[?1049h"},
			reset:   []string{"\x1b[?1049l"},
			restore: []string{"\x1b[?1049h"},
		},
		{
			name:    "legacy alternate screen 47",
			input:   []string{"\x1b[?47h"},
			reset:   []string{"\x1b[?47l"},
			restore: []string{"\x1b[?47h"},
		},
		{
			name:    "kitty flags pushed",
			input:   []string{"\x1b[>1u", "\x1b[>3u"},
			reset:   []string{"\x1b[<99u"},
			restore: []string{"\x1b[>1u", "\x1b[>3u"},
		},
		{
			name:   "kitty push then pop is empty",
			input:  []string{"\x1b[>1u", "\x1b[<u"},
			absent: []string{"u"},
		},
		{
			name:    "kitty set",
			input:   []string{"\x1b[=5;1u"},
			reset:   []string{"\x1b[<99u"},
			restore: []string{"\x1b[=5;1u"},
		},
		{
			name:    "modifyOtherKeys",
			input:   []string{"\x1b[>4;2m"},
			reset:   []string{"\x1b[>4;0m"},
			restore: []string{"\x1b[>4;2m"},
		},
		{
			name:    "synchronized output is only turned off",
			input:   []string{"\x1b[?2026h"},
			reset:   []string{"\x1b[?2026l"},
			restore: nil,
			absent:  []string{"\x1b[?2026h"},
		},
		{
			name:   "unknown private modes are ignored",
			input:  []string{"\x1b[?12345h\x1b[?5h"},
			absent: []string{"12345", "?5"},
		},
		{
			name:    "sequence split across writes",
			input:   []string{"\x1b[", "?10", "00h"},
			reset:   []string{"\x1b[?1000l"},
			restore: []string{"\x1b[?1000h"},
		},
		{
			name:   "RIS resets everything",
			input:  []string{"\x1b[?1000h\x1b[?1049h\x1b[>1u\x1b=", "\x1bc"},
			absent: []string{"1000", "1049", "u", "\x1b="},
		},
		{
			name:    "DECSTR resets cursor keys and visibility",
			input:   []string{"\x1b[?1h\x1b[?25l\x1b[?1000h", "\x1b[!p"},
			reset:   []string{"\x1b[?1000l"},
			restore: []string{"\x1b[?1000h"},
			absent:  []string{"?1h", "?1l", "?25"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := wrapper.NewModes()
			feed(m, tc.input...)
			reset, restore := string(m.Reset()), string(m.Restore())
			assertInOrder(t, "Reset", reset, tc.reset)
			assertInOrder(t, "Restore", restore, tc.restore)
			if tc.reset == nil && tc.absent != nil && len(reset) != 0 {
				for _, a := range tc.absent {
					if strings.Contains(reset, a) {
						t.Errorf("Reset = %q contains %q", reset, a)
					}
				}
			}
			for _, a := range tc.absent {
				if strings.Contains(restore, a) {
					t.Errorf("Restore = %q contains %q", restore, a)
				}
			}
		})
	}
}

func assertInOrder(t *testing.T, what, got string, want []string) {
	t.Helper()
	rest := got
	for _, w := range want {
		i := strings.Index(rest, w)
		if i < 0 {
			t.Errorf("%s = %q: missing %q (in order %q)", what, got, w, want)
			return
		}
		rest = rest[i+len(w):]
	}
}

func TestModesAltScreenKittyStacksPerScreen(t *testing.T) {
	m := wrapper.NewModes()
	// Flags pushed on the main screen, then on the alternate screen.
	feed(m, "\x1b[>1u", "\x1b[?1049h", "\x1b[>8u")
	reset := string(m.Reset())
	// Pop on the alternate screen, leave it, pop on the main screen.
	assertInOrder(t, "Reset", reset, []string{"\x1b[<99u", "\x1b[?1049l", "\x1b[<99u"})
	restore := string(m.Restore())
	// Rebuild the main stack, enter the alternate screen, rebuild its stack.
	assertInOrder(t, "Restore", restore, []string{"\x1b[>1u", "\x1b[?1049h", "\x1b[>8u"})
}

func TestModesLeavingAltScreenKeepsMainFlags(t *testing.T) {
	m := wrapper.NewModes()
	feed(m, "\x1b[>1u", "\x1b[?1049h", "\x1b[>8u", "\x1b[?1049l")
	restore := string(m.Restore())
	if strings.Contains(restore, "1049") || strings.Contains(restore, ">8u") {
		t.Fatalf("Restore = %q: the alternate screen and its flags are gone", restore)
	}
	assertInOrder(t, "Restore", restore, []string{"\x1b[>1u"})
}

func TestModesRestoreReestablishesFromReset(t *testing.T) {
	// Feeding Reset and then Restore to a second tracker yields the same
	// tracked state as the original (the round trip of a lock).
	m := wrapper.NewModes()
	feed(m, "\x1b[?1000;1006h\x1b[?2004h\x1b[?25l\x1b[?1049h\x1b[>4;1m\x1b=")
	shadow := wrapper.NewModes()
	feed(shadow, "\x1b[?1000;1006h\x1b[?2004h\x1b[?25l\x1b[?1049h\x1b[>4;1m\x1b=")
	shadow.Feed(m.Reset())
	if r := shadow.Reset(); len(r) != 0 {
		t.Fatalf("after applying Reset, a tracker still needs %q", r)
	}
	shadow.Feed(m.Restore())
	if got, want := string(shadow.Restore()), string(m.Restore()); got != want {
		t.Fatalf("after Restore the state differs:\n got %q\nwant %q", got, want)
	}
}

func TestModesZeroValueIsSafe(t *testing.T) {
	var m wrapper.Modes
	m.Feed([]byte("\x1b[?1000h"))
	if r := string(m.Reset()); !strings.Contains(r, "\x1b[?1000l") {
		t.Fatalf("zero-value Modes: Reset = %q", r)
	}
}

func TestModesIgnoresGarbage(t *testing.T) {
	m := wrapper.NewModes()
	feed(m, "\x1b[?", "\x18", "1000h", "\x1b[?1000;\x1b[?2004h", "\x1b[?99999999999999h", "\xff\xfe")
	reset := string(m.Reset())
	if strings.Contains(reset, "1000") {
		t.Fatalf("Reset = %q: a cancelled sequence was tracked", reset)
	}
	if !strings.Contains(reset, "\x1b[?2004l") {
		t.Fatalf("Reset = %q: the sequence after the aborted one was lost", reset)
	}
}
