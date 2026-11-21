package wrapper_test

import (
	"testing"

	"github.com/precinto/precinto/internal/wrapper"
)

// TestHumanInputFilterTable is the UX15/D37 filter: what terminals send on
// their own is never human input, and only an unmodified Enter outside a
// paste is an Enter.
func TestHumanInputFilterTable(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		human, enter bool
	}{
		{"empty", "", false, false},
		{"letter", "a", true, false},
		{"utf-8 text", "ñandú", true, false},
		{"enter", "\r", true, true},
		{"line feed is not enter", "\n", true, false},
		{"text then enter", "ls\r", true, true},
		{"ctrl-c", "\x03", true, false},
		{"backspace", "\x7f", true, false},
		{"tab", "\t", true, false},
		{"lone escape", "\x1b", true, false},
		{"alt+x", "\x1bx", true, false},
		{"alt+enter is not enter", "\x1b\r", true, false},
		{"arrow up", "\x1b[A", true, false},
		{"application arrow", "\x1bOA", true, false},
		{"keypad enter in application mode", "\x1bOM", true, true},
		{"function key", "\x1b[15~", true, false},
		{"modified arrow", "\x1b[1;5C", true, false},
		{"shift-tab", "\x1b[Z", true, false},
		{"kitty letter", "\x1b[97u", true, false},
		{"kitty enter", "\x1b[13u", true, true},
		{"kitty enter press event", "\x1b[13;1:1u", true, true},
		{"kitty enter release is not enter", "\x1b[13;1:3u", true, false},
		{"kitty shift+enter is not enter", "\x1b[13;2u", true, false},
		{"kitty keypad enter", "\x1b[57414u", true, true},
		{"kitty enter with caps lock", "\x1b[13;65u", true, true},
		{"bracketed paste", "\x1b[200~pasted text\x1b[201~", true, false},
		{"paste with newline is not enter", "\x1b[200~line one\rline two\x1b[201~", true, false},
		{"enter after paste", "\x1b[200~p\x1b[201~\r", true, true},
		{"empty paste markers only", "\x1b[200~\x1b[201~", false, false},

		{"focus in", "\x1b[I", false, false},
		{"focus out", "\x1b[O", false, false},
		{"focus in and out", "\x1b[I\x1b[O", false, false},
		{"x10 mouse", "\x1b[M !!", false, false},
		{"x10 mouse with enter-like byte", "\x1b[M#\r!", false, false},
		{"sgr mouse press", "\x1b[<0;10;5M", false, false},
		{"sgr mouse release", "\x1b[<0;10;5m", false, false},
		{"urxvt mouse", "\x1b[32;10;5M", false, false},
		{"cursor position report", "\x1b[24;80R", false, false},
		{"extended cursor position report", "\x1b[?24;80;1R", false, false},
		{"device attributes", "\x1b[?62;22c", false, false},
		{"secondary device attributes", "\x1b[>41;354;0c", false, false},
		{"kitty flags reply", "\x1b[?1u", false, false},
		{"mode report", "\x1b[?2004;1$y", false, false},
		{"status report", "\x1b[0n", false, false},
		{"window size report", "\x1b[8;24;80t", false, false},
		{"osc colour reply BEL", "\x1b]11;rgb:0000/0000/0000\x07", false, false},
		{"osc colour reply ST", "\x1b]10;rgb:ffff/ffff/ffff\x1b\\", false, false},
		{"xtversion reply", "\x1bP>|xterm(388)\x1b\\", false, false},
		{"kitty graphics reply", "\x1b_Gi=1;OK\x1b\\", false, false},
		{"several replies", "\x1b[I\x1b[24;80R\x1b[?62c\x1b]11;rgb:1/2/3\x07", false, false},

		{"reply then key", "\x1b[24;80Rq", true, false},
		{"key then reply", "q\x1b[I", true, false},
		{"reply then enter", "\x1b[O\r", true, true},
		{"incomplete reply at end", "\x1b[24;8", false, false},
		{"alt+[ alone", "\x1b[", true, false},
		{"alt+] alone", "\x1b]", true, false},
		{"alt+O alone", "\x1bO", true, false},
		{"malformed sequence", "\x1b[1;2\x1b[3", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			human, enter := wrapper.HumanInput([]byte(tc.in))
			if human != tc.human || enter != tc.enter {
				t.Fatalf("HumanInput(%q) = (%v, %v), want (%v, %v)", tc.in, human, enter, tc.human, tc.enter)
			}
		})
	}
}

func TestHumanInputNeverPanics(t *testing.T) {
	inputs := [][]byte{
		{0x1b}, {0x1b, 0x1b, 0x1b}, {0x1b, '[', 0xff}, {0x9b, 'A'}, {0x1b, 'P'},
		[]byte("\x1b[" + string(make([]byte, 200)) + "u"),
		[]byte("\x1b]" + string(make([]byte, 5000))),
		[]byte("\x1b[M\xc3"), []byte("\x1b[999999999999999999u"),
	}
	for _, in := range inputs {
		wrapper.HumanInput(in)
	}
}
