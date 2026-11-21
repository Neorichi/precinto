package wrapper

import (
	"fmt"
	"strings"
	"testing"
)

// describe renders the tokens of chunks fed in order, one per line.
func describe(input bool, chunks ...string) string {
	s := scanner{input: input}
	var out []string
	for _, c := range chunks {
		b := []byte(c)
		emit := func(t *token) {
			switch t.kind {
			case tokText:
				out = append(out, fmt.Sprintf("text %q", t.span(b)))
			case tokCtl:
				out = append(out, fmt.Sprintf("ctl %02x seq=%v", t.b, t.inSeq))
			case tokEsc:
				out = append(out, fmt.Sprintf("esc %q %q", t.inter, t.b))
			case tokSS:
				out = append(out, fmt.Sprintf("ss %c %c", t.intro, t.b))
			case tokCSI:
				out = append(out, fmt.Sprintf("csi %q %q %q %c x10=%v", t.prefix, t.params, t.inter, t.b, t.x10))
			case tokOSC:
				out = append(out, fmt.Sprintf("osc %q bel=%v", t.head, t.bel))
			case tokDCS, tokSOS:
				out = append(out, fmt.Sprintf("str %c %q", t.b, t.head))
			case tokBad:
				out = append(out, "bad")
			}
		}
		s.feed(b, emit)
		s.endChunk(len(b), emit)
	}
	return strings.Join(out, "\n")
}

func TestScannerOutputTokens(t *testing.T) {
	cases := []struct {
		chunks []string
		want   string
	}{
		{[]string{"ab\r\n"}, "text \"ab\"\nctl 0d seq=false\nctl 0a seq=false"},
		{[]string{"\x1b[?1049h"}, "csi '?' \"1049\" \"\" h x10=false"},
		{[]string{"\x1b[1;31m"}, "csi '\\x00' \"1;31\" \"\" m x10=false"},
		{[]string{"\x1b[", "?25", "l"}, "csi '?' \"25\" \"\" l x10=false"},
		{[]string{"\x1b]0;t\x07"}, "osc \"0;t\" bel=true"},
		{[]string{"\x1b]0;t\x1b\\"}, "osc \"0;t\" bel=false"},
		{[]string{"\x1b]0;t", "\x1b", "\\"}, "osc \"0;t\" bel=false"},
		{[]string{"\x1bP+q\x1b\\"}, "str P \"+q\""},
		{[]string{"\x1b(B"}, "esc \"(\" 'B'"},
		{[]string{"\x1b[1\n2H"}, "ctl 0a seq=true\ncsi '\\x00' \"12\" \"\" H x10=false"},
		{[]string{"\x1b[12\x18x"}, "bad\nctl 18 seq=false\ntext \"x\""},
		{[]string{"\x1b[12\x1b[m"}, "bad\ncsi '\\x00' \"\" \"\" m x10=false"},
		{[]string{"\x1b]0;a\x1b[m"}, "bad\ncsi '\\x00' \"\" \"\" m x10=false"},
		{[]string{"\x1b[1$p"}, "csi '\\x00' \"1\" \"$\" p x10=false"},
		{[]string{"\x1b[?1;2?h"}, "bad"},
	}
	for _, tc := range cases {
		if got := describe(false, tc.chunks...); got != tc.want {
			t.Errorf("chunks %q:\n got %s\nwant %s", tc.chunks, got, tc.want)
		}
	}
}

func TestScannerInputTokens(t *testing.T) {
	cases := []struct {
		chunks []string
		want   string
	}{
		{[]string{"\x1b"}, "esc \"\" '\\x00'"},
		{[]string{"\x1bx"}, "esc \"\" 'x'"},
		{[]string{"\x1b\x7f"}, "esc \"\" '\\x7f'"},
		{[]string{"\x1bOA"}, "ss O A"},
		{[]string{"\x1b[M !\""}, "csi '\\x00' \"\" \"\" M x10=true"},
		{[]string{"\x1b[M", " !\""}, "csi '\\x00' \"\" \"\" M x10=true"},
		{[]string{"\x1b["}, "esc \"\" '['"},
		{[]string{"\x1b[24;8", "0R"}, "csi '\\x00' \"24;80\" \"\" R x10=false"},
		{[]string{"\x1b\x1b"}, "esc \"\" '\\x00'\nesc \"\" '\\x00'"},
	}
	for _, tc := range cases {
		if got := describe(true, tc.chunks...); got != tc.want {
			t.Errorf("chunks %q:\n got %s\nwant %s", tc.chunks, got, tc.want)
		}
	}
}

func TestScannerParams(t *testing.T) {
	var got []int
	s := scanner{input: true}
	s.feed([]byte("\x1b[13;5:3;;7u"), func(t *token) {
		got = []int{t.param(0, -1), t.param(1, -1), t.subParam(1, 1, -1), t.param(2, -1), t.param(3, -1), t.param(4, -1), t.nparams()}
	})
	want := []int{13, 5, 3, -1, 7, -1, 4}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("params = %v, want %v", got, want)
	}
	if c := oscCode([]byte("52;c;x")); c != 52 {
		t.Fatalf("oscCode = %d", c)
	}
	if c := oscCode([]byte("x;1")); c != -1 {
		t.Fatalf("oscCode of a non-number = %d", c)
	}
}

func TestScannerAtGround(t *testing.T) {
	s := scanner{}
	s.feed([]byte("abc"), func(*token) {})
	if !s.atGround() {
		t.Fatal("not at ground after text")
	}
	s.feed([]byte("\x1b[3"), func(*token) {})
	if s.atGround() {
		t.Fatal("at ground inside a CSI")
	}
	s.feed([]byte("1m\xc3"), func(*token) {})
	if s.atGround() {
		t.Fatal("at ground inside a UTF-8 rune")
	}
	s.feed([]byte("\xb1"), func(*token) {})
	if !s.atGround() {
		t.Fatal("not at ground after the rune")
	}
}
