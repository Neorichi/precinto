package wrapper_test

import (
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/wrapper"
)

// SPEC §15.4, byte for byte.
const specReset = "\x1b[?1049l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1004l" +
	"\x1b[<99u\x1b[>4;0m\x1b[?25h\x1b[r\x1b[0m"

func TestResetSequence(t *testing.T) {
	cases := []struct {
		clear, iterm bool
		want         string
	}{
		{false, false, specReset},
		{false, true, specReset}, // iTerm2's ClearScrollback only comes with the clear
		{true, false, specReset + "\x1b[H\x1b[2J\x1b[3J"},
		{true, true, specReset + "\x1b[H\x1b[2J\x1b[3J\x1b]1337;ClearScrollback\x1b\\"},
	}
	for _, tc := range cases {
		if got := string(wrapper.ResetSequence(tc.clear, tc.iterm)); got != tc.want {
			t.Errorf("ResetSequence(%v, %v) = %q, want %q", tc.clear, tc.iterm, got, tc.want)
		}
	}
}

func TestOverlayLinesComeFromTheCatalog(t *testing.T) {
	o := wrapper.Overlay{Folder: "~/work/acme", Reason: "idle 15 min", Factor: "Mac password", Busy: true, Harness: "Claude Code"}
	lines := strings.Join(wrapper.OverlayLines(o, "", false), "\n")
	for _, want := range []string{
		ui.Format(ui.MsgOverlayTitle, ui.Vars{}),
		"~/work/acme · locked after idle 15 min",
		ui.Format(ui.MsgOverlayPaused, ui.Vars{}),
		ui.Format(ui.MsgOverlayBusy, ui.Vars{Harness: "Claude Code"}),
		ui.Format(ui.MsgOverlayKeys, ui.Vars{Factor: "Mac password"}),
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("overlay lacks %q:\n%s", want, lines)
		}
	}
	ending := strings.Join(wrapper.OverlayLines(o, "", true), "\n")
	if !strings.Contains(ending, ui.Format(ui.MsgOverlayEnding, ui.Vars{})) || strings.Contains(ending, "Ctrl-D") {
		t.Errorf("ending overlay:\n%s", ending)
	}
	notBusy := strings.Join(wrapper.OverlayLines(wrapper.Overlay{Folder: "f", Reason: "screen locked", Harness: "Codex"}, "status line", false), "\n")
	if strings.Contains(notBusy, "finishing") || !strings.Contains(notBusy, "status line") {
		t.Errorf("overlay without busy and with status:\n%s", notBusy)
	}
	// No usable factor known (CC-40): the key help names none.
	plain := strings.Join(wrapper.OverlayLines(wrapper.Overlay{Folder: "f", Reason: "screen locked"}, "", false), "\n")
	if !strings.Contains(plain, ui.Format(ui.MsgOverlayKeysPlain, ui.Vars{})) || strings.Contains(plain, "unlock (") {
		t.Errorf("overlay without a factor:\n%s", plain)
	}
}

func TestOverlaySanitizesText(t *testing.T) {
	o := wrapper.Overlay{Folder: "~/evil\x1b]52;c;AAAA\x07dir", Reason: "idle\x1b[2J", Factor: "pass\x07phrase", Busy: true, Harness: "x\x1b[31m"}
	for _, line := range wrapper.OverlayLines(o, "st\x1bPatus", false) {
		if strings.ContainsAny(line, "\x1b\x07") {
			t.Fatalf("overlay line carries control characters: %q", line)
		}
	}
}

func TestFilterReplayDropsQueriesAndSideEffects(t *testing.T) {
	keep := []string{
		"plain text\r\n",
		"\x1b[31mred\x1b[0m",
		"\x1b[2J\x1b[H\x1b[10;5H",
		"\x1b[?1049h", "\x1b[?2004h", "\x1b[?1000h",
		"\x1b]0;window title\x07", "\x1b]8;;http://example.invalid\x1b\\link\x1b]8;;\x1b\\",
		"\x1b]133;A\x07", "\x1b]11;#000000\x07",
		"\x1b7\x1b8", "\x1b(B", "\x1bM", "\x1b=",
		"\x1bOP",
	}
	drop := []string{
		"\x1b[c", "\x1b[0c", "\x1b[>c", "\x1b[=c", // device attributes
		"\x1b[5n", "\x1b[6n", "\x1b[?6n", "\x1b[?996n", // status, cursor, theme
		"\x1b[?u", "\x1b[>1u", "\x1b[<u", "\x1b[=1;1u", // kitty (restored by Modes)
		"\x1b[?2004$p", "\x1b[>q", "\x1b[18t", "\x1b[8;50;100t", "\x1b[x", "\x1b[5i",
		"\x1b]11;?\x07", "\x1b]4;1;?\x1b\\", // colour queries
		"\x1b]52;c;c2VjcmV0\x07", // clipboard
		"\x1b]9;notification\x07", "\x1b]777;notify;a;b\x07", "\x1b]99;;x\x1b\\",
		"\x1b]1337;RequestAttention=1\x07", "\x1b]1337;File=inline=1:AAAA\x07",
		"\x1bP+q544e\x1b\\", "\x1bP$qm\x1b\\", // XTGETTCAP, DECRQSS
		"\x1b_Ga=q,i=1;AAAA\x1b\\", // kitty graphics query
		"\x1bZ",                    // DECID
		"\x07", "\x05",             // bell, answerback
	}
	for _, k := range keep {
		if got := string(wrapper.FilterReplay([]byte(k))); got != k {
			t.Errorf("FilterReplay(%q) = %q, want it kept", k, got)
		}
	}
	for _, d := range drop {
		in := "A" + d + "B"
		if got := string(wrapper.FilterReplay([]byte(in))); got != "AB" {
			t.Errorf("FilterReplay(%q) = %q, want %q dropped", in, got, d)
		}
	}
}

func TestFilterReplayKeepsControlsOfDroppedSequences(t *testing.T) {
	// A CSI that executes a newline in its middle: the newline stays.
	if got := string(wrapper.FilterReplay([]byte("a\x1b[1\n0c b"))); got != "a\n b" {
		t.Fatalf("got %q", got)
	}
	// An unfinished sequence at the end is dropped.
	if got := string(wrapper.FilterReplay([]byte("done\x1b]0;tit"))); got != "done" {
		t.Fatalf("got %q", got)
	}
}

// Terminate uses the plan's values (CC-24): the adapter's quit keys and
// harness.KillGrace; a plan without them gets the 8 s floor and no keys.
func TestTerminationParameters(t *testing.T) {
	codex := wrapper.TerminateOptionsFor(harness.LaunchPlan{Harness: harness.Codex, QuitKeys: []byte{3, 3}, KillGrace: harness.KillGrace(3 * time.Second)})
	if codex.Grace != 9*time.Second || string(codex.QuitKeys) != "\x03\x03" {
		t.Errorf("codex plan: %+v, want 9 s and Ctrl-C twice", codex)
	}
	claude := wrapper.TerminateOptionsFor(harness.LaunchPlan{Harness: harness.ClaudeCode, KillGrace: harness.KillGrace(1500 * time.Millisecond)})
	if claude.Grace != 8*time.Second || len(claude.QuitKeys) != 0 {
		t.Errorf("claude plan: %+v, want 8 s and no keys", claude)
	}
	if g := wrapper.TerminateOptionsFor(harness.LaunchPlan{Harness: "generic"}); g.Grace != 8*time.Second || len(g.QuitKeys) != 0 {
		t.Errorf("plan without values: %+v, want the 8 s floor", g)
	}
	v := wrapper.PlanVars(map[string]string{"sid": "s1", "pid": "42", "folder": "~/w"})
	if v.SID != "s1" || v.PID != 42 || v.Folder != "~/w" {
		t.Errorf("PlanVars = %+v", v)
	}
}
