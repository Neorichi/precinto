package ui_test

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Neorichi/precinto/internal/ui"
)

// Additional coverage of the scaffold-implemented message helpers (their
// own tests live in catalog_test.go and stay unchanged).

func TestReasonTexts(t *testing.T) {
	for _, c := range []struct {
		r    ui.Reason
		d    time.Duration
		want string
	}{
		{ui.ReasonIdle, 15 * time.Minute, "idle 15 min"},
		{ui.ReasonScreen, 0, "screen locked"},
		{ui.ReasonLimit, 8 * time.Hour, "8 h limit reached"},
		{ui.ReasonManual, 0, "locked by you"},
		{ui.ReasonSleep, 0, "computer slept"},
		{ui.ReasonStart, 0, "not unlocked yet"},
		{ui.ReasonAgent, 0, "the precinto agent stopped responding"},
		{ui.Reason("other"), 0, "other"},
	} {
		if got := ui.ReasonText(c.r, c.d); got != c.want {
			t.Errorf("ReasonText(%q, %v) = %q, want %q", c.r, c.d, got, c.want)
		}
	}
}

func TestFormatEdges(t *testing.T) {
	if got := ui.Format(ui.MsgID("Z9.unknown"), ui.Vars{}); got != "Z9.unknown" {
		t.Errorf("unknown id renders %q", got)
	}
	if got := ui.Format(ui.MsgResumeMiss, ui.Vars{SID: "abc"}); !strings.Contains(got, "session abc is sealed") {
		t.Errorf("short sid: %q", got)
	}
	if got := ui.Format(ui.MsgExpiry, ui.Vars{Folder: "~/w", Limit: 8 * time.Hour, Reason: ui.ReasonLimit}); !strings.Contains(got, "(8 h limit)") {
		t.Errorf("limit: %q", got)
	}
}

func TestWriterLine(t *testing.T) {
	var b strings.Builder
	w := ui.Writer{W: &b}
	w.Line(ui.MsgUnlockTouch, ui.Vars{})
	w.Line(ui.MsgUnlockCancelled, ui.Vars{Folder: "~/work/acme"})
	want := "precinto: Touch your YubiKey...\nprecinto: unlock cancelled. ~/work/acme stays locked.\n"
	if b.String() != want {
		t.Errorf("Writer.Line wrote %q, want %q", b.String(), want)
	}
}

func TestErrCancelledText(t *testing.T) {
	if got := ui.ErrCancelled.Error(); got != "ui: cancelled" {
		t.Errorf("ErrCancelled = %q", got)
	}
}

// TestFormatShortSIDIsRuneSafe is a regression test: {sid} shows the first
// 8 characters; it used to cut the first 8 bytes, which shows fewer
// characters and can split a multi-byte one into invalid UTF-8.
func TestFormatShortSIDIsRuneSafe(t *testing.T) {
	for sid, want := range map[string]string{
		"0123456789abcdef": "01234567",
		"€€€€€€€€€€":       "€€€€€€€€",
		"ñañañañaña":       "ñañañaña",
		"abc":              "abc",
		"€€€":              "€€€",
	} {
		got := ui.Format(ui.MsgResumeMiss, ui.Vars{SID: sid})
		if !utf8.ValidString(got) || !strings.Contains(got, "session "+want+" is sealed") {
			t.Errorf("SID %q: %q, want the short sid %q", sid, got, want)
		}
	}
}

// FactorName names the first factor usable in the caller's context (CC-40).
func TestFactorName(t *testing.T) {
	for _, c := range []struct {
		kinds []string
		gui   bool
		want  string
	}{
		{[]string{"se", "passphrase"}, true, "Mac password"},
		{[]string{"se", "passphrase"}, false, "precinto passphrase"}, // SSH, tmux, linux
		{[]string{"se"}, false, ""},
		{[]string{"plugin", "passphrase"}, false, "security key"},
		{[]string{"passphrase"}, true, "precinto passphrase"},
		{[]string{"recovery"}, true, ""},
		{nil, true, ""},
		{[]string{"unknown", "passphrase"}, false, "precinto passphrase"},
	} {
		if got := ui.FactorName(c.kinds, c.gui); got != c.want {
			t.Errorf("FactorName(%v, %v) = %q, want %q", c.kinds, c.gui, got, c.want)
		}
	}
	// The prompt with a factor, and its plain variant.
	if got := ui.Format(ui.MsgEnterPrompt, ui.Vars{Folder: "~/w", Factor: "precinto passphrase"}); !strings.Contains(got, "Unlock now with your precinto passphrase?") {
		t.Errorf("C1.prompt = %q", got)
	}
	if got := ui.Format(ui.MsgEnterPromptPlain, ui.Vars{Folder: "~/w"}); strings.Contains(got, "Mac password") || !strings.Contains(got, "Unlock now?") {
		t.Errorf("C1.prompt.plain = %q", got)
	}
}

// CC-38, CC-08, CC-40: the texts the plan made normative, pinned here so a
// drift of the comment and the table together is still caught. The B.* and
// E.* entries keep the texts cmd/precinto printed before they moved (D70).
func TestNormativeTexts(t *testing.T) {
	v := ui.Vars{Folder: "~/work/acme", Factor: "precinto passphrase", File: "~/rec.txt", Command: "precinto init"}
	for id, want := range map[ui.MsgID]string{
		ui.MsgToolStop:         "precinto: ~/work/acme is locked",
		ui.MsgGateFailed:       "precinto: precinto could not check ~/work/acme, so it stays locked. Run precinto unlock in a terminal, then precinto doctor if this repeats.",
		ui.MsgSettingsKept:     "precinto: you passed your own --settings, so precinto did not add its settings that stop Claude compacting or summarizing while you are away. Add idleCompaction: false and awaySummaryEnabled: false to them.",
		ui.MsgPurgeForget:      "precinto: claude purge deletes Claude's own copies of these sessions. precinto keeps its sealed copies (precinto forget deletes them). Run claude purge? [y/N]", // D79: yes runs purge and keeps the capsules, no starts nothing
		ui.MsgUnlockBadSecret:  "precinto: that passphrase or recovery key is not right. ~/work/acme stays locked.",
		ui.MsgOverlayKeysPlain: "Enter   unlock          Ctrl-D   end session and seal it",
		ui.MsgEnterPromptPlain: "precinto: ~/work/acme is locked. Unlock now? [Enter = yes · any other key = skip]",
		ui.MsgEnterPrompt:      "precinto: ~/work/acme is locked. Unlock now with your precinto passphrase? [Enter = yes · any other key = skip]",
		ui.MsgPassphraseNew:    "Choose a precinto passphrase (at least 12 characters), or press Enter to get a generated one:",
		ui.MsgPassphraseAgain:  "Type the passphrase again:",
		ui.MsgPassphraseWeak:   "that passphrase is too weak (at least 12 characters and about 80 bits are needed). Try again.",
		ui.MsgPassphraseDiff:   "the two passphrases differ. Try again.",
		ui.MsgPassphraseGen:    "Your new precinto passphrase. Type it exactly as shown, hyphens included:", // D150: it is typed as shown
		ui.MsgRecoveryHeader:   "Your precinto recovery key. It opens every sealed folder if you lose your other ways to unlock.\nWrite it down and keep it offline. It is shown only once.",
		ui.MsgRecoveryAgain:    "The recovery key is shown only now. Show it again? [Y/n]",
		ui.MsgRecoveryLost:     "WARNING: the recovery key was not confirmed and cannot be shown again. Keep your other ways to unlock safe.",
		ui.MsgRecoveryWritten:  "recovery key written to ~/rec.txt. Move it offline (it opens every sealed folder).",
		ui.MsgRecoveryPrompt:   "precinto recovery key:",
		ui.MsgServiceOffer:     "Seal in the background every 10 minutes (installs a LaunchAgent)? [Y/n]",
		ui.MsgPolicyConfirm:    "Confirm these changes? [y/N]", // the text cmd/precinto asked before it moved (D70)
		ui.MsgNotProtected:     "~/work/acme is not inside a protected folder. Protect it with: precinto protect DIR",
		ui.MsgNotInitialized:   "precinto is not set up yet. Run: precinto init",
		ui.MsgAgentDownAll:     "the precinto agent isn't running, so every folder is locked. Unlock with: precinto unlock",
		ui.MsgNeedTerminal:     "precinto init needs your own terminal (stdin and stdout must be a terminal). Run it yourself in a terminal.",
	} {
		if got := ui.Format(id, v); got != want {
			t.Errorf("%s = %q, want %q", id, got, want)
		}
	}
	if got := ui.ReasonText(ui.ReasonAgent, 0); got != "the precinto agent stopped responding" {
		t.Errorf("ReasonAgent = %q", got)
	}
	// ReasonAgent renders inside the messages that name a reason (D112:
	// the lock screen shows the reason after the folder, under its title).
	if got := ui.Format(ui.MsgOverlayLine, ui.Vars{Folder: "~/work/acme", Reason: ui.ReasonAgent}); got != "~/work/acme · the precinto agent stopped responding" {
		t.Errorf("C4.line with ReasonAgent = %q", got)
	}
}

// UX-13, D112: every lock reason reads as a phrase of its own in the lock
// screen (C4.line) and in C5.ended. The texts are full phrases ("locked by
// you", "not unlocked yet"), so no template may glue them to a word of its
// own such as "after" ("locked after locked by you").
func TestReasonPhrasesFitTheirTemplates(t *testing.T) {
	reasons := []ui.Reason{ui.ReasonIdle, ui.ReasonScreen, ui.ReasonLimit, ui.ReasonManual, ui.ReasonSleep, ui.ReasonStart, ui.ReasonAgent}
	for _, r := range reasons {
		v := ui.Vars{Folder: "~/work/acme", Reason: r, Idle: 15 * time.Minute, Limit: 8 * time.Hour, N: 1, Resume: "claude --continue"}
		d := v.Idle
		if r == ui.ReasonLimit {
			d = v.Limit
		}
		text := ui.ReasonText(r, d)
		if got := ui.Format(ui.MsgOverlayLine, v); got != "~/work/acme · "+text {
			t.Errorf("C4.line(%s) = %q, want the folder and the reason only", r, got)
		}
		c5 := ui.Format(ui.MsgEnded, v)
		if want := "precinto: locked ~/work/acme (" + text + ") and ended 1 session(s). Resume with: claude --continue"; c5 != want {
			t.Errorf("C5.ended(%s) = %q, want %q", r, c5, want)
		}
		for _, id := range []ui.MsgID{ui.MsgOverlayLine, ui.MsgEnded} {
			got := ui.Format(id, v)
			for _, glue := range []string{"after ", "because ", "by "} {
				if strings.Contains(got, glue+text) && !strings.HasPrefix(text, glue) {
					t.Errorf("%s(%s) glues %q to the reason: %q", id, r, glue, got)
				}
			}
			if strings.Count(got, text) != 1 {
				t.Errorf("%s(%s) = %q: the reason must appear once", id, r, got)
			}
		}
	}
}
