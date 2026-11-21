package ui_test

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/precinto/precinto/internal/ui"
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
