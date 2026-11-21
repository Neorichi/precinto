package ui

import (
	"strings"
	"testing"
)

// TestFormatDropsAnEmptySID: a seal summary without a session id (a Codex
// session) renders without an empty slot (D128).
func TestFormatDropsAnEmptySID(t *testing.T) {
	cases := map[MsgID]string{
		MsgSealedLocked: "precinto: sealed this session (10 files · 2 MB).",
		MsgSealFailed:   "precinto: WARNING: couldn't seal this session (no_space). Its files are still readable on disk. Run precinto doctor.",
	}
	for id, want := range cases {
		if got := Format(id, Vars{Files: 10, Bytes: 2 << 20, Cause: "no_space"}); got != want {
			t.Errorf("%s: got %q, want %q", id, got, want)
		}
	}
	if got := Format(MsgSealedOK, Vars{Files: 10, Bytes: 2 << 20, Folder: "~/work/acme"}); !strings.HasPrefix(got, "precinto: sealed this session (10 files · 2 MB). ~/work/acme stays unlocked") {
		t.Errorf("C6.ok with no sid: %q", got)
	}
	if got := Format(MsgSealedLocked, Vars{SID: "0123456789abcdef", Files: 1, Bytes: 1}); got != "precinto: sealed this session (01234567 · 1 files · 1 B)." {
		t.Errorf("C6.sealed with a sid: %q", got)
	}
	for id := range catalog {
		if got := Format(id, Vars{}); strings.Contains(got, "( ·") || strings.Contains(got, "session  ") {
			t.Errorf("%s renders an empty sid slot: %q", id, got)
		}
	}
}
