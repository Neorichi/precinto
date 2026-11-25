package wrapper

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Neorichi/precinto/internal/ui"
)

// Terminal sequences written by the wrapper itself.
const (
	// resetModes is the mode part of the SPEC §15.4 reset sequence.
	resetModes = "\x1b[?1049l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1004l" +
		"\x1b[<99u\x1b[>4;0m\x1b[?25h\x1b[r\x1b[0m"
	clearScreen     = "\x1b[H\x1b[2J"
	clearScrollback = "\x1b[3J"
	// itermClearScrollback is iTerm2's proprietary scrollback clear (D30).
	itermClearScrollback = "\x1b]1337;ClearScrollback\x1b\\"
	enterAltScreen       = "\x1b[?1049h"
	leaveAltScreen       = "\x1b[?1049l"
	hideCursor           = "\x1b[?25l"
	showCursor           = "\x1b[?25h"
	// cancelSeq (CAN) abandons any escape sequence the child left half
	// written, before the wrapper writes its own.
	cancelSeq = "\x18"
	syncOff   = "\x1b[?2026l"
)

// resetSequence implements ResetSequence.
func resetSequence(clear, iterm bool) []byte {
	b := []byte(resetModes)
	if clear {
		b = append(b, clearScreen...)
		b = append(b, clearScrollback...)
		if iterm {
			b = append(b, itermClearScrollback...)
		}
	}
	return b
}

// overlayText is everything the lock screen shows.
type overlayText struct {
	o      Overlay
	status string // last relayed message, prompt or error
	ending bool   // C4.ending instead of the key help
}

// lines renders the overlay's lines (sanitized catalog texts).
func (v overlayText) lines() []string {
	clean := func(s string) string {
		return strings.TrimSpace(strings.ReplaceAll(string(ui.SanitizeTerminal([]byte(s))), "\n", " "))
	}
	var out []string
	out = append(out, clean(ui.Format(ui.MsgOverlayTitle, ui.Vars{})), "")
	folder := clean(v.o.Folder)
	if v.o.Reason != "" {
		// Overlay.Reason is already rendered text; ui.Format passes text
		// that is not a Reason code through unchanged.
		out = append(out, clean(ui.Format(ui.MsgOverlayLine, ui.Vars{Folder: folder, Reason: ui.Reason(v.o.Reason)})))
	} else if folder != "" {
		out = append(out, folder)
	}
	out = append(out, clean(ui.Format(ui.MsgOverlayPaused, ui.Vars{})))
	if v.o.Busy {
		out = append(out, clean(ui.Format(ui.MsgOverlayBusy, ui.Vars{Harness: clean(v.o.Harness)})))
	}
	out = append(out, "")
	switch factor := clean(v.o.Factor); {
	case v.ending:
		out = append(out, clean(ui.Format(ui.MsgOverlayEnding, ui.Vars{})))
	case factor != "":
		out = append(out, clean(ui.Format(ui.MsgOverlayKeys, ui.Vars{Factor: factor})))
	default:
		// No usable factor is known (CC-40): the key help names none.
		out = append(out, clean(ui.Format(ui.MsgOverlayKeysPlain, ui.Vars{})))
	}
	if s := clean(v.status); s != "" {
		out = append(out, "", s)
	}
	return out
}

// render draws the overlay on a cleared screen of cols×rows, each line
// centred. cursorAfter places the cursor after the last line (a prompt);
// otherwise it is hidden.
func (v overlayText) render(cols, rows int, cursorAfter bool) []byte {
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	lines := v.lines()
	top := (rows-len(lines))/2 + 1
	if top < 1 {
		top = 1
	}
	b := []byte(hideCursor + "\x1b[0m" + clearScreen)
	lastRow, lastCol := top, 1
	for i, line := range lines {
		row := top + i
		if row > rows {
			break
		}
		line = truncate(line, cols)
		w := utf8.RuneCountInString(line)
		col := (cols-w)/2 + 1
		if col < 1 {
			col = 1
		}
		if line != "" {
			b = appendPos(b, row, col)
			if i == 0 {
				b = append(b, "\x1b[1m"...)
				b = append(b, line...)
				b = append(b, "\x1b[0m"...)
			} else {
				b = append(b, line...)
			}
		}
		lastRow, lastCol = row, col+w
	}
	if cursorAfter {
		if lastCol > cols {
			lastCol = cols
		}
		b = appendPos(b, lastRow, lastCol)
		b = append(b, showCursor...)
	}
	return b
}

func appendPos(b []byte, row, col int) []byte {
	b = append(b, "\x1b["...)
	b = strconv.AppendInt(b, int64(row), 10)
	b = append(b, ';')
	b = strconv.AppendInt(b, int64(col), 10)
	return append(b, 'H')
}

// truncate shortens s to at most n runes.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// filterReplay returns the replayable part of recorded child output: the
// same bytes without the sequences that would make the terminal answer
// (device attribute, status, cursor and mode queries; DCS, APC; OSC
// queries), act outside the screen (bell, notifications, clipboard,
// printer, window operations) or change the kitty keyboard stack (which
// Modes restores exactly once afterwards). A sequence left unfinished at
// the end is dropped. Controls executed inside a dropped sequence are kept.
func filterReplay(b []byte) []byte {
	out := make([]byte, 0, len(b))
	var s scanner
	var inner []byte // controls executed inside the sequence being scanned
	keep := func(t *token) {
		out = append(out, t.span(b)...)
		inner = inner[:0]
	}
	drop := func() {
		out = append(out, inner...)
		inner = inner[:0]
	}
	s.feed(b, func(t *token) {
		switch t.kind {
		case tokText:
			out = append(out, t.span(b)...)
		case tokCtl:
			switch {
			case t.inSeq:
				inner = append(inner, t.b)
			case t.b == 0x07 || t.b == 0x05: // BEL, ENQ (answerback)
			default:
				out = append(out, t.b)
			}
		case tokEsc:
			if len(t.inter) == 0 && t.b == 'Z' { // DECID: identify
				drop()
				return
			}
			keep(t)
		case tokSS:
			keep(t)
		case tokCSI:
			if replayDropsCSI(t) {
				drop()
				return
			}
			keep(t)
		case tokOSC:
			if replayKeepsOSC(t) {
				keep(t)
				return
			}
			inner = inner[:0]
		default: // DCS, SOS/PM/APC, malformed
			if t.kind == tokBad {
				drop()
				return
			}
			inner = inner[:0]
		}
	})
	return out
}

func replayDropsCSI(t *token) bool {
	switch {
	case t.b == 'c', t.b == 'n', t.b == 't', t.b == 'x', t.b == 'i':
		// DA, DSR/CPR, window ops and reports, DECREQTPARM, media copy
		return true
	case t.b == 'u' && t.prefix != 0:
		// kitty query, push, pop and set
		return true
	case t.b == 'p' && len(t.inter) == 1 && t.inter[0] == '$':
		return true // DECRQM
	case t.b == 'q' && t.prefix == '>':
		return true // XTVERSION
	case t.b == 'S' && t.prefix == '?':
		return true // XTSMGRAPHICS
	}
	return false
}

// replayKeepsOSC keeps titles, working-directory and prompt marks,
// hyperlinks and colour settings; it drops queries, the clipboard,
// notifications, iTerm2/kitty proprietary commands and anything unknown.
func replayKeepsOSC(t *token) bool {
	query := strings.Contains(string(t.head), "?")
	switch oscCode(t.head) {
	case 0, 1, 2, 7, 8, 133, 633:
		return true
	case 4, 10, 11, 12, 17, 19, 104, 110, 111, 112, 117, 119:
		return !query
	}
	return false
}
