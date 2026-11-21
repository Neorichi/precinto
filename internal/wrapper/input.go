package wrapper

// Input classification (UX15, D37, D54): what the user's terminal sends is
// either a human keystroke or paste, or a sequence the terminal generates on
// its own (focus and mouse reports, cursor position and device attribute
// replies, kitty and DECRQM replies, OSC/DCS/APC replies). Only the former
// is activity, and only an unmodified Enter outside a paste counts as Enter.
// Ambiguous shapes are classified as terminal-generated: a missed keystroke
// only makes a folder lock sooner (fail closed), a false one would keep it
// unlocked.

// Kitty keyboard protocol key codes.
const (
	kittyEnter   = 13
	kittyKPEnter = 57414
)

// inputFilter is the stateful classifier the proxy runs over every read
// from the user's terminal: replies split over two reads are still
// recognised, and bracketed paste spans reads.
type inputFilter struct {
	sc    scanner
	paste bool // inside ESC[200~ … ESC[201~
}

func newInputFilter() *inputFilter { return &inputFilter{sc: scanner{input: true}} }

// feed classifies one read.
func (f *inputFilter) feed(b []byte) (human, enter bool) {
	emit := func(t *token) {
		h, e := f.classify(t)
		human = human || h
		enter = enter || e
	}
	f.sc.feed(b, emit)
	f.sc.endChunk(len(b), emit)
	return human, enter
}

// idle forgets a sequence left pending by an earlier read.
func (f *inputFilter) idle() { f.sc.idle(func(*token) {}) }

func (f *inputFilter) classify(t *token) (human, enter bool) {
	switch t.kind {
	case tokText:
		return true, false
	case tokCtl:
		if t.inSeq {
			return false, false
		}
		return true, t.b == '\r' && !f.paste
	case tokEsc:
		// Alt+key or a lone Escape; ESC with intermediates never comes
		// from a keyboard.
		return len(t.inter) == 0, false
	case tokSS:
		return true, t.intro == 'O' && t.b == 'M' && !f.paste // keypad Enter
	case tokCSI:
		return f.classifyCSI(t)
	}
	return false, false // OSC, DCS, APC/PM/SOS replies and malformed input
}

func (f *inputFilter) classifyCSI(t *token) (human, enter bool) {
	if t.x10 {
		return false, false // X10/normal mouse report
	}
	if t.b == '~' && t.prefix == 0 && len(t.inter) == 0 {
		switch t.param(0, 0) {
		case 200:
			f.paste = true
			return false, false
		case 201:
			f.paste = false
			return false, false
		}
	}
	if t.prefix != 0 || len(t.inter) != 0 {
		// '<': SGR mouse; '?', '>', '=': DA, kitty, DECRPM, DSR, XTVERSION
		// replies; intermediates: DECRPM ($y) and friends.
		return false, false
	}
	switch t.b {
	case 'I', 'O':
		if len(t.params) == 0 {
			return false, false // focus in/out
		}
	case 'M', 'm':
		return false, false // urxvt mouse (1015)
	case 'R':
		if t.nparams() >= 2 {
			return false, false // cursor position report
		}
	case 'c', 'n', 't', 'x', 'y':
		return false, false // device attributes, status, window and parameter reports
	case 'u':
		key := t.param(0, 0)
		return true, !f.paste && (key == kittyEnter || key == kittyKPEnter) && kittyPlain(t)
	}
	return true, false
}

// kittyPlain reports whether a kitty key event has no modifiers (other
// than lock keys) and is a press or repeat.
func kittyPlain(t *token) bool {
	mods := t.subParam(1, 0, 1) - 1
	const capsNum = 64 | 128
	if mods < 0 || mods&^capsNum != 0 {
		return false
	}
	ev := t.subParam(1, 1, 1)
	return ev == 1 || ev == 2
}

// overlayKey decodes the keys the lock screen understands: Enter (returned
// as '\r') and Ctrl-D (0x04). Kitty and modifyOtherKeys encodings are
// recognised in case the terminal still uses them.
func overlayKey(t *token) (byte, bool) {
	switch t.kind {
	case tokCtl:
		switch {
		case t.inSeq:
		case t.b == '\r' || t.b == '\n':
			return '\r', true
		case t.b == 0x04:
			return 0x04, true
		}
	case tokSS:
		if t.intro == 'O' && t.b == 'M' {
			return '\r', true
		}
	case tokCSI:
		if t.prefix != 0 || len(t.inter) != 0 || t.x10 {
			return 0, false
		}
		switch t.b {
		case 'u':
			key := t.param(0, 0)
			switch {
			case (key == kittyEnter || key == kittyKPEnter) && kittyPlain(t):
				return '\r', true
			case (key == 'd' || key == 'D') && kittyCtrl(t):
				return 0x04, true
			}
		case '~':
			// modifyOtherKeys: CSI 27 ; modifiers ; key ~
			if t.param(0, 0) == 27 {
				key, mods := t.param(2, 0), t.param(1, 1)-1
				switch {
				case key == kittyEnter && mods == 0:
					return '\r', true
				case (key == 'd' || key == 'D') && mods == 4:
					return 0x04, true
				}
			}
		}
	}
	return 0, false
}

// kittyCtrl reports a press of the key with Ctrl as the only modifier
// (lock keys aside).
func kittyCtrl(t *token) bool {
	mods := t.subParam(1, 0, 1) - 1
	const capsNum = 64 | 128
	ev := t.subParam(1, 1, 1)
	return mods&^capsNum == 4 && (ev == 1 || ev == 2)
}

// lineEditor collects one line typed on the lock screen into a caller-owned
// buffer (locked memory for secrets). Escape sequences are skipped; Enter
// submits; Ctrl-C, Ctrl-\ and Ctrl-D on an empty line cancel; Backspace and
// Ctrl-U edit.
type lineEditor struct {
	buf    []byte
	n      int
	limit  int
	sc     scanner
	done   bool
	cancel bool
}

func newLineEditor(buf []byte, limit int) *lineEditor {
	if limit > len(buf) {
		limit = len(buf)
	}
	return &lineEditor{buf: buf, limit: limit, sc: scanner{input: true}}
}

// feed processes one read; it reports whether the line is finished.
func (e *lineEditor) feed(b []byte) bool {
	emit := func(t *token) {
		if e.done || e.cancel {
			return
		}
		switch t.kind {
		case tokText:
			for _, c := range t.span(b) {
				if e.n < e.limit {
					e.buf[e.n] = c
					e.n++
				}
			}
		case tokCtl:
			if t.inSeq {
				return
			}
			switch t.b {
			case '\r', '\n':
				e.done = true
			case 0x03, 0x1c:
				e.cancel = true
			case 0x04:
				e.cancel = e.n == 0
			case 0x7f, 0x08:
				e.erase(1)
			case 0x15:
				e.erase(-1)
			}
		case tokSS:
			if t.intro == 'O' && t.b == 'M' {
				e.done = true
			}
		}
	}
	e.sc.feed(b, emit)
	e.sc.endChunk(len(b), emit)
	return e.done || e.cancel
}

// erase removes count runes (all with count < 0) from the end.
func (e *lineEditor) erase(count int) {
	for e.n > 0 && count != 0 {
		start := e.n - 1
		for start > 0 && e.n-start < 4 && e.buf[start]&0xc0 == 0x80 {
			start--
		}
		clear(e.buf[start:e.n])
		e.n = start
		count--
	}
}

func (e *lineEditor) wipe() {
	clear(e.buf)
	e.n = 0
}

// humanInput implements HumanInput.
func humanInput(b []byte) (human, enter bool) {
	return newInputFilter().feed(b)
}
