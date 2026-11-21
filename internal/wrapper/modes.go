package wrapper

import "strconv"

// decDefault lists the DEC private modes the tracker follows, with the value
// a terminal has after a reset. The alternate-screen modes (47, 1047, 1049)
// are tracked separately (Modes.alt).
var decDefault = map[int]bool{
	1:    false, // DECCKM application cursor keys
	7:    true,  // DECAWM autowrap
	9:    false, // X10 mouse
	25:   true,  // DECTCEM cursor visible
	1000: false, // mouse: press/release
	1001: false, // mouse: highlight
	1002: false, // mouse: button motion
	1003: false, // mouse: any motion
	1004: false, // focus in/out reports
	1005: false, // mouse: UTF-8 coordinates
	1006: false, // mouse: SGR coordinates
	1007: false, // alternate scroll
	1015: false, // mouse: urxvt coordinates
	1016: false, // mouse: SGR pixel coordinates
	2004: false, // bracketed paste
	2026: false, // synchronized output: only ever turned off (Reset, after a replay)
}

// Emission orders: coordinate encodings go on before mouse tracking and off
// after it, so no report is ever sent in the wrong encoding.
var (
	restoreOrder = []int{1, 7, 25, 1004, 2004, 1005, 1006, 1015, 1016, 1007, 9, 1000, 1001, 1002, 1003}
	resetOrder   = []int{9, 1000, 1001, 1002, 1003, 1005, 1006, 1015, 1016, 1007, 1004, 2004, 1, 7, 25}
)

// maxKittyStack bounds the kitty keyboard flag stack the tracker keeps.
const maxKittyStack = 32

// kittyClear pops every kitty keyboard flag entry and zeroes the flags.
const kittyClear = "\x1b[<99u\x1b[=0;1u"

func isAltScreen(mode int) bool { return mode == 47 || mode == 1047 || mode == 1049 }

// kittyStack models the kitty keyboard protocol flags of one screen: cur is
// the active flags, saved the entries a pop returns to (oldest first).
type kittyStack struct {
	cur   int
	saved []int
}

func (k *kittyStack) empty() bool { return k.cur == 0 && len(k.saved) == 0 }

func (k *kittyStack) push(flags int) {
	if len(k.saved) >= maxKittyStack {
		k.saved = append(k.saved[:0], k.saved[1:]...)
	}
	k.saved = append(k.saved, k.cur)
	k.cur = flags
}

func (k *kittyStack) pop(n int) {
	if n < 1 {
		n = 1
	}
	for ; n > 0; n-- {
		if len(k.saved) == 0 {
			k.cur = 0 // popping the last entry resets every flag
			return
		}
		k.cur = k.saved[len(k.saved)-1]
		k.saved = k.saved[:len(k.saved)-1]
	}
}

func (k *kittyStack) set(flags, mode int) {
	switch mode {
	case 2:
		k.cur |= flags
	case 3:
		k.cur &^= flags
	default:
		k.cur = flags
	}
}

// restore returns the sequence that rebuilds k on a terminal whose stack is
// empty.
func (k *kittyStack) restore(b []byte) []byte {
	if k.empty() {
		return b
	}
	if len(k.saved) == 0 {
		return appendCSI(b, "=", k.cur, ";1u")
	}
	if k.saved[0] != 0 {
		b = appendCSI(b, "=", k.saved[0], ";1u")
	}
	for _, v := range k.saved[1:] {
		b = appendCSI(b, ">", v, "u")
	}
	return appendCSI(b, ">", k.cur, "u")
}

func appendCSI(b []byte, prefix string, v int, tail string) []byte {
	b = append(b, "\x1b["...)
	b = append(b, prefix...)
	b = strconv.AppendInt(b, int64(v), 10)
	return append(b, tail...)
}

func appendDEC(b []byte, mode int, on bool) []byte {
	b = append(b, "\x1b[?"...)
	b = strconv.AppendInt(b, int64(mode), 10)
	if on {
		return append(b, 'h')
	}
	return append(b, 'l')
}

// atGround reports whether the child's output stream is between sequences.
func (m *Modes) atGround() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sc.atGround()
}

// altActive reports whether the child uses the alternate screen.
func (m *Modes) altActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.alt != 0
}

// restoreFromState is restoreFrom under m's lock.
func (m *Modes) restoreFromState(cur *Modes) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreFrom(cur)
}

func (m *Modes) init() {
	if m.set == nil {
		m.set = map[int]bool{}
	}
}

func (m *Modes) feed(b []byte) {
	m.init()
	m.sc.feed(b, m.apply)
}

func (m *Modes) apply(t *token) {
	switch t.kind {
	case tokCSI:
		if len(t.inter) > 0 {
			if t.prefix == 0 && len(t.inter) == 1 && t.inter[0] == '!' && t.b == 'p' {
				m.softReset() // DECSTR
			}
			return
		}
		switch {
		case t.prefix == '?' && (t.b == 'h' || t.b == 'l'):
			on := t.b == 'h'
			for i, n := 0, t.nparams(); i < n; i++ {
				v := t.param(i, -1)
				if isAltScreen(v) {
					m.setAlt(v, on)
				} else if _, ok := decDefault[v]; ok {
					m.set[v] = on
				}
			}
		case t.prefix == '>' && t.b == 'u':
			m.kitty[m.screen()].push(t.param(0, 0))
		case t.prefix == '<' && t.b == 'u':
			m.kitty[m.screen()].pop(t.param(0, 1))
		case t.prefix == '=' && t.b == 'u':
			m.kitty[m.screen()].set(t.param(0, 0), t.param(1, 1))
		case t.prefix == '>' && t.b == 'm':
			// XTMODKEYS: resource 4 is modifyOtherKeys; no value (or no
			// resource at all) resets it.
			if t.nparams() == 0 || t.param(0, -1) == 4 {
				m.mok = t.param(1, 0)
			}
		}
	case tokEsc:
		if len(t.inter) != 0 {
			return
		}
		switch t.b {
		case '=':
			m.keypad = true
		case '>':
			m.keypad = false
		case 'c': // RIS
			m.hardReset()
		}
	}
}

func (m *Modes) screen() int {
	if m.alt != 0 {
		return 1
	}
	return 0
}

func (m *Modes) setAlt(mode int, on bool) {
	if on {
		if m.alt == 0 {
			m.altSwitches++
			m.kitty[1] = kittyStack{} // a fresh alternate screen starts with no flags
		}
		m.alt = mode
		return
	}
	if m.alt != 0 {
		m.altSwitches++
	}
	m.alt = 0
}

func (m *Modes) softReset() {
	delete(m.set, 1)
	delete(m.set, 25)
	m.keypad = false
}

func (m *Modes) hardReset() {
	clear(m.set)
	m.keypad = false
	m.mok = 0
	m.kitty = [2]kittyStack{}
	if m.alt != 0 {
		m.altSwitches++
	}
	m.alt = 0
}

// state returns the tracked value of a DEC mode (its default when untouched).
func (m *Modes) state(mode int) bool {
	if on, ok := m.set[mode]; ok {
		return on
	}
	return decDefault[mode]
}

func (m *Modes) resetSeq() []byte {
	var b []byte
	if m.state(2026) {
		b = appendDEC(b, 2026, false)
	}
	if m.alt != 0 {
		if !m.kitty[1].empty() {
			b = append(b, kittyClear...)
		}
		b = appendDEC(b, m.alt, false)
	}
	if !m.kitty[0].empty() {
		b = append(b, kittyClear...)
	}
	for _, v := range resetOrder {
		if on := m.state(v); on != decDefault[v] {
			b = appendDEC(b, v, decDefault[v])
		}
	}
	if m.mok != 0 {
		b = append(b, "\x1b[>4;0m"...)
	}
	if m.keypad {
		b = append(b, "\x1b>"...)
	}
	return b
}

// restoreFrom returns the sequence that takes a terminal in state cur (as
// tracked from what was written to it since a reset, with no kitty flags)
// to the state m tracks.
func (m *Modes) restoreFrom(cur *Modes) []byte {
	var b []byte
	switch {
	case m.alt != 0 && cur.alt != 0:
		if !m.kitty[0].empty() {
			// The main screen's flags can only be pushed from the main
			// screen; re-entering clears the alternate screen, which the
			// forced repaint redraws.
			b = appendDEC(b, cur.alt, false)
			b = m.kitty[0].restore(b)
			b = appendDEC(b, m.alt, true)
		}
	case m.alt != 0:
		b = m.kitty[0].restore(b)
		b = appendDEC(b, m.alt, true)
	case cur.alt != 0:
		b = appendDEC(b, cur.alt, false)
		b = m.kitty[0].restore(b)
	default:
		b = m.kitty[0].restore(b)
	}
	if m.alt != 0 {
		b = m.kitty[1].restore(b)
	}
	for _, v := range restoreOrder {
		if want := m.state(v); want != cur.state(v) {
			b = appendDEC(b, v, want)
		}
	}
	if cur.state(2026) {
		b = appendDEC(b, 2026, false)
	}
	if m.mok != cur.mok {
		b = appendCSI(b, ">4;", m.mok, "m")
	}
	if m.keypad != cur.keypad {
		if m.keypad {
			b = append(b, "\x1b="...)
		} else {
			b = append(b, "\x1b>"...)
		}
	}
	return b
}
