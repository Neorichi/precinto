package platform

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"time"
)

// Parsers of the console tools' output. They are OS-independent so the
// fixture tests run everywhere; the tools run only on their OS
// (screen_darwin.go, screen_linux.go).

// consoleSession is one entry of the IOConsoleUsers array of `ioreg -n Root
// -d1`.
type consoleSession struct {
	UID       int
	HasUID    bool
	OnConsole bool
	Locked    bool // CGSSessionScreenIsLocked
}

// ioregConsole is what precinto reads from `ioreg -n Root -d1`.
type ioregConsole struct {
	ConsoleLocked    bool // IOConsoleLocked
	HasConsoleLocked bool
	Sessions         []consoleSession
}

// parseIoregRoot extracts IOConsoleLocked and the IOConsoleUsers sessions.
// Unknown keys and values are skipped; a malformed IOConsoleUsers value
// yields no sessions (callers then report the lock state as unknown).
func parseIoregRoot(out []byte) ioregConsole {
	var c ioregConsole
	if v, ok := ioregTopValue(out, "IOConsoleLocked"); ok {
		switch string(v) {
		case "Yes":
			c.ConsoleLocked, c.HasConsoleLocked = true, true
		case "No":
			c.HasConsoleLocked = true
		}
	}
	if v, ok := ioregTopValue(out, "IOConsoleUsers"); ok {
		p := &plistParser{b: v}
		if arr, ok := p.value(); ok {
			if list, ok := arr.([]any); ok {
				for _, e := range list {
					d, ok := e.(map[string]any)
					if !ok {
						continue
					}
					var s consoleSession
					if n, ok := d["kCGSSessionUserIDKey"].(int64); ok {
						s.UID, s.HasUID = int(n), true
					}
					s.OnConsole = d["kCGSSessionOnConsoleKey"] == true
					s.Locked = d["CGSSessionScreenIsLocked"] == true
					c.Sessions = append(c.Sessions, s)
				}
			}
		}
	}
	return c
}

// screenFor derives the console state of uid: locked if the console is
// locked, if uid's on-console session shows a locked screen, or if uid has
// sessions but none on the console (another user switched in). The state
// is unknown when uid has no console session and the console is not
// locked (headless, SSH-only logins).
func (c ioregConsole) screenFor(uid int) (locked, known, onConsole bool) {
	found, sessionLocked := false, false
	for _, s := range c.Sessions {
		if !s.HasUID || s.UID != uid {
			continue
		}
		found = true
		if s.OnConsole {
			onConsole = true
			sessionLocked = sessionLocked || s.Locked
		}
	}
	switch {
	case c.HasConsoleLocked && c.ConsoleLocked:
		return true, true, onConsole
	case found && !onConsole:
		return true, true, false
	case found:
		return sessionLocked, true, true
	}
	return false, false, false
}

// parseHIDIdle reads the first "HIDIdleTime" = <ns> of ioreg output.
func parseHIDIdle(out []byte) (time.Duration, bool) {
	v, ok := ioregTopValue(out, "HIDIdleTime")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(string(v), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return time.Duration(n), true
}

// ioregTopValue finds `"key" = value` (ioreg's property syntax, one per
// line) and returns the raw value up to the end of the line.
func ioregTopValue(out []byte, key string) ([]byte, bool) {
	needle := []byte(`"` + key + `" = `)
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		i := bytes.Index(line, needle)
		if i < 0 {
			continue
		}
		// Only a property line: the key must be the first token after the
		// tree's indentation (spaces and '|').
		if len(bytes.Trim(line[:i], " \t|")) != 0 {
			continue
		}
		return bytes.TrimSpace(line[i+len(needle):]), true
	}
	return nil, false
}

// plistParser reads ioreg's old-style property syntax: ( a,b ), { "k"=v,…
// }, "strings" with \-escapes, numbers, Yes/No and <hex data>.
type plistParser struct {
	b     []byte
	i     int
	depth int
}

func (p *plistParser) skipSpace() {
	for p.i < len(p.b) && (p.b[p.i] == ' ' || p.b[p.i] == '\t') {
		p.i++
	}
}

// value parses one value; ok=false on malformed input.
func (p *plistParser) value() (any, bool) {
	p.skipSpace()
	if p.i >= len(p.b) || p.depth > 32 {
		return nil, false
	}
	switch c := p.b[p.i]; {
	case c == '(':
		return p.array()
	case c == '{':
		return p.dict()
	case c == '"':
		return p.str()
	case c == '<':
		j := bytes.IndexByte(p.b[p.i:], '>')
		if j < 0 {
			return nil, false
		}
		v := string(p.b[p.i : p.i+j+1])
		p.i += j + 1
		return v, true
	default:
		start := p.i
		for p.i < len(p.b) && !strings.ContainsRune(",)}= \t", rune(p.b[p.i])) {
			p.i++
		}
		tok := string(p.b[start:p.i])
		switch tok {
		case "Yes":
			return true, true
		case "No":
			return false, true
		case "":
			return nil, false
		}
		if n, err := strconv.ParseInt(tok, 10, 64); err == nil {
			return n, true
		}
		return tok, true
	}
}

func (p *plistParser) str() (any, bool) {
	p.i++ // opening quote
	var sb strings.Builder
	for p.i < len(p.b) {
		c := p.b[p.i]
		switch c {
		case '\\':
			if p.i+1 < len(p.b) {
				sb.WriteByte(p.b[p.i+1])
				p.i += 2
				continue
			}
			return nil, false
		case '"':
			p.i++
			return sb.String(), true
		}
		sb.WriteByte(c)
		p.i++
	}
	return nil, false
}

func (p *plistParser) array() (any, bool) {
	p.i++ // (
	p.depth++
	defer func() { p.depth-- }()
	var out []any
	for {
		p.skipSpace()
		if p.i >= len(p.b) {
			return nil, false
		}
		if p.b[p.i] == ')' {
			p.i++
			return out, true
		}
		v, ok := p.value()
		if !ok {
			return nil, false
		}
		out = append(out, v)
		p.skipSpace()
		if p.i < len(p.b) && p.b[p.i] == ',' {
			p.i++
		}
	}
}

func (p *plistParser) dict() (any, bool) {
	p.i++ // {
	p.depth++
	defer func() { p.depth-- }()
	out := map[string]any{}
	for {
		p.skipSpace()
		if p.i >= len(p.b) {
			return nil, false
		}
		if p.b[p.i] == '}' {
			p.i++
			return out, true
		}
		k, ok := p.value()
		if !ok {
			return nil, false
		}
		ks, ok := k.(string)
		if !ok {
			return nil, false
		}
		p.skipSpace()
		if p.i >= len(p.b) || p.b[p.i] != '=' {
			return nil, false
		}
		p.i++
		v, ok := p.value()
		if !ok {
			return nil, false
		}
		out[ks] = v
		p.skipSpace()
		if p.i < len(p.b) && p.b[p.i] == ',' {
			p.i++
		}
	}
}

// parseProps reads `KEY=VALUE` lines (loginctl show-session/show-user).
func parseProps(out []byte) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok && k != "" {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

// screenFromLoginctl converts `loginctl show-session -p LockedHint -p
// IdleHint -p IdleSinceHint` properties. LockedHint is authoritative when
// present. HID idle is known only while the session is idle (IdleHint=yes:
// idle since IdleSinceHint, µs since the epoch); while it is not idle
// logind only says "less than the desktop's idle delay", which cannot prove
// the ≤ 5 s of D37, so the idle time is reported unknown.
func screenFromLoginctl(props map[string]string, now time.Time) ScreenState {
	s := ScreenState{At: now}
	switch props["LockedHint"] {
	case "yes":
		s.Locked, s.LockKnown = true, true
	case "no":
		s.LockKnown = true
	}
	if props["IdleHint"] == "yes" {
		if us, err := strconv.ParseInt(props["IdleSinceHint"], 10, 64); err == nil && us > 0 {
			since := time.UnixMicro(us)
			if d := now.Sub(since); d >= 0 {
				s.HIDIdle, s.IdleKnown = d, true
			}
		}
	}
	return s
}
