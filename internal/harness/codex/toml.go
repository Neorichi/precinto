package codex

// A statement-level TOML 1.0 reader. The codex package may only use the
// standard library (docs/API.md), and seeding a per-root home needs three
// precise operations on the user's config.toml: drop two root-level keys
// (sqlite_home, log_dir), find the [hooks.state."…"] trust entries, and
// carry the per-root home's trust entries over a re-seed. The reader keeps
// the byte span of every statement so edits never reformat the rest of the
// file, and rejects anything it does not understand (the caller then fails
// closed instead of copying a config it could not strip).

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// errTOML is wrapped by every parse error.
var errTOML = errors.New("codex: config.toml does not parse")

type stmtKind int

const (
	stmtTable      stmtKind = iota // [a.b]
	stmtArrayTable                 // [[a.b]]
	stmtKeyVal                     // a.b = value
)

// tomlStmt is one statement with its byte span (from the start of its line
// through its newline) and, for key/values, the decoded value.
type tomlStmt struct {
	kind       stmtKind
	start, end int
	table      []string // enclosing table (key/values) or the header path
	key        []string // key/values: the dotted key
	value      any      // string, bool, map[string]any (inline table), []any, rawScalar
}

// rawScalar is a number, date or time, kept as text.
type rawScalar string

type tomlDoc struct {
	src   string
	stmts []tomlStmt
}

func (d *tomlDoc) errorf(pos int, format string, args ...any) error {
	line := 1 + strings.Count(d.src[:min(pos, len(d.src))], "\n")
	return fmt.Errorf("%w: line %d: %s", errTOML, line, fmt.Sprintf(format, args...))
}

// parseTOML splits src into statements.
func parseTOML(src string) (*tomlDoc, error) {
	if !utf8.ValidString(src) {
		return nil, fmt.Errorf("%w: not UTF-8", errTOML)
	}
	d := &tomlDoc{src: src}
	p := &tomlParser{d: d, s: src}
	var table []string
	for p.i < len(p.s) {
		lineStart := p.i
		p.skipSpace()
		if p.i >= len(p.s) {
			break
		}
		switch c := p.s[p.i]; {
		case c == '\n' || c == '\r':
			if err := p.newline(); err != nil {
				return nil, err
			}
			continue
		case c == '#':
			p.skipComment()
			if err := p.endLine(); err != nil {
				return nil, err
			}
			continue
		case c == '[':
			kind := stmtTable
			p.i++
			if p.i < len(p.s) && p.s[p.i] == '[' {
				kind = stmtArrayTable
				p.i++
			}
			p.skipSpace()
			key, err := p.key()
			if err != nil {
				return nil, err
			}
			p.skipSpace()
			closing := "]"
			if kind == stmtArrayTable {
				closing = "]]"
			}
			if !strings.HasPrefix(p.s[p.i:], closing) {
				return nil, d.errorf(p.i, "unterminated table header")
			}
			p.i += len(closing)
			if err := p.endStatement(); err != nil {
				return nil, err
			}
			table = key
			d.stmts = append(d.stmts, tomlStmt{kind: kind, start: lineStart, end: p.i, table: key})
		default:
			key, err := p.key()
			if err != nil {
				return nil, err
			}
			p.skipSpace()
			if p.i >= len(p.s) || p.s[p.i] != '=' {
				return nil, d.errorf(p.i, "expected '=' after a key")
			}
			p.i++
			p.skipSpace()
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			if err := p.endStatement(); err != nil {
				return nil, err
			}
			d.stmts = append(d.stmts, tomlStmt{kind: stmtKeyVal, start: lineStart, end: p.i, table: table, key: key, value: v})
		}
	}
	return d, nil
}

type tomlParser struct {
	d *tomlDoc
	s string
	i int
}

func (p *tomlParser) skipSpace() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *tomlParser) skipComment() {
	for p.i < len(p.s) && p.s[p.i] != '\n' && p.s[p.i] != '\r' {
		p.i++
	}
}

func (p *tomlParser) newline() error {
	if strings.HasPrefix(p.s[p.i:], "\r\n") {
		p.i += 2
		return nil
	}
	if p.i < len(p.s) && p.s[p.i] == '\n' {
		p.i++
		return nil
	}
	return p.d.errorf(p.i, "bare carriage return")
}

// endLine consumes the newline ending a line (or accepts EOF).
func (p *tomlParser) endLine() error {
	if p.i >= len(p.s) {
		return nil
	}
	return p.newline()
}

// endStatement accepts trailing spaces, a comment, then a newline or EOF.
func (p *tomlParser) endStatement() error {
	p.skipSpace()
	if p.i < len(p.s) && p.s[p.i] == '#' {
		p.skipComment()
	}
	if p.i < len(p.s) && p.s[p.i] != '\n' && p.s[p.i] != '\r' {
		return p.d.errorf(p.i, "unexpected text after a statement")
	}
	return p.endLine()
}

func isBare(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// key parses a (dotted) key.
func (p *tomlParser) key() ([]string, error) {
	var parts []string
	for {
		p.skipSpace()
		if p.i >= len(p.s) {
			return nil, p.d.errorf(p.i, "expected a key")
		}
		var part string
		switch c := p.s[p.i]; {
		case c == '"':
			if strings.HasPrefix(p.s[p.i:], `"""`) {
				return nil, p.d.errorf(p.i, "multi-line string as a key")
			}
			s, err := p.basicString()
			if err != nil {
				return nil, err
			}
			part = s
		case c == '\'':
			if strings.HasPrefix(p.s[p.i:], "'''") {
				return nil, p.d.errorf(p.i, "multi-line string as a key")
			}
			s, err := p.literalString()
			if err != nil {
				return nil, err
			}
			part = s
		case isBare(c):
			j := p.i
			for j < len(p.s) && isBare(p.s[j]) {
				j++
			}
			part = p.s[p.i:j]
			p.i = j
		default:
			return nil, p.d.errorf(p.i, "unexpected %q in a key", c)
		}
		parts = append(parts, part)
		p.skipSpace()
		if p.i < len(p.s) && p.s[p.i] == '.' {
			p.i++
			continue
		}
		return parts, nil
	}
}

// basicString parses "…" with TOML escapes.
func (p *tomlParser) basicString() (string, error) {
	start := p.i
	p.i++ // opening quote
	var b strings.Builder
	for {
		if p.i >= len(p.s) || p.s[p.i] == '\n' || p.s[p.i] == '\r' {
			return "", p.d.errorf(start, "unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c == '\\':
			r, err := p.escape(false)
			if err != nil {
				return "", err
			}
			b.WriteString(r)
		case c < 0x20 && c != '\t' || c == 0x7f:
			return "", p.d.errorf(p.i, "control character in a string")
		default:
			b.WriteByte(c)
			p.i++
		}
	}
}

// escape decodes one escape sequence at p.i (a backslash). In multi-line
// strings a backslash before a newline trims the following whitespace.
func (p *tomlParser) escape(multi bool) (string, error) {
	start := p.i
	p.i++
	if p.i >= len(p.s) {
		return "", p.d.errorf(start, "truncated escape")
	}
	c := p.s[p.i]
	p.i++
	switch c {
	case 'b':
		return "\b", nil
	case 't':
		return "\t", nil
	case 'n':
		return "\n", nil
	case 'f':
		return "\f", nil
	case 'r':
		return "\r", nil
	case 'e':
		return "\x1b", nil
	case '"':
		return `"`, nil
	case '\\':
		return `\`, nil
	case 'u', 'U':
		n := 4
		if c == 'U' {
			n = 8
		}
		if p.i+n > len(p.s) {
			return "", p.d.errorf(start, "truncated unicode escape")
		}
		v, err := strconv.ParseUint(p.s[p.i:p.i+n], 16, 32)
		if err != nil || !utf8.ValidRune(rune(v)) {
			return "", p.d.errorf(start, "bad unicode escape")
		}
		p.i += n
		return string(rune(v)), nil
	}
	if multi {
		// Line-ending backslash: skip whitespace and newlines.
		j := p.i - 1
		for j < len(p.s) && (p.s[j] == ' ' || p.s[j] == '\t') {
			j++
		}
		if j < len(p.s) && (p.s[j] == '\n' || p.s[j] == '\r') {
			for j < len(p.s) && (p.s[j] == ' ' || p.s[j] == '\t' || p.s[j] == '\n' || p.s[j] == '\r') {
				j++
			}
			p.i = j
			return "", nil
		}
	}
	return "", p.d.errorf(start, "unknown escape \\%c", c)
}

func (p *tomlParser) literalString() (string, error) {
	start := p.i
	p.i++
	j := p.i
	for j < len(p.s) && p.s[j] != '\'' {
		if p.s[j] == '\n' || p.s[j] == '\r' {
			return "", p.d.errorf(start, "unterminated literal string")
		}
		j++
	}
	if j >= len(p.s) {
		return "", p.d.errorf(start, "unterminated literal string")
	}
	s := p.s[p.i:j]
	p.i = j + 1
	return s, nil
}

// multiString parses a multi-line basic or literal string: three quote
// characters open and close it, and up to two more quotes may end it.
func (p *tomlParser) multiString(q byte) (string, error) {
	start := p.i
	delim := strings.Repeat(string(q), 3)
	p.i += 3
	if strings.HasPrefix(p.s[p.i:], "\r\n") {
		p.i += 2
	} else if p.i < len(p.s) && p.s[p.i] == '\n' {
		p.i++
	}
	var b strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", p.d.errorf(start, "unterminated multi-line string")
		}
		if strings.HasPrefix(p.s[p.i:], delim) {
			extra := 0
			for p.i+3+extra < len(p.s) && p.s[p.i+3+extra] == q && extra < 2 {
				extra++
			}
			b.WriteString(p.s[p.i : p.i+extra])
			p.i += 3 + extra
			return b.String(), nil
		}
		c := p.s[p.i]
		if q == '"' && c == '\\' {
			r, err := p.escape(true)
			if err != nil {
				return "", err
			}
			b.WriteString(r)
			continue
		}
		b.WriteByte(c)
		p.i++
	}
}

// value parses one value; inline tables and arrays recursively.
func (p *tomlParser) value() (any, error) {
	if p.i >= len(p.s) {
		return nil, p.d.errorf(p.i, "missing value")
	}
	switch c := p.s[p.i]; {
	case strings.HasPrefix(p.s[p.i:], `"""`):
		return p.multiString('"')
	case strings.HasPrefix(p.s[p.i:], "'''"):
		return p.multiString('\'')
	case c == '"':
		return p.basicString()
	case c == '\'':
		return p.literalString()
	case c == '{':
		return p.inlineTable()
	case c == '[':
		return p.array()
	}
	j := p.i
	for j < len(p.s) {
		c := p.s[j]
		if c == ',' || c == ']' || c == '}' || c == '#' || c == '\n' || c == '\r' {
			break
		}
		j++
	}
	text := strings.TrimRight(p.s[p.i:j], " \t")
	if text == "" {
		return nil, p.d.errorf(p.i, "missing value")
	}
	p.i += len(text)
	switch text {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	for _, r := range text {
		if !(r >= '0' && r <= '9' || strings.ContainsRune("+-_.:eExXoObBTtZzaAcCdDfFinf ", r)) {
			return nil, p.d.errorf(p.i, "unknown value %q", text)
		}
	}
	return rawScalar(text), nil
}

// skipBlank skips whitespace, newlines and comments (inside arrays).
func (p *tomlParser) skipBlank() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		case '#':
			p.skipComment()
		default:
			return
		}
	}
}

func (p *tomlParser) array() ([]any, error) {
	start := p.i
	p.i++
	var out []any
	for {
		p.skipBlank()
		if p.i >= len(p.s) {
			return nil, p.d.errorf(start, "unterminated array")
		}
		if p.s[p.i] == ']' {
			p.i++
			return out, nil
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipBlank()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			continue
		}
		p.skipBlank()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return out, nil
		}
		return nil, p.d.errorf(p.i, "expected ',' or ']' in an array")
	}
}

func (p *tomlParser) inlineTable() (map[string]any, error) {
	start := p.i
	p.i++
	out := map[string]any{}
	p.skipBlank()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return out, nil
	}
	for {
		p.skipBlank()
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.i >= len(p.s) || p.s[p.i] != '=' {
			return nil, p.d.errorf(p.i, "expected '=' in an inline table")
		}
		p.i++
		p.skipSpace()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		if err := setPath(out, key, v); err != nil {
			return nil, p.d.errorf(start, "%v", err)
		}
		p.skipBlank()
		if p.i >= len(p.s) {
			return nil, p.d.errorf(start, "unterminated inline table")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return out, nil
		default:
			return nil, p.d.errorf(p.i, "expected ',' or '}' in an inline table")
		}
	}
}

// setPath stores v at the dotted path key of m.
func setPath(m map[string]any, key []string, v any) error {
	for i, k := range key {
		if i == len(key)-1 {
			if _, dup := m[k]; dup {
				return fmt.Errorf("duplicate key %q", k)
			}
			m[k] = v
			return nil
		}
		next, ok := m[k]
		if !ok {
			nm := map[string]any{}
			m[k] = nm
			m = nm
			continue
		}
		nm, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("key %q is not a table", k)
		}
		m = nm
	}
	return nil
}

// hookState is one [hooks.state."<key>"] entry of Codex's config.
type hookState struct {
	trustedHash string
	enabled     *bool
	// stmts are the indices of the statements that define the entry (all
	// of them must go when the entry is replaced).
	stmts []int
	// inline is set when the entry is part of an inline table: it cannot
	// be removed without rewriting that table.
	inline bool
}

// hookStates extracts every hooks.state entry, whatever TOML form defines
// it: [hooks.state."k"] tables, dotted keys below [hooks], [hooks.state]
// or the root, and inline tables.
func (d *tomlDoc) hookStates() map[string]*hookState {
	out := map[string]*hookState{}
	get := func(k string) *hookState {
		if out[k] == nil {
			out[k] = &hookState{}
		}
		return out[k]
	}
	apply := func(k string, fields map[string]any, idx int, inline bool) {
		hs := get(k)
		hs.stmts = appendIdx(hs.stmts, idx)
		hs.inline = hs.inline || inline
		if v, ok := fields["trusted_hash"].(string); ok {
			hs.trustedHash = v
		}
		if v, ok := fields["enabled"].(bool); ok {
			b := v
			hs.enabled = &b
		}
	}
	tableOf := -1 // index of the header of a [hooks.state."k"] table
	for i, st := range d.stmts {
		switch st.kind {
		case stmtTable, stmtArrayTable:
			tableOf = -1
			if st.kind == stmtTable && len(st.table) == 3 && st.table[0] == "hooks" && st.table[1] == "state" {
				tableOf = i
				get(st.table[2]).stmts = appendIdx(get(st.table[2]).stmts, i)
			}
			continue
		}
		full := append(append([]string{}, st.table...), st.key...)
		if len(full) < 2 || full[0] != "hooks" {
			continue
		}
		if full[1] != "state" {
			continue
		}
		switch len(full) {
		case 2: // hooks.state = { "k" = { … } }
			if m, ok := st.value.(map[string]any); ok {
				for k, v := range m {
					if fm, ok := v.(map[string]any); ok {
						apply(k, fm, i, true)
					}
				}
			}
		case 3: // hooks.state."k" = { … }: the statement is exactly the entry
			if fm, ok := st.value.(map[string]any); ok {
				apply(full[2], fm, i, false)
			}
		default: // hooks.state."k".field = v
			apply(full[2], map[string]any{full[3]: st.value}, i, false)
			if tableOf >= 0 && len(st.table) == 3 {
				get(full[2]).stmts = appendIdx(get(full[2]).stmts, tableOf)
			}
		}
	}
	// "hooks = { state = { … } }" at the root.
	for i, st := range d.stmts {
		if st.kind != stmtKeyVal {
			continue
		}
		full := append(append([]string{}, st.table...), st.key...)
		if len(full) == 1 && full[0] == "hooks" {
			if m, ok := st.value.(map[string]any); ok {
				if sm, ok := m["state"].(map[string]any); ok {
					for k, v := range sm {
						if fm, ok := v.(map[string]any); ok {
							apply(k, fm, i, true)
						}
					}
				}
			}
		}
	}
	return out
}

func appendIdx(list []int, i int) []int {
	for _, x := range list {
		if x == i {
			return list
		}
	}
	return append(list, i)
}

// inlineHooks reports whether the document defines hooks or hooks.state as
// an inline table (new [hooks.state."…"] tables cannot be added then).
func (d *tomlDoc) inlineHooks() bool {
	for _, st := range d.stmts {
		if st.kind != stmtKeyVal {
			continue
		}
		full := append(append([]string{}, st.table...), st.key...)
		if _, ok := st.value.(map[string]any); ok && (len(full) == 1 && full[0] == "hooks" || len(full) == 2 && full[0] == "hooks" && full[1] == "state") {
			return true
		}
	}
	return false
}

// without returns the source with the statements at idx removed (whole
// lines, comments of other lines untouched).
func (d *tomlDoc) without(idx map[int]bool) string {
	var b strings.Builder
	last := 0
	for i, st := range d.stmts {
		if !idx[i] {
			continue
		}
		if st.start < last { // already removed with its table
			last = max(last, st.end)
			continue
		}
		b.WriteString(d.src[last:st.start])
		last = st.end
		// A removed table takes its key/values with it.
		if st.kind == stmtTable || st.kind == stmtArrayTable {
			for j := i + 1; j < len(d.stmts) && d.stmts[j].kind == stmtKeyVal; j++ {
				last = d.stmts[j].end
			}
		}
	}
	b.WriteString(d.src[last:])
	return b.String()
}

// tomlQuote renders s as a TOML basic string.
func tomlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
