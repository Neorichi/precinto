package wrapper

// Terminal byte-stream scanning shared by the scrollback ring (safe line
// starts), the mode tracker, the human-input filter and the replay filter.
//
// scanner is an incremental tokenizer for the escape-sequence grammar of
// DEC/xterm terminals (a reduced form of Paul Williams' VT500 parser): text
// runs, C0 controls, ESC sequences, SS2/SS3, CSI, OSC and the DCS/SOS/PM/APC
// strings. It keeps its state across feed calls, so a sequence split over
// two reads is still recognised, and it never buffers more than a few dozen
// bytes per sequence (string bodies are only sampled).
//
// In input mode (bytes the terminal sends to the program) it also knows the
// shapes that only occur there: X10 mouse reports (CSI M plus three raw
// bytes), Alt+key (ESC plus a byte) and SS3 keys.

type tokKind uint8

const (
	tokText tokKind = iota + 1 // run of printable bytes (UTF-8 included)
	tokCtl                     // one C0 control byte or DEL
	tokEsc                     // ESC [intermediates] final; final 0 is a lone ESC (input)
	tokSS                      // SS2/SS3: ESC N x, ESC O x
	tokCSI                     // control sequence introducer sequence
	tokOSC                     // operating system command string
	tokDCS                     // device control string
	tokSOS                     // SOS, PM or APC string (intro says which)
	tokBad                     // aborted or malformed sequence
)

type scanState uint8

const (
	stGround   scanState = iota
	stEsc                // after ESC
	stEscInter           // ESC plus intermediates
	stSS                 // ESC N / ESC O: one more byte
	stCSI                // CSI parameters, intermediates, final
	stX10                // CSI M in input mode: three raw mouse bytes
	stStr                // OSC/DCS/SOS/PM/APC body
	stStrEsc             // ESC inside a string body (perhaps ST)
)

const (
	maxParams = 64 // CSI parameter bytes kept (longer: malformed)
	maxInter  = 4  // intermediate bytes kept (more: malformed)
	maxHead   = 64 // string body bytes sampled
)

// token is one scanned element. Slices alias scanner storage and are valid
// only during the emit callback.
type token struct {
	kind tokKind
	// start and end delimit the token in the chunk being fed; start is
	// negative when the token began in an earlier chunk.
	start, end int
	b          byte   // tokCtl: the byte; tokEsc/tokSS/tokCSI: final byte; strings: introducer
	intro      byte   // tokSS: 'N' or 'O'
	prefix     byte   // tokCSI private marker '<', '=', '>', '?' or 0
	inter      []byte // intermediates (tokEsc, tokCSI)
	params     []byte // tokCSI parameter bytes without the prefix
	head       []byte // strings: first bytes of the body
	inSeq      bool   // tokCtl executed in the middle of a sequence
	x10        bool   // tokCSI: X10 mouse report (input)
	bel        bool   // tokOSC terminated by BEL rather than ST
}

type scanner struct {
	input bool // terminal-to-program direction

	st       scanState
	seqStart int // chunk-relative start of the pending sequence
	escAt    int // chunk-relative position of an ESC inside a string body
	strKind  tokKind
	intro    byte
	prefix   byte
	par      [maxParams]byte
	npar     int
	inter    [maxInter]byte
	ninter   int
	head     [maxHead]byte
	nhead    int
	bad      bool
	x10Left  int
	x10Cont  int
	utf8Left int // ground: UTF-8 continuation bytes still expected

	tok token
}

// atGround reports whether the stream is between sequences and between
// UTF-8 runes, where another writer may safely insert bytes.
func (s *scanner) atGround() bool { return s.st == stGround && s.utf8Left == 0 }

// reset forgets any pending sequence.
func (s *scanner) reset() {
	input := s.input
	*s = scanner{input: input}
}

// feed scans b, calling emit for every complete token.
func (s *scanner) feed(b []byte, emit func(*token)) {
	text := -1
	for i := 0; i < len(b); i++ {
		c := b[i]
		if s.st == stGround {
			switch {
			case c == 0x1b:
				text = s.flushText(text, i, emit)
				s.utf8Left = 0
				s.beginSeq(i)
				s.st = stEsc
			case c < 0x20 || c == 0x7f:
				text = s.flushText(text, i, emit)
				s.utf8Left = 0
				s.emitCtl(i, c, false, emit)
			default:
				if text < 0 {
					text = i
				}
				s.trackUTF8(c)
			}
			continue
		}
		if s.step(i, c, emit) {
			i-- // the byte belongs to what follows the aborted sequence
		}
	}
	s.flushText(text, len(b), emit)
	if s.st != stGround {
		s.seqStart -= len(b)
		s.escAt -= len(b)
	}
}

// endChunk resolves, in input mode, what a read that ends inside a sequence
// most likely was: a lone ESC is the Escape key, and an introducer with
// nothing after it is Alt plus that key (terminals write their reports in
// one piece). Anything longer stays pending for the next read.
func (s *scanner) endChunk(n int, emit func(*token)) {
	if !s.input {
		return
	}
	switch s.st {
	case stEsc:
		s.emitEsc(n, 0, emit)
	case stSS:
		s.emitEsc(n, s.intro, emit)
	case stCSI:
		if s.prefix == 0 && s.npar == 0 && s.ninter == 0 && !s.bad {
			s.emitEsc(n, '[', emit)
		}
	case stStr:
		if s.nhead == 0 {
			s.emitEsc(n, s.intro, emit)
		}
	}
}

// idle drops a pending sequence after a pause in the input: a report never
// pauses in the middle, so whatever is pending was not one.
func (s *scanner) idle(emit func(*token)) {
	if s.st != stGround {
		s.emitBad(0, emit)
	}
}

func (s *scanner) trackUTF8(c byte) {
	switch {
	case c < 0x80:
		s.utf8Left = 0
	case c >= 0xc0 && c < 0xe0:
		s.utf8Left = 1
	case c >= 0xe0 && c < 0xf0:
		s.utf8Left = 2
	case c >= 0xf0 && c < 0xf8:
		s.utf8Left = 3
	case c < 0xc0 && s.utf8Left > 0:
		s.utf8Left--
	default:
		s.utf8Left = 0
	}
}

func (s *scanner) flushText(text, i int, emit func(*token)) int {
	if text >= 0 && i > text {
		s.tok = token{kind: tokText, start: text, end: i}
		emit(&s.tok)
	}
	return -1
}

func (s *scanner) beginSeq(i int) {
	s.seqStart = i
	s.prefix, s.npar, s.ninter, s.nhead = 0, 0, 0, 0
	s.bad = false
}

func (s *scanner) emitCtl(i int, c byte, inSeq bool, emit func(*token)) {
	s.tok = token{kind: tokCtl, start: i, end: i + 1, b: c, inSeq: inSeq}
	emit(&s.tok)
}

func (s *scanner) emitEsc(end int, final byte, emit func(*token)) {
	s.tok = token{kind: tokEsc, start: s.seqStart, end: end, b: final, inter: s.inter[:s.ninter]}
	s.st = stGround
	emit(&s.tok)
}

func (s *scanner) emitBad(end int, emit func(*token)) {
	s.tok = token{kind: tokBad, start: s.seqStart, end: end}
	s.st = stGround
	emit(&s.tok)
}

func (s *scanner) emitCSI(end int, final byte, x10 bool, emit func(*token)) {
	s.tok = token{kind: tokCSI, start: s.seqStart, end: end, b: final, prefix: s.prefix,
		inter: s.inter[:s.ninter], params: s.par[:s.npar], x10: x10}
	s.st = stGround
	emit(&s.tok)
}

func (s *scanner) emitStr(end int, bel bool, emit func(*token)) {
	s.tok = token{kind: s.strKind, start: s.seqStart, end: end, b: s.intro, head: s.head[:s.nhead], bel: bel}
	s.st = stGround
	emit(&s.tok)
}

func (s *scanner) addInter(c byte) {
	if s.ninter < maxInter {
		s.inter[s.ninter] = c
		s.ninter++
		return
	}
	s.bad = true
}

func (s *scanner) beginStr(kind tokKind, intro byte) {
	s.strKind, s.intro, s.nhead = kind, intro, 0
	s.st = stStr
}

// step advances a pending sequence by one byte. It returns true when the
// sequence was aborted and c must be scanned again from the new state.
func (s *scanner) step(i int, c byte, emit func(*token)) bool {
	switch s.st {
	case stEsc:
		return s.stepEsc(i, c, emit)
	case stEscInter:
		switch {
		case c >= 0x20 && c <= 0x2f:
			s.addInter(c)
		case c >= 0x30 && c <= 0x7e:
			if s.bad {
				s.emitBad(i+1, emit)
			} else {
				s.emitEsc(i+1, c, emit)
			}
		default:
			return s.abortOn(i, c, emit)
		}
	case stSS:
		if c >= 0x20 && c <= 0x7e {
			s.tok = token{kind: tokSS, start: s.seqStart, end: i + 1, b: c, intro: s.intro}
			s.st = stGround
			emit(&s.tok)
			return false
		}
		if s.input {
			s.emitEsc(i, s.intro, emit) // Alt+O / Alt+N followed by a control
		} else {
			s.emitBad(i, emit)
		}
		return true
	case stCSI:
		switch {
		case c >= 0x30 && c <= 0x3f:
			switch {
			case s.ninter > 0:
				s.bad = true
			case c >= 0x3c:
				if s.npar == 0 && s.prefix == 0 {
					s.prefix = c
				} else {
					s.bad = true
				}
			case s.npar < maxParams:
				s.par[s.npar] = c
				s.npar++
			default:
				s.bad = true
			}
		case c >= 0x20 && c <= 0x2f:
			s.addInter(c)
		case c >= 0x40 && c <= 0x7e:
			switch {
			case s.bad:
				s.emitBad(i+1, emit)
			case s.input && c == 'M' && s.prefix == 0 && s.npar == 0 && s.ninter == 0:
				s.st, s.x10Left, s.x10Cont = stX10, 3, 0
			default:
				s.emitCSI(i+1, c, false, emit)
			}
		default:
			return s.abortOn(i, c, emit)
		}
	case stX10:
		switch {
		case s.x10Cont > 0:
			s.x10Cont--
			if s.x10Cont == 0 {
				s.x10Left--
			}
		case c >= 0xc0 && c < 0xe0:
			s.x10Cont = 1 // mode 1005: a UTF-8 coordinate
		case c >= 0xe0 && c < 0xf0:
			s.x10Cont = 2
		default:
			s.x10Left--
		}
		if s.x10Left <= 0 && s.x10Cont == 0 {
			s.emitCSI(i+1, 'M', true, emit)
		}
	case stStr:
		switch {
		case c == 0x07 && s.strKind == tokOSC:
			s.emitStr(i+1, true, emit)
		case c == 0x1b:
			s.escAt = i
			s.st = stStrEsc
		case c == 0x18 || c == 0x1a:
			s.emitBad(i, emit)
			s.emitCtl(i, c, false, emit)
		default:
			if s.nhead < maxHead {
				s.head[s.nhead] = c
				s.nhead++
			}
		}
	case stStrEsc:
		if c == '\\' {
			s.emitStr(i+1, false, emit)
			return false
		}
		// ESC followed by anything else ends the string; the ESC starts
		// the next sequence.
		s.emitBad(s.escAt, emit)
		s.beginSeq(s.escAt)
		s.st = stEsc
		return true
	}
	return false
}

func (s *scanner) stepEsc(i int, c byte, emit func(*token)) bool {
	switch {
	case c == '[':
		s.prefix, s.npar, s.ninter, s.bad = 0, 0, 0, false
		s.st = stCSI
	case c == ']':
		s.beginStr(tokOSC, c)
	case c == 'P':
		s.beginStr(tokDCS, c)
	case c == 'X' || c == '^' || c == '_':
		s.beginStr(tokSOS, c)
	case c == 'N' || c == 'O':
		s.intro = c
		s.st = stSS
	case c >= 0x20 && c <= 0x2f:
		s.ninter = 0
		s.addInter(c)
		s.st = stEscInter
	case c >= 0x30 && c <= 0x7e:
		s.emitEsc(i+1, c, emit)
	case c == 0x1b:
		if s.input {
			s.emitEsc(i, 0, emit) // Escape pressed twice, or Alt+Escape
		}
		s.beginSeq(i)
		s.st = stEsc
	case c == 0x18 || c == 0x1a:
		s.emitBad(i, emit)
		s.emitCtl(i, c, false, emit)
	case c == 0x7f || c < 0x20:
		if s.input {
			s.emitEsc(i+1, c, emit) // Alt+Backspace, Alt+Enter, Alt+Ctrl-key
		} else if c != 0x7f {
			s.emitCtl(i, c, true, emit)
		}
	default: // a byte >= 0x80 cannot continue an escape sequence
		if s.input {
			s.emitEsc(i, 0, emit)
		} else {
			s.emitBad(i, emit)
		}
		return true
	}
	return false
}

// abortOn handles a byte that is neither a parameter, an intermediate nor a
// final inside ESC-intermediate and CSI sequences: C0 controls execute,
// DEL is ignored, CAN/SUB and ESC abort, anything else is malformed.
func (s *scanner) abortOn(i int, c byte, emit func(*token)) bool {
	switch {
	case c == 0x1b:
		s.emitBad(i, emit)
		s.beginSeq(i)
		s.st = stEsc
	case c == 0x18 || c == 0x1a:
		s.emitBad(i, emit)
		s.emitCtl(i, c, false, emit)
	case c == 0x7f:
	case c < 0x20:
		s.emitCtl(i, c, true, emit)
	default:
		s.emitBad(i, emit)
		return true
	}
	return false
}

// span returns the bytes of t inside chunk b (clamped to the chunk).
func (t *token) span(b []byte) []byte {
	start, end := t.start, t.end
	if start < 0 {
		start = 0
	}
	if end > len(b) {
		end = len(b)
	}
	if end <= start {
		return nil
	}
	return b[start:end]
}

// param returns the idx-th parameter of a CSI token (fields separated by
// ';', sub-parameters after ':' ignored), or def when it is absent or empty.
func (t *token) param(idx, def int) int {
	return t.subParam(idx, 0, def)
}

// subParam returns sub-parameter sub of parameter idx ("13;5:1" has
// parameter 1 = 5 with sub-parameter 1 = 1), or def.
func (t *token) subParam(idx, sub, def int) int {
	field, part := 0, 0
	v, have := 0, false
	for _, c := range t.params {
		switch {
		case c == ';':
			if field == idx && part == sub {
				return valueOr(v, have, def)
			}
			field++
			part = 0
			v, have = 0, false
		case c == ':':
			if field == idx && part == sub {
				return valueOr(v, have, def)
			}
			part++
			v, have = 0, false
		case c >= '0' && c <= '9':
			if v < 1<<24 {
				v = v*10 + int(c-'0')
			}
			have = true
		}
	}
	if field == idx && part == sub {
		return valueOr(v, have, def)
	}
	return def
}

// nparams returns the number of ';'-separated parameters (0 when none).
func (t *token) nparams() int {
	if len(t.params) == 0 {
		return 0
	}
	n := 1
	for _, c := range t.params {
		if c == ';' {
			n++
		}
	}
	return n
}

func valueOr(v int, have bool, def int) int {
	if !have {
		return def
	}
	return v
}

// oscCode returns the numeric command of an OSC body ("52;c;…" → 52), or
// -1 when it does not start with digits followed by ';' or the end.
func oscCode(head []byte) int {
	v, n := 0, 0
	for _, c := range head {
		if c == ';' {
			break
		}
		if c < '0' || c > '9' || n >= 6 {
			return -1
		}
		v = v*10 + int(c-'0')
		n++
	}
	if n == 0 {
		return -1
	}
	return v
}
