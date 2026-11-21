package ui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/awnumar/memguard"
	"golang.org/x/term"
)

const (
	devTTY = "/dev/tty"

	// pollInterval bounds how long a prompt waits for input before it
	// checks for Close and signals again.
	pollInterval = 100 * time.Millisecond

	maxSecret   = 4096 // bytes Secret keeps
	maxLine     = 1024 // bytes ReadLine, YesNo and Confirm keep
	maxTypeBack = 256  // bytes ShowSecretScreen keeps per attempt
	readRoom    = 256  // read window kept free beyond the accepted bytes
	maxDrain    = 1024 // reads spent discarding pending input
	yesNoTries  = 3    // unrecognized YesNo answers before ErrCancelled
)

var (
	errNotOpen     = errors.New("ui: terminal not open")
	errClosed      = fmt.Errorf("ui: terminal closed: %w", os.ErrClosed)
	errNotTerminal = errors.New("ui: not a terminal")
	errNoLockedMem = errors.New("ui: cannot allocate locked memory")
)

// termModes switches a terminal between the mode it was in and the raw mode
// prompts read in. It is a seam: tests over pipes use a no-op version.
type termModes interface {
	// raw puts fd in raw mode and returns a function that restores the
	// mode in force before.
	raw(fd int) (restore func() error, err error)
	// reraw re-applies raw mode after the process was stopped and
	// continued (SIGCONT): the shell may have changed the mode meanwhile.
	reraw(fd int) error
	// terminal reports whether fd is a terminal.
	terminal(fd int) bool
}

// xtermModes implements termModes with golang.org/x/term.
type xtermModes struct{}

func (xtermModes) raw(fd int) (func() error, error) {
	st, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	return func() error { return term.Restore(fd, st) }, nil
}

func (xtermModes) reraw(fd int) error {
	_, err := term.MakeRaw(fd)
	return err
}

func (xtermModes) terminal(fd int) bool { return term.IsTerminal(fd) }

// openTTY implements OpenTTY on an explicit device path.
func openTTY(path string) (*TTY, error) {
	f, err := openTerminalFile(path)
	if err != nil {
		return nil, fmt.Errorf("ui: open terminal: %w", err)
	}
	if !isTerminal(f) {
		_ = f.Close()
		return nil, fmt.Errorf("ui: open terminal %s: %w", path, errNotTerminal)
	}
	return &TTY{in: f, out: f, owned: true}, nil
}

// isTerminal reports whether f is a terminal, without switching f to
// blocking mode (File.Fd would).
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	ok := false
	_ = control(f, func(fd int) { ok = term.IsTerminal(fd) })
	return ok
}

// control runs fn with the descriptor of f, which stays valid meanwhile.
func control(f *os.File, fn func(fd int)) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Control(func(fd uintptr) { fn(int(fd)) })
}

func (t *TTY) termModes() termModes {
	if t.modes == nil {
		return xtermModes{}
	}
	return t.modes
}

// usable reports why t cannot be used. Callers hold t.mu.
func (t *TTY) usable() error {
	switch {
	case t.closed:
		return errClosed
	case t.in == nil || t.out == nil:
		return errNotOpen
	}
	return nil
}

// write writes b completely. Callers hold t.mu.
func (t *TTY) write(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if _, err := t.out.Write(b); err != nil {
		return fmt.Errorf("ui: write terminal: %w", err)
	}
	return nil
}

func (t *TTY) writeString(s string) error { return t.write([]byte(s)) }

// promptText sanitizes a prompt and makes it end with one space.
func promptText(prompt string) string {
	s := strings.TrimRight(string(SanitizeTerminal([]byte(prompt))), " \t\n")
	if s == "" {
		return ""
	}
	return s + " "
}

// rawText translates line feeds for output written while OPOST is off.
func rawText(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

// session is one public prompt call: it holds t.mu (taken by the caller),
// watches the signals that cancel a prompt and knows whether the terminal is
// currently in raw mode.
type session struct {
	t         *TTY
	modes     termModes
	fd        int
	sigc      chan os.Signal
	raw       bool // the terminal is in raw mode (reraw on SIGCONT)
	cancelled bool // a cancelling signal arrived
}

// begin starts a session. Callers hold t.mu and checked t.usable.
func (t *TTY) begin() (*session, error) {
	s := &session{t: t, modes: t.termModes(), fd: -1}
	if err := control(t.in, func(fd int) { s.fd = fd }); err != nil {
		return nil, fmt.Errorf("ui: terminal descriptor: %w", err)
	}
	if sigs := watchedSignals(); len(sigs) > 0 {
		s.sigc = make(chan os.Signal, 8)
		signal.Notify(s.sigc, sigs...)
	}
	return s, nil
}

// end stops watching signals. It reports whether a cancelling signal
// arrived during the session, including one not yet seen by poll.
func (s *session) end() (cancelled bool) {
	if s.sigc != nil {
		signal.Stop(s.sigc)
		for {
			select {
			case sig := <-s.sigc:
				if !isContinueSignal(sig) {
					s.cancelled = true
				}
				continue
			default:
			}
			break
		}
	}
	return s.cancelled
}

// poll returns ErrCancelled once Close was called or a cancelling signal
// arrived; a SIGCONT re-applies raw mode.
func (s *session) poll() error {
	if s.t.abort.Load() {
		s.cancelled = true
	}
	for s.sigc != nil && !s.cancelled {
		select {
		case sig := <-s.sigc:
			if !isContinueSignal(sig) {
				s.cancelled = true
				continue
			}
			if s.raw {
				if err := s.modes.reraw(s.fd); err != nil {
					return fmt.Errorf("ui: terminal mode: %w", err)
				}
			}
			continue
		default:
		}
		break
	}
	if s.cancelled {
		return ErrCancelled
	}
	return nil
}

// readOptions configures one line read.
type readOptions struct {
	prompt string // written once raw mode is on (and pending input is gone)
	limit  int    // bytes kept; extra input is dropped
	echo   bool   // echo accepted characters (visible, non-secret lines)
	// redraw, when set, shows the line by rewriting redraw followed by the
	// accepted bytes straight from buf after every read, so characters of
	// a secret typed back visibly never leave buf.
	redraw  string
	discard bool // discard pending input before and after (secrets)
}

// readLine switches to raw mode, writes the prompt and reads one line into
// buf (len(buf) must exceed o.limit). It returns the number of bytes kept at
// the start of buf; every other byte of buf it touched is wiped. Ctrl-C,
// Ctrl-\, Ctrl-D on an empty line, a cancelling signal and Close return
// ErrCancelled. The terminal mode in force before is restored on every
// return path.
func (s *session) readLine(buf []byte, o readOptions) (n int, err error) {
	if err := s.poll(); err != nil {
		return 0, err
	}
	restore, err := s.modes.raw(s.fd)
	if err != nil {
		return 0, fmt.Errorf("ui: terminal mode: %w", err)
	}
	s.raw = true
	defer func() {
		s.raw = false
		if rerr := restore(); rerr != nil && err == nil {
			wipe(buf[:n])
			n, err = 0, fmt.Errorf("ui: restore terminal: %w", rerr)
		}
	}()
	if o.discard {
		if err := s.drain(buf); err != nil {
			return 0, err
		}
	}
	if err := s.t.writeString(rawText(o.prompt)); err != nil {
		return 0, err
	}
	ed := editor{buf: buf, limit: o.limit, echo: o.echo}
	defer func() {
		if err != nil {
			ed.wipe()
		}
	}()
	for {
		if err := s.poll(); err != nil {
			_ = s.t.writeString("\r\n")
			return 0, err
		}
		ready, err := s.t.waitInput(pollInterval)
		if err != nil {
			return 0, fmt.Errorf("ui: read terminal: %w", err)
		}
		if !ready {
			ed.esc = escNone // a lone Escape key, not a sequence
			continue
		}
		k, eof, err := s.t.readInput(buf[ed.n:])
		switch {
		case err != nil:
			return 0, fmt.Errorf("ui: read terminal: %w", err)
		case eof:
			return 0, fmt.Errorf("ui: read terminal: %w", errEOF)
		case k == 0:
			continue
		}
		done, cancel := ed.feed(k)
		if err := s.t.write(ed.takeEcho()); err != nil {
			return 0, err
		}
		if o.redraw != "" {
			if err := s.t.writeString(o.redraw); err != nil {
				return 0, err
			}
			if err := s.t.write(buf[:ed.n]); err != nil {
				return 0, err
			}
		}
		if cancel {
			_ = s.t.writeString("\r\n")
			return 0, ErrCancelled
		}
		if done {
			if err := s.t.writeString("\r\n"); err != nil {
				return 0, err
			}
			if o.discard {
				if err := s.drain(buf[ed.n:]); err != nil {
					return 0, err
				}
			}
			return ed.n, nil
		}
	}
}

// drain reads and wipes pending input (typeahead) into scratch.
func (s *session) drain(scratch []byte) error {
	if len(scratch) == 0 {
		return nil
	}
	for i := 0; i < maxDrain; i++ {
		ready, err := s.t.waitInput(0)
		if err != nil {
			return fmt.Errorf("ui: read terminal: %w", err)
		}
		if !ready {
			return nil
		}
		k, eof, err := s.t.readInput(scratch)
		wipe(scratch[:k])
		switch {
		case err != nil:
			return fmt.Errorf("ui: read terminal: %w", err)
		case eof:
			return fmt.Errorf("ui: read terminal: %w", errEOF)
		}
	}
	return nil
}

// errEOF reports a terminal that hung up while a prompt was reading.
var errEOF = fmt.Errorf("terminal hung up: %w", io.EOF)

// escState tracks an escape sequence (arrow keys, bracketed paste markers)
// so that its bytes never become part of the line.
type escState uint8

const (
	escNone  escState = iota
	escStart          // after ESC
	escCSI            // ESC [ parameters, until a final byte 0x40–0x7E
	escSS3            // ESC O, one more byte
)

func (s escState) next(c byte) escState {
	switch s {
	case escStart:
		switch c {
		case '[':
			return escCSI
		case 'O':
			return escSS3
		case 0x1b:
			return escStart
		}
		return escNone // Alt+key: both bytes dropped
	case escCSI:
		if c >= 0x20 && c <= 0x3f {
			return escCSI
		}
		return escNone // final byte (or a malformed one) ends it
	}
	return escNone
}

// editor is a minimal line editor over a caller-owned buffer: accepted bytes
// are buf[:n]; read bytes land at buf[n:] and are compacted in place, so a
// secret never leaves buf (locked memory for Secret).
type editor struct {
	buf   []byte
	limit int
	n     int
	echo  bool
	esc   escState
	out   []byte // pending echo (visible prompts only)
}

// feed processes the k bytes just read into buf[n:n+k].
func (e *editor) feed(k int) (done, cancel bool) {
	end := e.n + k
	w := e.n
	for i := e.n; i < end && !done && !cancel; i++ {
		c := e.buf[i]
		if e.esc != escNone {
			if c >= 0x20 && c != 0x7f {
				e.esc = e.esc.next(c)
				continue
			}
			// A control key always keeps its meaning.
			e.esc = escNone
		}
		switch {
		case c == '\r' || c == '\n':
			done = true
		case c == 0x03 || c == 0x1c: // Ctrl-C, Ctrl-\ (ISIG is off)
			cancel = true
		case c == 0x04: // Ctrl-D cancels an empty line
			cancel = w == 0
		case c == 0x7f || c == 0x08: // Backspace
			w = e.erase(w, 1)
		case c == 0x15: // Ctrl-U erases the line
			w = e.erase(w, -1)
		case c == 0x1b:
			e.esc = escStart
		case c < 0x20:
			// Other control characters are ignored.
		case w < e.limit:
			e.buf[w] = c
			w++
			if e.echo {
				e.out = append(e.out, c)
			}
		}
	}
	wipe(e.buf[w:end])
	e.n = w
	return done, cancel
}

// erase removes up to count runes (all with count < 0) before w and returns
// the new end of the accepted bytes.
func (e *editor) erase(w, count int) int {
	for w > 0 && count != 0 {
		start := w - 1
		for start > 0 && w-start < utf8.UTFMax && !utf8.RuneStart(e.buf[start]) {
			start--
		}
		wipe(e.buf[start:w])
		w = start
		count--
		if e.echo {
			e.out = append(e.out, "\b \b"...)
		}
	}
	return w
}

// takeEcho returns the pending echo output and resets it.
func (e *editor) takeEcho() []byte {
	out := e.out
	e.out = nil
	return out
}

// wipe clears every byte the editor touched.
func (e *editor) wipe() {
	wipe(e.buf[:e.n])
	e.n = 0
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// readVisible reads one echoed line after prompt. Callers hold t.mu.
func (t *TTY) readVisible(s *session, prompt string) (string, error) {
	buf := make([]byte, maxLine+readRoom)
	n, err := s.readLine(buf, readOptions{prompt: prompt, limit: maxLine, echo: true})
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// visiblePrompt runs one visible-line prompt as a whole public call.
func (t *TTY) visiblePrompt(prompt string) (string, error) {
	if t == nil {
		return "", errNotOpen
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.usable(); err != nil {
		return "", err
	}
	s, err := t.begin()
	if err != nil {
		return "", err
	}
	defer s.end()
	line, err := t.readVisible(s, prompt)
	if s.end() && err == nil {
		return "", ErrCancelled
	}
	return line, err
}

// secret implements Secret. Callers hold t.mu.
func (t *TTY) secret(prompt string) (*memguard.LockedBuffer, error) {
	work := memguard.NewBuffer(maxSecret + readRoom)
	if work.Size() == 0 {
		return nil, errNoLockedMem
	}
	defer work.Destroy()
	s, err := t.begin()
	if err != nil {
		return nil, err
	}
	defer s.end()
	n, err := s.readLine(work.Bytes(), readOptions{prompt: promptText(prompt), limit: maxSecret, discard: true})
	if s.end() && err == nil {
		err = ErrCancelled
	}
	if err != nil {
		return nil, err
	}
	// The result is an exact-size, read-only locked buffer; NewBufferFromBytes
	// wipes the bytes of work it copies from.
	return memguard.NewBufferFromBytes(work.Bytes()[:n]), nil
}

// yesNoHint returns the prompt with its [Y/n] or [y/N] hint and the default
// the user sees. A prompt that already ends with a hint (the catalog texts
// do) keeps it, and that hint decides the default.
func yesNoHint(prompt string, def bool) (string, bool) {
	p := strings.TrimRight(string(SanitizeTerminal([]byte(prompt))), " \t\n")
	switch {
	case strings.HasSuffix(p, "[Y/n]"):
		return p + " ", true
	case strings.HasSuffix(p, "[y/N]"):
		return p + " ", false
	}
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	if p == "" {
		return hint + " ", def
	}
	return p + " " + hint + " ", def
}

// confirmText renders a Confirm prompt and returns the word that means yes.
func confirmText(prompt, yes, no string) (text, yesWord string, ambiguous bool) {
	clean := func(s, def string) string {
		s = strings.TrimSpace(string(SanitizeTerminal([]byte(s))))
		s = strings.Join(strings.Fields(s), " ")
		if s == "" {
			return def
		}
		return s
	}
	yesWord, noWord := clean(yes, "yes"), clean(no, "no")
	p := strings.TrimRight(string(SanitizeTerminal([]byte(prompt))), " \t\n")
	hint := "[" + yesWord + "/" + noWord + "]"
	if p != "" {
		hint = p + " " + hint
	}
	return hint + " ", yesWord, strings.EqualFold(yesWord, noWord)
}

// oneLine renders an informational message: sanitized, one trailing newline.
func oneLine(msg string) []byte {
	b := SanitizeTerminal([]byte(msg))
	for len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return append(b, '\n')
}
