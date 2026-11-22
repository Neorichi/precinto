package ui

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/awnumar/memguard"
	"golang.org/x/term"
)

// Terminal sequences of the recovery-key screen (SPEC §4.7, D7).
const (
	seqEnterAlt = "\x1b[?1049h\x1b[H\x1b[2J" // alternate screen, cleared
	// Clear the screen and the scrollback (xterm ED 3; iTerm2 OSC 1337
	// ClearScrollback ST), then leave the alternate screen.
	seqClearLeave = "\x1b[H\x1b[2J\x1b[3J\x1b]1337;ClearScrollback\x1b\\\x1b[?1049l"
	// seqRetry goes back from below the answered prompt to the line above
	// it (the instruction), erased, for the mismatch line (UX-07); the
	// prompt follows on the next line, erased too.
	seqRetry  = "\x1b[2A\r\x1b[2K"
	seqRedraw = "\r\x1b[2K" // the prompt line, erased

	typeBackPrompt = "> "
	groupSize      = 6
	secretIndent   = "  "
)

var (
	errConfirmLast = errors.New("ui: secret screen: confirmLast must be at least 1")
	errNoSecret    = errors.New("ui: secret screen: the secret is missing, empty or not printable")
)

// showSecretScreen implements ShowSecretScreen. Nothing is written unless the
// arguments are valid and the output is a terminal; once the alternate
// screen is entered, every return path clears it and the scrollback and
// leaves it. The caller keeps ownership of secret; every copy made here
// (the grouped display text, the expected tail, the typed answer) lives in
// locked memory and is destroyed before returning.
func (t *TTY) showSecretScreen(header []string, secret *memguard.LockedBuffer, confirmLast int) (err error) {
	if t == nil {
		return errNotOpen
	}
	if confirmLast < 1 {
		return errConfirmLast
	}
	if secret == nil || !secret.IsAlive() || !displayableSecret(secret.Bytes()) {
		return errNoSecret
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.usable(); err != nil {
		return err
	}
	outFd := -1
	if err := control(t.out, func(fd int) { outFd = fd }); err != nil || !t.termModes().terminal(outFd) {
		return fmt.Errorf("ui: secret screen: %w", errNotTerminal)
	}
	width := 80
	if w, _, err := term.GetSize(outFd); err == nil && w >= 20 {
		width = w
	}

	sb := secret.Bytes()
	body, err := groupedSecret(sb, width)
	if err != nil {
		return err
	}
	defer body.Destroy()
	want, err := secretTail(sb, confirmLast)
	if err != nil {
		return err
	}
	defer want.Destroy()
	typed := memguard.NewBuffer(maxTypeBack + readRoom)
	if typed.Size() == 0 {
		return errNoLockedMem
	}
	defer typed.Destroy()

	s, err := t.begin()
	if err != nil {
		return err
	}
	defer s.end()

	if err := t.writeString(seqEnterAlt); err != nil {
		return err
	}
	defer func() {
		if werr := t.writeString(seqClearLeave); werr != nil && err == nil {
			err = werr
		}
	}()
	var head strings.Builder
	for _, line := range header {
		head.Write(SanitizeTerminal([]byte(line)))
		head.WriteByte('\n')
	}
	head.WriteByte('\n')
	if err := t.writeString(head.String()); err != nil {
		return err
	}
	if err := t.write(body.Bytes()); err != nil {
		return err
	}
	if err := t.writeString("\n"); err != nil {
		return err
	}
	// What to type comes from the catalog (UX-07): the header the caller
	// passes need not say it, and a mismatch replaces it with B.typeback.wrong.
	v := Vars{N: confirmLast}
	if err := t.write(append(SanitizeTerminal([]byte(Format(MsgTypeBack, v))), '\n')); err != nil {
		return err
	}
	wrong := string(SanitizeTerminal([]byte(Format(MsgTypeBackWrong, v))))
	prompt := typeBackPrompt
	for {
		n, err := s.readLine(typed.Bytes(), readOptions{
			prompt:  prompt,
			limit:   maxTypeBack,
			redraw:  seqRedraw + typeBackPrompt,
			discard: true,
		})
		if err != nil {
			return err
		}
		ok := tailMatches(want, typed.Bytes()[:n])
		wipe(typed.Bytes()[:n])
		if ok {
			break
		}
		prompt = seqRetry + wrong + "\n" + seqRedraw + typeBackPrompt
	}
	if s.end() {
		return ErrCancelled
	}
	return nil
}

// isSecretSpace reports the bytes that separate groups of a secret. UTF-8
// continuation and lead bytes are never ASCII, so a byte test is exact.
func isSecretSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' }

// displayableSecret reports whether b is valid UTF-8 without control
// characters (whitespace separators aside) and has a visible character.
func displayableSecret(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	visible := false
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		i += size
		switch {
		case r < 0x80 && isSecretSpace(byte(r)):
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			return false
		default:
			visible = true
		}
	}
	return visible
}

// isWordsPassphrase reports a generated passphrase (vault.Diceware):
// lowercase ASCII words joined by single hyphens, nothing else.
func isWordsPassphrase(b []byte) bool {
	words, n := 0, 0
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			n++
		case c == '-' && n > 0 && i < len(b)-1:
			words++
			n = 0
		default:
			return false
		}
	}
	return n > 0 && words > 0
}

// secretTokens returns the byte ranges of the groups to display and
// whether they are shown apart (joined by a space): the secret's own
// groups when it already contains separators (a key formatted for
// display); a generated passphrase's words, each with its hyphen, shown
// together, exactly as it must be typed (D150: unlike a recovery key, a
// passphrase is never read with its spaces removed, so the screen adds
// none and breaks a line only after a hyphen); otherwise runs of
// groupSize characters.
func secretTokens(b []byte) (tokens [][2]int, apart bool) {
	var out [][2]int
	grouped := false
	for _, c := range b {
		if isSecretSpace(c) {
			grouped = true
			break
		}
	}
	if !grouped && isWordsPassphrase(b) {
		start := 0
		for i, c := range b {
			if c == '-' {
				out = append(out, [2]int{start, i + 1})
				start = i + 1
			}
		}
		return append(out, [2]int{start, len(b)}), false
	}
	if grouped {
		start := -1
		for i, c := range b {
			switch {
			case isSecretSpace(c) && start >= 0:
				out = append(out, [2]int{start, i})
				start = -1
			case !isSecretSpace(c) && start < 0:
				start = i
			}
		}
		if start >= 0 {
			out = append(out, [2]int{start, len(b)})
		}
		return out, true
	}
	start, runes := 0, 0
	for i := 0; i < len(b); {
		_, size := utf8.DecodeRune(b[i:])
		i += size
		if runes++; runes == groupSize {
			out = append(out, [2]int{start, i})
			start, runes = i, 0
		}
	}
	if start < len(b) {
		out = append(out, [2]int{start, len(b)})
	}
	return out, true
}

// groupedSecret lays the groups of b out in lines no wider than width,
// indented, in a new locked buffer.
func groupedSecret(b []byte, width int) (*memguard.LockedBuffer, error) {
	tokens, apart := secretTokens(b)
	gap := 0
	if apart {
		gap = 1
	}
	limit := width - 1
	layout := func(emit func([]byte)) {
		col, onLine := 0, false
		for _, tk := range tokens {
			w := utf8.RuneCount(b[tk[0]:tk[1]])
			if onLine && col+gap+w > limit {
				emit([]byte{'\n'})
				col, onLine = 0, false
			}
			if onLine {
				if apart {
					emit([]byte{' '})
					col++
				}
			} else {
				emit([]byte(secretIndent))
				col = len(secretIndent)
			}
			emit(b[tk[0]:tk[1]])
			col += w
			onLine = true
		}
		emit([]byte{'\n'})
	}
	size := 0
	layout(func(p []byte) { size += len(p) })
	out := memguard.NewBuffer(size)
	if out.Size() == 0 {
		return nil, errNoLockedMem
	}
	dst, off := out.Bytes(), 0
	layout(func(p []byte) { off += copy(dst[off:], p) })
	return out, nil
}

// secretTail returns, in a new locked buffer, the last n characters of b
// that are not separators, with ASCII letters upper-cased (recovery keys
// are case-insensitive).
func secretTail(b []byte, n int) (*memguard.LockedBuffer, error) {
	start, count := len(b), 0
	for start > 0 && count < n {
		_, size := utf8.DecodeLastRune(b[:start])
		start -= size
		if size > 1 || !isSecretSpace(b[start]) {
			count++
		}
	}
	size := 0
	for _, c := range b[start:] {
		if !isSecretSpace(c) {
			size++
		}
	}
	out := memguard.NewBuffer(size)
	if out.Size() == 0 {
		return nil, errNoLockedMem
	}
	dst, k := out.Bytes(), 0
	for _, c := range b[start:] {
		if !isSecretSpace(c) {
			dst[k] = upperASCII(c)
			k++
		}
	}
	return out, nil
}

// tailMatches compares the typed answer, separators removed and ASCII
// upper-cased, with want in constant time.
func tailMatches(want *memguard.LockedBuffer, typed []byte) bool {
	if len(typed) == 0 {
		return false
	}
	norm := memguard.NewBuffer(len(typed))
	if norm.Size() == 0 {
		return false
	}
	defer norm.Destroy()
	dst, k := norm.Bytes(), 0
	for _, c := range typed {
		if !isSecretSpace(c) {
			dst[k] = upperASCII(c)
			k++
		}
	}
	return want.EqualTo(dst[:k])
}

func upperASCII(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}
