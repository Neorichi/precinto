package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/paths"
)

// pinentryNames are the pinentry programs tried, most specific first (D4).
var pinentryNames = []string{"pinentry-mac", "pinentry-gnome3", "pinentry-qt", "pinentry"}

// errPinentryCancelled reports the user closing the dialog.
var errPinentryCancelled = errors.New("agent: pinentry cancelled")

// errNoPinentry reports that no pinentry program is installed.
var errNoPinentry = errors.New("agent: no pinentry program")

// maxPin bounds a pinentry answer.
const maxPin = 4096

// pinentryEnv is the environment of pinentry: what a dialog needs to find
// the user's display, nothing else.
func pinentryEnv(e paths.Env) []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "USER", "LANG", "LC_ALL", "LC_CTYPE", "DISPLAY", "WAYLAND_DISPLAY",
		"DBUS_SESSION_BUS_ADDRESS", paths.EnvXDGRuntimeDir} {
		if v, ok := e.Lookup(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// runPinentry asks for a secret through pinentry's Assuan protocol: OK
// greeting, SETDESC, SETPROMPT, GETPIN, then a "D" line (percent-encoded)
// and OK, or ERR on cancel. The answer is decoded straight into a locked
// buffer; the transfer buffers are wiped.
func runPinentry(ctx context.Context, e paths.Env, desc, prompt string) (*memguard.LockedBuffer, error) {
	prog := ""
	for _, n := range pinentryNames {
		if p, err := paths.LookPath(e, n); err == nil {
			prog = p
			break
		}
	}
	if prog == "" {
		return nil, errNoPinentry
	}
	ctx, cancel := context.WithTimeout(ctx, hookUnlockWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, prog)
	cmd.Env = pinentryEnv(e)
	cmd.WaitDelay = time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("agent: pinentry: %w", err)
	}
	defer func() {
		_, _ = io.WriteString(stdin, "BYE\n")
		_ = stdin.Close()
		_ = cmd.Wait()
	}()
	a := &assuan{r: stdout}
	defer a.wipe()
	if _, err := a.expectOK(); err != nil {
		return nil, err
	}
	for _, c := range []string{"SETDESC " + assuanEscape(desc), "SETPROMPT " + assuanEscape(prompt)} {
		if _, err := io.WriteString(stdin, c+"\n"); err != nil {
			return nil, err
		}
		if _, err := a.expectOK(); err != nil {
			return nil, err
		}
	}
	if _, err := io.WriteString(stdin, "GETPIN\n"); err != nil {
		return nil, err
	}
	return a.expectOK()
}

// assuan reads pinentry responses line by line into a wiped buffer.
type assuan struct {
	r    io.Reader
	line [maxPin * 3]byte
}

func (a *assuan) wipe() { clear(a.line[:]) }

// readLine reads one response line into a.line (no bufio: nothing secret
// stays in a buffer that cannot be wiped).
func (a *assuan) readLine() ([]byte, error) {
	n := 0
	var b [1]byte
	for {
		if _, err := a.r.Read(b[:]); err != nil {
			return nil, err
		}
		if b[0] == '\n' {
			return a.line[:n], nil
		}
		if n == len(a.line) {
			return nil, errors.New("agent: pinentry line too long")
		}
		a.line[n] = b[0]
		n++
	}
}

// expectOK reads until OK (returning any "D" data in a locked buffer) or
// ERR.
func (a *assuan) expectOK() (*memguard.LockedBuffer, error) {
	var data *memguard.LockedBuffer
	for {
		l, err := a.readLine()
		if err != nil {
			if data != nil {
				data.Destroy()
			}
			return nil, fmt.Errorf("agent: pinentry: %w", err)
		}
		switch {
		case bytes.HasPrefix(l, []byte("OK")):
			if data == nil {
				data = memguard.NewBuffer(0)
			}
			clear(l)
			return data, nil
		case bytes.HasPrefix(l, []byte("D ")):
			if data != nil {
				data.Destroy()
			}
			data = assuanUnescape(l[2:])
			clear(l)
		case bytes.HasPrefix(l, []byte("ERR")):
			if data != nil {
				data.Destroy()
			}
			clear(l)
			return nil, errPinentryCancelled
		default:
			clear(l) // comments ("#") and status lines ("S")
		}
	}
}

// assuanEscape percent-encodes what Assuan reserves (%, CR, LF).
func assuanEscape(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

// assuanUnescape decodes %XX escapes into a new locked buffer.
func assuanUnescape(b []byte) *memguard.LockedBuffer {
	out := memguard.NewBuffer(len(b))
	if len(b) == 0 {
		return out
	}
	dst := out.Bytes()
	n := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '%' && i+2 < len(b) {
			if v, ok := unhex(b[i+1], b[i+2]); ok {
				dst[n] = v
				n++
				i += 2
				continue
			}
		}
		dst[n] = b[i]
		n++
	}
	if n == len(b) {
		return out
	}
	trimmed := memguard.NewBuffer(n)
	if n > 0 {
		copy(trimmed.Bytes(), dst[:n])
	}
	out.Destroy()
	return trimmed
}

func unhex(a, b byte) (byte, bool) {
	h := func(c byte) (byte, bool) {
		switch {
		case c >= '0' && c <= '9':
			return c - '0', true
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10, true
		case c >= 'A' && c <= 'F':
			return c - 'A' + 10, true
		}
		return 0, false
	}
	x, ok1 := h(a)
	y, ok2 := h(b)
	return x<<4 | y, ok1 && ok2
}
