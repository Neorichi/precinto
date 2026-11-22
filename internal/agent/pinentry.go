package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
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
// the user's display, nothing else; PATH is limited to the program's own
// directory (D97, as for age plugins). The dialog endpoints decide where
// the install-wide passphrase is typed, and the daemon's environment is
// that of whichever client started it, so each passes only in the form
// that names the user's own local session (D139): the per-user runtime
// directory the login manager creates, the session bus in it, a Wayland
// socket of the user there, an X display of this machine with its socket.
// The clients pass these variables only from a terminal no agent runs
// (the hook never does).
func pinentryEnv(e paths.Env, prog string) []string {
	env := []string{"PATH=" + filepath.Dir(prog)}
	for _, k := range []string{"HOME", "USER", "LANG", "LC_ALL", "LC_CTYPE"} {
		if v, ok := e.Lookup(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return append(env, dialogEnv(e)...)
}

// Where the dialog endpoints live (variables so tests can use a temporary
// tree; trusted replaces the root-only check of the runtime directory's
// parent there).
var (
	runUserDir = "/run/user"
	x11Dir     = "/tmp/.X11-unix"
	trusted    = rootOnlyChain
)

// dialogEnv returns the dialog endpoints of e that name the user's own
// session (D139), as KEY=VALUE pairs.
func dialogEnv(e paths.Env) []string {
	var env []string
	uid := os.Getuid()
	rt := filepath.Join(runUserDir, strconv.Itoa(uid))
	rtOK := e.Get(paths.EnvXDGRuntimeDir) == rt && privateDir(rt, uid) && trusted(runUserDir)
	if rtOK {
		env = append(env, paths.EnvXDGRuntimeDir+"="+rt)
		if e.Get("DBUS_SESSION_BUS_ADDRESS") == "unix:path="+filepath.Join(rt, "bus") {
			env = append(env, "DBUS_SESSION_BUS_ADDRESS=unix:path="+filepath.Join(rt, "bus"))
		}
		if w := e.Get("WAYLAND_DISPLAY"); waylandName(w) && ownSocket(filepath.Join(rt, w), uid) {
			env = append(env, "WAYLAND_DISPLAY="+w)
		}
	}
	if d := e.Get("DISPLAY"); localDisplay(d) {
		n, _, _ := strings.Cut(strings.TrimPrefix(d, ":"), ".")
		// The X socket directory is writable by everyone: the socket must
		// be the user's own server's (rootless Xorg, Xwayland) or root's.
		if st, err := fsx.Lstat(filepath.Join(x11Dir, "X"+n)); err == nil && st.Mode&0o170000 == 0o140000 &&
			(int(st.UID) == uid || st.UID == 0) {
			env = append(env, "DISPLAY="+d)
		}
	}
	return env
}

// dialogKeys are the variables that tell a pinentry where to draw its
// dialog or which session bus prompter to ask (D139).
var dialogKeys = []string{"DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS"}

// StartEnv returns the environment a daemon started by process pid keeps
// (D139): e without the dialog endpoints (DISPLAY, WAYLAND_DISPLAY,
// DBUS_SESSION_BUS_ADDRESS) when pid runs in an agent context by evidence
// an autostarted daemon does not carry on its own — an agent marker in e,
// or an AI agent among pid's ancestors (cut at the D64 stop in -tags
// testing builds; ancestry that cannot be read counts as one) — so
// `precinto agent` run from an agent's shell gives its pinentry no display
// of the agent's choosing. The no-controlling-terminal rule does not
// count: every autostarted daemon is detached, and a client that runs in
// an agent context already leaves these variables out of the daemon it
// autostarts (the hook always does).
func StartEnv(e paths.Env, t platform.ProcTable, pid int) paths.Env {
	if !startedByAgent(e, t, pid) {
		return e
	}
	return e.Without(dialogKeys...)
}

// startedByAgent reports the agent-context evidence StartEnv uses.
func startedByAgent(e paths.Env, t platform.ProcTable, pid int) bool {
	if len(paths.AgentMarkers(e)) > 0 {
		return true
	}
	if t == nil {
		return true
	}
	self, err := t.Lookup(pid)
	if err != nil {
		return true // fail closed
	}
	stop, haveStop := testAncestryStop(e)
	if haveStop && sameIncarnation(self.ID, stop) {
		return false
	}
	anc, err := platform.Ancestors(t, pid, maxAncestry)
	if err != nil {
		return true
	}
	for _, a := range anc {
		if haveStop && sameIncarnation(a.ID, stop) {
			return false // D64: the test process and everything above it
		}
		if _, ok := agentProgram(a); ok {
			return true
		}
	}
	return false
}

// pinentryCanDraw reports whether prog can show its dialog with the
// dialog endpoints env: pinentry-mac uses the user's macOS session and
// needs none; the X11/Wayland pinentries need a display (D139).
func pinentryCanDraw(prog string, env []string) bool {
	if filepath.Base(prog) == "pinentry-mac" {
		return true
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "DISPLAY=") || strings.HasPrefix(kv, "WAYLAND_DISPLAY=") {
			return true
		}
	}
	return false
}

// privateDir reports a directory (not a symlink) owned by uid, mode 0700.
func privateDir(p string, uid int) bool {
	st, err := fsx.Lstat(p)
	return err == nil && st.IsDir() && int(st.UID) == uid && st.Mode&0o777 == 0o700
}

// ownSocket reports a socket owned by uid.
func ownSocket(p string, uid int) bool {
	st, err := fsx.Lstat(p)
	return err == nil && st.Mode&0o170000 == 0o140000 && int(st.UID) == uid
}

// waylandName reports a compositor socket name as compositors choose it
// ("wayland-0"): no path, nothing else.
func waylandName(s string) bool {
	n, ok := strings.CutPrefix(s, "wayland-")
	return ok && digits(n)
}

// localDisplay reports an X display of this machine (":0", ":1.0"): no
// host part, so never a connection to another machine.
func localDisplay(s string) bool {
	rest, ok := strings.CutPrefix(s, ":")
	if !ok {
		return false
	}
	n, screen, has := strings.Cut(rest, ".")
	return digits(n) && (!has || digits(screen))
}

func digits(s string) bool {
	if s == "" || len(s) > 6 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// findPinentry returns the pinentry program to run (D97): the first of
// pinentryNames, in PATH order, that is a trusted executable. The program
// receives the install-wide passphrase, and the daemon's PATH comes from
// whichever client autostarted it, so a pinentry in a directory the user
// (or an agent running as the user) can write — Homebrew's prefix, a
// directory put first on PATH — is never run.
func findPinentry(e paths.Env) (string, error) {
	dirs := filepath.SplitList(e.Get("PATH"))
	for _, n := range pinentryNames {
		for _, d := range dirs {
			if d == "" || !filepath.IsAbs(d) {
				continue
			}
			if real, ok := trustedExecutable(filepath.Join(d, n)); ok {
				return real, nil
			}
		}
	}
	return "", errNoPinentry
}

// trustedExecutable resolves p and reports whether it is a regular,
// executable file owned by root and not group- or other-writable, whose
// directory chain (that of p and that of its target) only root can change.
func trustedExecutable(p string) (string, bool) {
	if !rootOnlyChain(filepath.Dir(p)) {
		return "", false
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", false
	}
	st, err := fsx.Lstat(real)
	if err != nil || !st.IsRegular() || st.UID != 0 || st.Mode&0o022 != 0 || st.Mode&0o111 == 0 {
		return "", false
	}
	if !rootOnlyChain(filepath.Dir(real)) {
		return "", false
	}
	return real, true
}

// rootOnlyChain reports whether dir and every ancestor are owned by root
// and, when directories, not group- or other-writable (a symlinked
// component is judged by its own ownership here and its target through
// the resolved chain).
func rootOnlyChain(dir string) bool {
	if !filepath.IsAbs(dir) {
		return false
	}
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		st, err := fsx.Lstat(d)
		if err != nil || st.UID != 0 || (st.IsDir() && st.Mode&0o022 != 0) {
			return false
		}
		if !st.IsDir() {
			real, err := filepath.EvalSymlinks(d)
			if err != nil || (real != d && !rootOnlyChain(real)) {
				return false
			}
		}
		if d == "/" {
			return true
		}
	}
}

// runPinentry asks for a secret through pinentry's Assuan protocol: OK
// greeting, SETDESC, SETPROMPT, GETPIN, then a "D" line (percent-encoded)
// and OK, or ERR on cancel. The answer is decoded straight into a locked
// buffer; the transfer buffers are wiped.
func runPinentry(ctx context.Context, e paths.Env, desc, prompt string) (*memguard.LockedBuffer, error) {
	prog, err := findPinentry(e)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, hookUnlockWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, prog)
	cmd.Env = pinentryEnv(e, prog)
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
