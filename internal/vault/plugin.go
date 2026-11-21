package vault

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/fsx"
)

// Plugin-backed factors (se and plugin) run their age plugin through this
// minimal client of the age plugin protocol (identity-v1 to unwrap,
// recipient-v1 to wrap). filippo.io/age/plugin's own client resolves
// "age-plugin-<name>" through the daemon's PATH and passes the daemon's
// whole environment, so it cannot honour S2: here the plugin always runs
// from its pinned absolute path, after its SHA-256 matched the pin, with an
// environment holding only PATH=<pinned directory>.

const (
	maxPluginLine  = 64 << 10 // one protocol line
	maxPluginBody  = 1 << 20  // one stanza body
	pluginExitWait = 5 * time.Second
	maxUIText      = 512       // plugin-supplied prompt or message, after sanitizing
	maxPluginBin   = 512 << 20 // a plugin binary to hash (real ones are a few MB)
)

var errPluginProtocol = errors.New("vault: age plugin protocol error")

// errPluginFailed marks a failure the plugin reported or a plugin that
// could not run: never a sign of a wrong or tampered identity file.
var errPluginFailed = errors.New("vault: age plugin failed")

var pluginB64 = base64.RawStdEncoding.Strict()

// pinHash hashes the plugin binary at path, which must be a regular file
// (not a symlink) of bounded size and must not be replaced or changed
// while it is read. It is opened O_NOFOLLOW|O_NONBLOCK, so a symlink or a
// FIFO swapped in after the lstat fails at once instead of blocking.
func pinHash(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("vault: plugin path %q is not absolute and clean", path)
	}
	lst, err := fsx.Lstat(path)
	if err != nil {
		return "", err
	}
	if !lst.IsRegular() {
		return "", fmt.Errorf("vault: plugin %s is not a regular file", path)
	}
	f, err := os.OpenFile(path, pinOpenFlags, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return "", err
	}
	if !st.IsRegular() || !st.SameFile(lst) {
		return "", fmt.Errorf("vault: plugin %s was replaced while being checked", path)
	}
	if st.Size > maxPluginBin {
		return "", fmt.Errorf("vault: plugin %s is too large (%d bytes)", path, st.Size)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxPluginBin+1))
	if err != nil {
		return "", err
	}
	// Content only: ctime also moves when the binary's metadata changes
	// (an xattr set while another unwrap runs it), which alters no byte.
	if after, err := fsx.Fstat(f); err != nil || n != st.Size || !after.SameFile(st) || after.Size != st.Size || after.MtimeNS != st.MtimeNS {
		return "", fmt.Errorf("vault: plugin %s changed while being checked", path)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyPin requires the factor's plugin to match its pinned hash (S2).
func verifyPin(f Factor) error {
	if f.PluginPath == "" || f.PluginSHA256 == "" {
		return fmt.Errorf("%w: factor %s has no pinned plugin", ErrPluginPin, f.Name)
	}
	sum, err := pinHash(f.PluginPath)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPluginPin, err)
	}
	if sum != f.PluginSHA256 {
		return fmt.Errorf("%w: %s", ErrPluginPin, f.PluginPath)
	}
	return nil
}

// sanitizeUI keeps plugin-supplied text printable and short before it is
// relayed to a terminal or dialog.
func sanitizeUI(b []byte) string {
	var sb strings.Builder
	for _, r := range string(b) {
		if sb.Len() >= maxUIText {
			break
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func validArg(a string) bool {
	if a == "" {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] < 33 || a[i] > 126 {
			return false
		}
	}
	return true
}

// pluginConn is one running plugin process.
type pluginConn struct {
	cmd   *exec.Cmd
	in    io.WriteCloser
	out   *bufio.Reader
	ui    UI
	name  string
	uiErr error // first relayed-UI failure, reported instead of the plugin's error
}

func startPlugin(ctx context.Context, f Factor, name, machine string, ui UI) (*pluginConn, error) {
	if err := verifyPin(f); err != nil {
		return nil, err
	}
	if filepath.Base(f.PluginPath) != "age-plugin-"+name {
		return nil, fmt.Errorf("%w: %s does not run plugin %q", ErrPluginPin, f.PluginPath, name)
	}
	dir := filepath.Dir(f.PluginPath)
	cmd := exec.CommandContext(ctx, f.PluginPath, "--age-plugin="+machine)
	cmd.Env = []string{"PATH=" + dir}
	cmd.Dir = dir
	cmd.WaitDelay = pluginExitWait
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: starting the %s plugin: %w", errPluginFailed, name, err)
	}
	return &pluginConn{cmd: cmd, in: in, out: bufio.NewReaderSize(out, maxPluginLine), ui: ui, name: name}, nil
}

// close ends the session: stdin is closed and the plugin gets
// pluginExitWait to exit before it is killed.
func (c *pluginConn) close() {
	c.in.Close()
	done := make(chan struct{})
	go func() { _ = c.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(pluginExitWait):
		_ = c.cmd.Process.Kill()
		<-done
	}
}

func (c *pluginConn) write(typ string, args []string, body []byte) error {
	var hdr bytes.Buffer
	hdr.WriteString("-> ")
	hdr.WriteString(typ)
	for _, a := range args {
		if !validArg(a) {
			return fmt.Errorf("%w: invalid stanza argument", errPluginProtocol)
		}
		hdr.WriteByte(' ')
		hdr.WriteString(a)
	}
	hdr.WriteByte('\n')
	if _, err := c.in.Write(hdr.Bytes()); err != nil {
		return err
	}
	return writeBody(c.in, body)
}

// writeBody writes body as base64 lines of 64 columns ending with a shorter
// (possibly empty) line. It encodes through one small buffer that is wiped
// afterwards, because bodies may carry a PIN or a file key.
func writeBody(w io.Writer, body []byte) error {
	var line [65]byte
	defer memguard.WipeBytes(line[:])
	for len(body) >= 48 {
		base64.RawStdEncoding.Encode(line[:64], body[:48])
		line[64] = '\n'
		if _, err := w.Write(line[:]); err != nil {
			return err
		}
		body = body[48:]
	}
	n := base64.RawStdEncoding.EncodedLen(len(body))
	base64.RawStdEncoding.Encode(line[:n], body)
	line[n] = '\n'
	_, err := w.Write(line[:n+1])
	return err
}

func (c *pluginConn) readLine() ([]byte, error) {
	line, err := c.out.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return nil, fmt.Errorf("%w: line too long", errPluginProtocol)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errPluginProtocol, err)
	}
	return line[:len(line)-1], nil
}

func (c *pluginConn) read() (string, []string, []byte, error) {
	line, err := c.readLine()
	if err != nil {
		return "", nil, nil, err
	}
	rest, ok := bytes.CutPrefix(line, []byte("-> "))
	if !ok {
		return "", nil, nil, fmt.Errorf("%w: malformed stanza", errPluginProtocol)
	}
	fields := strings.Split(string(rest), " ")
	for _, f := range fields {
		if !validArg(f) {
			return "", nil, nil, fmt.Errorf("%w: malformed stanza", errPluginProtocol)
		}
	}
	var body []byte
	for {
		l, err := c.readLine()
		if err != nil {
			return "", nil, nil, err
		}
		if len(l) > 64 {
			return "", nil, nil, fmt.Errorf("%w: body line too long", errPluginProtocol)
		}
		dec, err := pluginB64.DecodeString(string(l))
		if err != nil {
			return "", nil, nil, fmt.Errorf("%w: malformed body", errPluginProtocol)
		}
		body = append(body, dec...)
		if len(body) > maxPluginBody {
			return "", nil, nil, fmt.Errorf("%w: body too large", errPluginProtocol)
		}
		if len(l) < 64 {
			return fields[0], fields[1:], body, nil
		}
	}
}

func (c *pluginConn) noteUI(err error) {
	if c.uiErr == nil && (errors.Is(err, ErrNoUI) || errors.Is(err, ErrCancelled)) {
		c.uiErr = err
	}
}

// interact answers the plugin's UI requests through the relayed UI (D4).
func (c *pluginConn) interact(typ string, args []string, body []byte) error {
	switch typ {
	case "msg":
		if c.ui == nil {
			return c.write("fail", nil, nil)
		}
		if err := c.ui.Display(sanitizeUI(body)); err != nil {
			c.noteUI(err)
			return c.write("fail", nil, nil)
		}
		return c.write("ok", nil, nil)
	case "request-secret", "request-public":
		if c.ui == nil {
			c.noteUI(ErrNoUI)
			return c.write("fail", nil, nil)
		}
		val, err := c.ui.Secret(sanitizeUI(body))
		if err != nil {
			c.noteUI(err)
			return c.write("fail", nil, nil)
		}
		defer val.Destroy()
		return c.write("ok", nil, val.Bytes())
	case "confirm":
		if len(args) != 1 && len(args) != 2 {
			return fmt.Errorf("%w: malformed confirm", errPluginProtocol)
		}
		yes, err := pluginB64.DecodeString(args[0])
		if err != nil {
			return fmt.Errorf("%w: malformed confirm", errPluginProtocol)
		}
		var no []byte
		if len(args) == 2 {
			if no, err = pluginB64.DecodeString(args[1]); err != nil {
				return fmt.Errorf("%w: malformed confirm", errPluginProtocol)
			}
		}
		if c.ui == nil {
			c.noteUI(ErrNoUI)
			return c.write("fail", nil, nil)
		}
		ok, err := c.ui.Confirm(sanitizeUI(body), sanitizeUI(yes), sanitizeUI(no))
		if err != nil {
			c.noteUI(err)
			return c.write("fail", nil, nil)
		}
		answer := "no"
		if ok {
			answer = "yes"
		}
		return c.write("ok", []string{answer}, nil)
	default:
		return c.write("unsupported", nil, nil) // grease and unknown requests
	}
}

func (c *pluginConn) pluginError(body []byte) error {
	if c.uiErr != nil {
		return c.uiErr
	}
	return fmt.Errorf("%w: the %s plugin reported: %s", errPluginFailed, c.name, sanitizeUI(body))
}

// unwrap runs identity-v1 for one file's stanzas.
func (c *pluginConn) unwrap(stub string, stanzas []*age.Stanza) ([]byte, error) {
	if err := c.write("add-identity", []string{stub}, nil); err != nil {
		return nil, err
	}
	for _, s := range stanzas {
		if err := c.write("recipient-stanza", append([]string{"0", s.Type}, s.Args...), s.Body); err != nil {
			return nil, err
		}
	}
	if err := c.write("done", nil, nil); err != nil {
		return nil, err
	}
	var fileKey []byte
	for {
		typ, args, body, err := c.read()
		if err != nil {
			if c.uiErr != nil {
				return nil, c.uiErr
			}
			return nil, err
		}
		switch typ {
		case "file-key":
			if len(args) != 1 || args[0] != "0" || fileKey != nil {
				return nil, fmt.Errorf("%w: unexpected file-key", errPluginProtocol)
			}
			fileKey = body
			if err := c.write("ok", nil, nil); err != nil {
				return nil, err
			}
		case "error":
			_ = c.write("ok", nil, nil)
			return nil, c.pluginError(body)
		case "done":
			if fileKey == nil {
				if c.uiErr != nil {
					return nil, c.uiErr
				}
				return nil, age.ErrIncorrectIdentity
			}
			return fileKey, nil
		default:
			if err := c.interact(typ, args, body); err != nil {
				return nil, err
			}
		}
	}
}

// wrap runs recipient-v1 for one file key.
func (c *pluginConn) wrap(recipient string, fileKey []byte) ([]*age.Stanza, error) {
	for _, s := range []struct {
		typ  string
		args []string
		body []byte
	}{{"add-recipient", []string{recipient}, nil}, {"wrap-file-key", nil, fileKey}, {"extension-labels", nil, nil}, {"done", nil, nil}} {
		if err := c.write(s.typ, s.args, s.body); err != nil {
			return nil, err
		}
	}
	var stanzas []*age.Stanza
	for {
		typ, args, body, err := c.read()
		if err != nil {
			if c.uiErr != nil {
				return nil, c.uiErr
			}
			return nil, err
		}
		switch typ {
		case "recipient-stanza":
			if len(args) < 2 || args[0] != "0" {
				return nil, fmt.Errorf("%w: unexpected recipient-stanza", errPluginProtocol)
			}
			stanzas = append(stanzas, &age.Stanza{Type: args[1], Args: append([]string(nil), args[2:]...), Body: body})
			if err := c.write("ok", nil, nil); err != nil {
				return nil, err
			}
		case "labels":
			// One recipient per identity file: labels need no consistency check.
			if err := c.write("ok", nil, nil); err != nil {
				return nil, err
			}
		case "error":
			_ = c.write("ok", nil, nil)
			return nil, c.pluginError(body)
		case "done":
			if len(stanzas) == 0 {
				return nil, fmt.Errorf("%w: no recipient stanza", errPluginProtocol)
			}
			return stanzas, nil
		default:
			if err := c.interact(typ, args, body); err != nil {
				return nil, err
			}
		}
	}
}

// pluginName returns the plugin a factor runs, from its identity stub.
func pluginName(f Factor) (string, error) {
	name, _, err := plugin.ParseIdentity(f.IdentityStub)
	if err != nil {
		return "", fmt.Errorf("vault: factor %s has a malformed identity stub", f.Name)
	}
	return name, nil
}

// pluginIdentity unwraps through the factor's pinned plugin (age.Identity).
type pluginIdentity struct {
	ctx context.Context
	f   Factor
	ui  UI
}

func (p *pluginIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	name, err := pluginName(p.f)
	if err != nil {
		return nil, err
	}
	c, err := startPlugin(p.ctx, p.f, name, "identity-v1", p.ui)
	if err != nil {
		return nil, err
	}
	defer c.close()
	key, err := c.unwrap(p.f.IdentityStub, stanzas)
	if err != nil && p.ctx.Err() != nil {
		return nil, p.ctx.Err()
	}
	return key, err
}

// pluginRecipient wraps through the factor's pinned plugin (age.Recipient).
type pluginRecipient struct {
	ctx       context.Context
	f         Factor
	ui        UI
	name      string
	recipient string
}

func (p *pluginRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	c, err := startPlugin(p.ctx, p.f, p.name, "recipient-v1", p.ui)
	if err != nil {
		return nil, err
	}
	defer c.close()
	st, err := c.wrap(p.recipient, fileKey)
	if err != nil && p.ctx.Err() != nil {
		return nil, p.ctx.Err()
	}
	return st, err
}
