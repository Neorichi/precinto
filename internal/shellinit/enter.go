package shellinit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/ui"
)

// errPWD rejects a request whose PWD is not an absolute path.
var errPWD = errors.New("shellinit: PWD must be an absolute path")

// Vault states in ipc.VaultStatus.State. "unlocking" is how the daemon
// reports an unlock in flight in another terminal (single-flight, SPEC
// §15.5); any state but "unlocked" counts as locked.
const (
	stateUnlocked  = "unlocked"
	stateUnlocking = "unlocking"
)

// statusClient is the part of the ipc client OnEnter uses.
type statusClient interface {
	Status(ctx context.Context) (ipc.StatusResp, error)
	Close() error
}

// dialStatus connects to the daemon without autostart (OnEnter never
// starts it). A variable so that tests substitute a fake daemon.
var dialStatus = func(ctx context.Context, l paths.Layout) (statusClient, error) {
	c, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l, Client: "shell", Timeout: ipc.GateBudget})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// onEnter implements OnEnter.
func onEnter(ctx context.Context, c config.Config, l paths.Layout, r EnterRequest) (EnterResult, error) {
	pwd, ok := cleanAbs(r.PWD)
	if !ok {
		return EnterResult{}, errPWD
	}
	root, ok := c.RootFor(pwd)
	if !ok || root.ID == "" {
		return EnterResult{}, nil
	}
	// Only outside→inside transitions, or the first prompt of a shell that
	// starts inside (D29).
	if prev, ok := cleanAbs(r.PrevPWD); !r.FirstRun && ok && paths.Within(root.Path, prev) {
		return EnterResult{}, nil
	}
	mode := c.EffectiveOnEnter(root)
	if mode == config.OnEnterOff {
		return EnterResult{}, nil
	}
	vs, known := vaultState(ctx, l, root.ID)
	if known && vs.State == stateUnlocked {
		return EnterResult{}, nil
	}
	res := EnterResult{RootID: root.ID, Folder: displayFolder(l, root.Path), Epoch: epochOf(vs, known)}
	if r.SkipKey == res.RootID+":"+strconv.FormatUint(res.Epoch, 10) {
		// Already asked in this shell since the folder last locked.
		return EnterResult{RootID: res.RootID, Folder: res.Folder, Epoch: res.Epoch}, nil
	}
	v := ui.Vars{Folder: res.Folder}
	switch {
	case known && vs.State == stateUnlocking:
		res.Action, res.Message = EnterBusy, ui.Format(ui.MsgEnterElsewhere, v)
	case mode == config.OnEnterNotify:
		res.Action, res.Message = EnterNotify, ui.Format(ui.MsgEnterNotify, v)
	default:
		// "prompt", and any value precinto does not know (strictest).
		res.Action, res.Message = EnterPrompt, ui.Format(ui.MsgEnterPrompt, v)
	}
	return res, nil
}

// vaultState asks the daemon, within the gate budget, how the folder's vault
// is. known is false when the daemon cannot answer: no daemon means every
// folder is locked (no process holds a key).
func vaultState(ctx context.Context, l paths.Layout, rootID string) (vs ipc.VaultStatus, known bool) {
	ctx, cancel := context.WithTimeout(ctx, ipc.GateBudget)
	defer cancel()
	defer func() {
		if recover() != nil {
			vs, known = ipc.VaultStatus{}, false
		}
	}()
	cl, err := dialStatus(ctx, l)
	if err != nil || cl == nil {
		return ipc.VaultStatus{}, false
	}
	defer cl.Close()
	st, err := cl.Status(ctx)
	if err != nil {
		return ipc.VaultStatus{}, false
	}
	for _, v := range st.Vaults {
		if v.VaultID == rootID {
			return v, true
		}
	}
	// The daemon runs but has no vault for the folder: locked.
	return ipc.VaultStatus{VaultID: rootID, State: "locked", Since: st.Started}, true
}

// epochOf is the lock epoch a skip is remembered for: the time the vault
// entered its current state (0 when the daemon is not running, so a skip
// lasts until the daemon starts and reports one).
func epochOf(vs ipc.VaultStatus, known bool) uint64 {
	if !known || vs.Since.IsZero() || vs.Since.Before(time.Unix(0, 0)) {
		return 0
	}
	return uint64(vs.Since.Unix())
}

// displayFolder is the ~-shortened folder path. OnEnter has no environment,
// so HOME is recovered from precinto's base when the base is the default
// one for the OS (…/Library/Application Support/precinto or
// …/.local/share/precinto); otherwise the full path is shown.
func displayFolder(l paths.Layout, p string) string {
	for _, suffix := range []string{"/Library/Application Support/precinto", "/.local/share/precinto"} {
		if home, ok := strings.CutSuffix(l.Base, suffix); ok && home != "" && filepath.IsAbs(home) {
			return paths.Tilde(home, p)
		}
	}
	return p
}

// resultLines renders r the way the integration scripts read the output of
// `precinto shell-hook`: one key=value line each for action, root, epoch,
// folder and message, every value on one line. Nothing at all when there
// is nothing to do.
func resultLines(r EnterResult) string {
	if r.Action == EnterNothing {
		return ""
	}
	var b strings.Builder
	for _, kv := range [][2]string{
		{"action", string(r.Action)},
		{"root", r.RootID},
		{"epoch", strconv.FormatUint(r.Epoch, 10)},
		{"folder", r.Folder},
		{"message", r.Message},
	} {
		b.WriteString(kv[0])
		b.WriteByte('=')
		b.WriteString(singleLine(kv[1]))
		b.WriteByte('\n')
	}
	return b.String()
}

// singleLine keeps a value on its line and free of terminal controls.
func singleLine(s string) string {
	b := ui.SanitizeTerminal([]byte(s))
	return strings.NewReplacer("\n", " ", "\t", " ").Replace(string(b))
}

// install implements Install.
func install(shell, home string) error {
	if _, ok := cleanAbs(home); !ok {
		return errors.New("shellinit: home must be an absolute path")
	}
	rc, line := rcFile(shell, home), installLine(shell)
	if rc == "" || line == "" {
		return errShell
	}
	b, err := os.ReadFile(rc)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, have := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(have) == line {
			return nil // already installed
		}
	}
	if err := os.MkdirAll(filepath.Dir(rc), 0o700); err != nil {
		return err
	}
	// O_APPEND keeps the file (and a symlink to a dotfiles repository) as it
	// is and adds one line.
	f, err := os.OpenFile(rc, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	add := line + "\n"
	if len(b) > 0 && !strings.HasSuffix(string(b), "\n") {
		add = "\n" + add
	}
	if _, err := f.WriteString(add); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
