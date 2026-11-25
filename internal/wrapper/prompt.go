package wrapper

import (
	"strings"

	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/ipc"
)

// promptUI is the terminal the wrapper prompts on before the launch
// (*ui.TTY in production).
type promptUI interface {
	ipc.UIHandler
	YesNo(prompt string, def bool) (bool, error)
	Close() error
}

// lazyUI opens the terminal on first use only, so a launch that needs no
// prompt never touches /dev/tty.
type lazyUI struct {
	open func() (promptUI, error)
	t    promptUI
	err  error
}

func (l *lazyUI) get() (promptUI, error) {
	if l.t == nil && l.err == nil {
		l.t, l.err = l.open()
		if l.err == nil && l.t == nil {
			l.err = errNotTerminal
		}
	}
	return l.t, l.err
}

func (l *lazyUI) Display(msg string) error {
	t, err := l.get()
	if err != nil {
		return err
	}
	return t.Display(msg)
}

func (l *lazyUI) Secret(prompt string) (*memguard.LockedBuffer, error) {
	t, err := l.get()
	if err != nil {
		return nil, err
	}
	return t.Secret(prompt)
}

func (l *lazyUI) Confirm(prompt, yes, no string) (bool, error) {
	t, err := l.get()
	if err != nil {
		return false, err
	}
	return t.Confirm(prompt, yes, no)
}

func (l *lazyUI) YesNo(prompt string, def bool) (bool, error) {
	t, err := l.get()
	if err != nil {
		return false, err
	}
	return t.YesNo(prompt, def)
}

func (l *lazyUI) Close() error {
	if l.t == nil {
		return nil
	}
	err := l.t.Close()
	l.t, l.err = nil, nil
	return err
}

// overlayUI relays the daemon's unlock prompts onto the lock screen (Enter
// on the overlay unlocks in this terminal, SPEC §15.2). Keys reach it
// through the proxy's input loop, never as activity.
type overlayUI struct {
	s      *proxyState
	cancel <-chan struct{}
}

var _ ipc.UIHandler = (*overlayUI)(nil)

func (u *overlayUI) Display(msg string) error {
	u.s.setStatus(msg)
	return nil
}

func (u *overlayUI) Secret(prompt string) (*memguard.LockedBuffer, error) {
	lb, _, err := u.s.prompt(prompt, true, u.cancel)
	return lb, err
}

// Confirm asks to type the yes word (the relayed request's words).
func (u *overlayUI) Confirm(prompt, yes, no string) (bool, error) {
	if strings.TrimSpace(yes) == "" {
		yes = "yes"
	}
	if strings.TrimSpace(no) == "" {
		no = "no"
	}
	text := strings.TrimSpace(prompt) + " [" + yes + "/" + no + "]"
	_, line, err := u.s.prompt(text, false, u.cancel)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(line), strings.TrimSpace(yes)), nil
}
