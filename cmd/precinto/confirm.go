package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

// refusal describes a command that a human must run in their own terminal
// (D7, D28, D59): it is refused in agent contexts (environment markers, a
// harness ancestor, or no controlling terminal, which ui.AgentContext
// counts itself).
type refusal struct {
	action  string // C12.agent {action}: "forget the sealed copies of"
	folder  string // C12.agent {folder}: the display path, or a phrase
	command string // C12.agent {command}: what to run instead
	init    bool   // print B.refuse instead of C12.agent
}

// refuseAgent prints the refusal and returns a refusedError when the
// caller runs in an agent context. It is called only by the commands SPEC
// §16.1 lists (init, factor, recover, vault repair, prune, forget,
// unprotect), never by daemon workers or targeted restores (D62).
func (a *app) refuseAgent(r refusal) error {
	agentCtx, _ := a.sys.agentContext(a.env, a.procs())
	if !agentCtx {
		return nil
	}
	if r.init {
		a.line(ui.MsgInitRefuseAgent, ui.Vars{})
	} else {
		a.line(ui.MsgRefuseAgent, ui.Vars{Action: r.action, Folder: r.folder, Command: r.command})
	}
	return refusedError{reason: "agent context"}
}

// needTerminal opens the controlling terminal for a command that must run
// on a human TTY (typed confirmations, recovery key, vault repair). Without
// one the command is refused (exit 3).
func (a *app) needTerminal(name string) (terminal, error) {
	t, err := a.sys.openTTY()
	if err != nil {
		a.line(ui.MsgNeedTerminal, ui.Vars{Command: "precinto " + name})
		return nil, refusedError{reason: "no terminal"}
	}
	return t, nil
}

// typedConfirm asks for the typed confirmation word of a destructive
// command (C12.typed, D59). Anything but the exact word refuses.
func (a *app) typedConfirm(t terminal, action, word string) error {
	prompt := ui.Format(ui.MsgConfirmTyped, ui.Vars{Action: action, Command: word})
	return a.typedWord(t, prompt, word)
}

// typedWord reads one line and requires it to equal word.
func (a *app) typedWord(t terminal, prompt, word string) error {
	line, err := t.ReadLine(prompt)
	if err != nil {
		if errors.Is(err, ui.ErrCancelled) {
			a.say(textNotConfirmed)
			return refusedError{reason: "cancelled"}
		}
		return err
	}
	if strings.TrimSpace(line) != word {
		a.say(textNotConfirmed)
		return refusedError{reason: "not confirmed"}
	}
	return nil
}

// headlessUI is the ipc.UIHandler of a client without a terminal: relayed
// messages are shown on stderr and every prompt is refused, so the daemon
// falls back to a GUI factor or pinentry (D4, D27).
type headlessUI struct{ w io.Writer }

func (h headlessUI) Display(msg string) error {
	_, err := fmt.Fprintln(h.w, oneLineText(msg))
	return err
}

func (headlessUI) Secret(string) (*memguard.LockedBuffer, error) { return nil, vault.ErrNoUI }

func (headlessUI) Confirm(string, string, string) (bool, error) { return false, vault.ErrNoUI }

// vaultUI adapts the terminal to vault.UI (init runs vault.Store.Init in
// the CLI, docs/API.md §7).
type vaultUI struct {
	t   terminal
	gui bool
}

func (u vaultUI) Display(msg string) error { return u.t.Display(msg) }

func (u vaultUI) Secret(prompt string) (*memguard.LockedBuffer, error) {
	b, err := u.t.Secret(prompt)
	if errors.Is(err, ui.ErrCancelled) {
		return nil, vault.ErrCancelled
	}
	return b, err
}

func (u vaultUI) Confirm(prompt, yes, no string) (bool, error) {
	ok, err := u.t.Confirm(prompt, yes, no)
	if errors.Is(err, ui.ErrCancelled) {
		return false, vault.ErrCancelled
	}
	return ok, err
}

func (u vaultUI) Interactive() bool { return true }

func (u vaultUI) GUI() bool { return u.gui }

// secretAnswer is an ipc.UIHandler that answers every relayed secret prompt
// with a copy of one secret (recover: the daemon asks for the recovery key
// once per folder) and relays everything else to next.
type secretAnswer struct {
	secret *memguard.LockedBuffer
	next   interface {
		Display(string) error
		Confirm(string, string, string) (bool, error)
	}
}

func (s secretAnswer) Display(msg string) error { return s.next.Display(msg) }

func (s secretAnswer) Secret(string) (*memguard.LockedBuffer, error) {
	return copySecret(s.secret)
}

// copySecret copies a locked buffer into a new one without a heap copy
// (ipc consumes the buffers it sends).
func copySecret(b *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	if b == nil || !b.IsAlive() || b.Size() == 0 {
		return nil, vault.ErrNoUI
	}
	c := memguard.NewBuffer(b.Size())
	c.Copy(b.Bytes())
	return c, nil
}

func (s secretAnswer) Confirm(prompt, yes, no string) (bool, error) {
	return s.next.Confirm(prompt, yes, no)
}
