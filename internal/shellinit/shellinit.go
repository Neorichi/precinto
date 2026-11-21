package shellinit

import (
	"context"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/paths"
)

// Shells.
const (
	Zsh  = "zsh"
	Bash = "bash"
	Fish = "fish"
)

// Options configures Script.
type Options struct {
	Shell     string
	Harnesses []string // e.g. ["claude", "codex"] (executable names)
	Exe       string   // absolute precinto path written into the functions
}

// Script returns the integration snippet for o.Shell.
func Script(o Options) (string, error) { panic("unimplemented: shellinit.Script") }

// InstallLine returns the rc-file line (`eval "$(precinto shell-init zsh)"`).
func InstallLine(shell string) string { panic("unimplemented: shellinit.InstallLine") }

// RCFile returns the rc file for shell under home (~/.zshrc, ~/.bashrc,
// ~/.config/fish/config.fish).
func RCFile(shell, home string) string { panic("unimplemented: shellinit.RCFile") }

// Install appends InstallLine to the rc file once (idempotent), only after
// the caller obtained consent.
func Install(shell, home string) error { panic("unimplemented: shellinit.Install") }

// EnterAction is what the folder-entry hook should do.
type EnterAction string

// Enter actions.
const (
	EnterNothing EnterAction = ""
	EnterNotify  EnterAction = "notify" // print ui.MsgEnterNotify
	EnterPrompt  EnterAction = "prompt" // print ui.MsgEnterPrompt and unlock on Enter
	EnterBusy    EnterAction = "busy"   // another terminal is unlocking (ui.MsgEnterElsewhere)
)

// EnterRequest is one shell-hook invocation.
type EnterRequest struct {
	PWD      string
	PrevPWD  string
	Shell    string
	SkipKey  string // _PRECINTO_SKIP=<root-id>:<epoch> from the shell
	FirstRun bool   // first prompt of a new shell
}

// EnterResult is printed by the shell hook as shell assignments.
type EnterResult struct {
	Action  EnterAction
	RootID  string
	Folder  string
	Epoch   uint64 // lock epoch, so a skip is remembered until the next lock
	Message string
}

// OnEnter decides the action for r using config and a ≤150 ms daemon
// status query; it never prompts and never autostarts the daemon.
func OnEnter(ctx context.Context, c config.Config, l paths.Layout, r EnterRequest) (EnterResult, error) {
	panic("unimplemented: shellinit.OnEnter")
}
