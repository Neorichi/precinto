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
func Script(o Options) (string, error) { return script(o) }

// InstallLine returns the rc-file line (`eval "$(precinto shell-init zsh)"`).
func InstallLine(shell string) string { return installLine(shell) }

// RCFile returns the rc file for shell under home (~/.zshrc, ~/.bashrc,
// ~/.config/fish/config.fish).
func RCFile(shell, home string) string { return rcFile(shell, home) }

// Install appends InstallLine to the rc file once (idempotent), only after
// the caller obtained consent.
func Install(shell, home string) error { return install(shell, home) }

// EnterAction is what the folder-entry hook should do.
type EnterAction string

// Enter actions.
const (
	EnterNothing EnterAction = ""
	EnterNotify  EnterAction = "notify" // print ui.MsgEnterNotify
	EnterPrompt  EnterAction = "prompt" // print ui.MsgEnterPrompt (or .plain) and unlock on Enter
	EnterBusy    EnterAction = "busy"   // another terminal is unlocking (ui.MsgEnterElsewhere)
)

// EnterRequest is one shell-hook invocation.
type EnterRequest struct {
	PWD      string
	PrevPWD  string
	Shell    string
	SkipKey  string // _PRECINTO_SKIP=<root-id>:<epoch> from the shell
	FirstRun bool   // first prompt of a new shell
	Home     string // the user's HOME, for ~-shortened folders
	// GUI reports whether a GUI dialog can appear for this terminal
	// (platform.DetectUIContext): C1.prompt names the Mac password only
	// then (ui.FactorName).
	GUI bool
}

// EnterResult is the decision of one shell-hook invocation; `precinto
// shell-hook` prints Lines() and nothing else (D69).
type EnterResult struct {
	Action  EnterAction
	RootID  string
	Path    string // absolute folder path, for precinto unlock --root
	Folder  string
	Epoch   uint64 // lock epoch, so a skip is remembered until the next lock
	Message string
}

// Lines renders r as key=value lines action=, root=, epoch=, path=,
// folder=, message=, one per line, values stripped of C0/C1 controls (a
// newline or tab becomes a space), empty for EnterNothing. The scripts
// parse them without eval: a folder name never becomes shell code (D69).
func (r EnterResult) Lines() string { return resultLines(r) }

// OnEnter decides the action for r using config and a ≤150 ms daemon
// status query; it never prompts and never autostarts the daemon.
func OnEnter(ctx context.Context, c config.Config, l paths.Layout, r EnterRequest) (EnterResult, error) {
	return onEnter(ctx, c, l, r)
}
