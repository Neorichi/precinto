//go:build !darwin && !linux

package ui

import (
	"errors"
	"os"
	"time"
)

// errUnsupported: precinto prompts on darwin and linux terminals only (D34).
var errUnsupported = errors.New("ui: terminal prompts are not supported on this OS")

func watchedSignals() []os.Signal { return nil }

func isContinueSignal(os.Signal) bool { return false }

func openTerminalFile(string) (*os.File, error) { return nil, errUnsupported }

// hasControllingTerminal cannot be determined here; AgentContext then
// treats the process as an agent context (fail closed).
func hasControllingTerminal() bool { return false }

func (t *TTY) waitInput(time.Duration) (bool, error) { return false, errUnsupported }

func (t *TTY) readInput([]byte) (int, bool, error) { return 0, false, errUnsupported }
