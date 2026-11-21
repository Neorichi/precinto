package main

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

// usageError is a command-line mistake (exit 2).
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usageErrorf(format string, args ...any) error {
	return usageError{msg: fmt.Sprintf(format, args...)}
}

// notProtectedError names a directory that is not inside a protected
// folder (exit 2: the argument is wrong).
type notProtectedError struct{ dir string }

func (e notProtectedError) Error() string {
	return fmt.Sprintf(textNotProtected, e.dir)
}

// refusedError is a refusal the CLI itself decided (agent context, no
// terminal, missing typed confirmation): exit 3. Its message was printed.
type refusedError struct{ reason string }

func (e refusedError) Error() string { return e.reason }

// shownError is a failure whose message was already printed (a catalog
// line such as B.needse); code is its exit code.
type shownError struct {
	reason string
	code   int
}

func (e shownError) Error() string { return e.reason }

// Exit-code classes of docs/API.md §5, by sentinel. Restore-only classes
// (fsx.ErrUnsafe and harness.ErrUnitKey raised while restoring or
// extracting) are added by exitForRestore.
var (
	verifyErrors = []error{
		capsule.ErrVerify, capsule.ErrHeader, capsule.ErrRecipients, capsule.ErrFormat,
		capsule.ErrUnsafe, capsule.ErrTooLarge,
		vault.ErrMACMismatch, vault.ErrRecipientsChanged, vault.ErrWrongIdentity, vault.ErrPluginPin,
		capslog.ErrNotLogged, sweep.ErrTripwire, sweep.ErrNotLogged,
	}
	restoreVerifyErrors = []error{fsx.ErrUnsafe, harness.ErrUnitKey}
	liveErrors          = []error{sweep.ErrLive, capsule.ErrChanged, sweep.ErrConflict}
	lockedErrors        = []error{
		sweep.ErrKeyDenied, vault.ErrCancelled, vault.ErrNoUI, vault.ErrLocked, vault.ErrNeedRecovery,
		ui.ErrCancelled, platform.ErrRoot,
	}
	usageErrors = []error{sweep.ErrNotMarker}
)

// exitFor maps err to the CLI exit code (SPEC §16.2, docs/API.md §5). A
// joined or wrapped error takes the highest code found anywhere in its
// tree, so a verification failure (5) is never hidden behind an I/O error
// (1) or a live unit (4).
func exitFor(err error) int { return exitCode(err, false) }

// exitForRestore is exitFor for restore and extract paths, where an unsafe
// path or a unit id that does not match its key is a verification failure.
func exitForRestore(err error) int { return exitCode(err, true) }

func exitCode(err error, restore bool) int {
	if err == nil {
		return exitOK
	}
	best := 0
	walkErr(err, func(e error) {
		if c := leafCode(e, restore); c > best {
			best = c
		}
	})
	if best == 0 {
		return exitError
	}
	return best
}

// leafCode returns the exit code one node of an error tree stands for, or
// 0 when the node itself carries no class.
func leafCode(e error, restore bool) int {
	switch v := e.(type) {
	case *ipc.Error:
		return v.ExitCode()
	case *keyDeniedError:
		return v.exitCode()
	case usageError, notProtectedError:
		return exitUsage
	case refusedError:
		return exitLocked
	case shownError:
		return v.code
	}
	comparable := reflect.TypeOf(e).Comparable()
	match := func(list []error) bool {
		for _, s := range list {
			if comparable && e == s {
				return true
			}
			if is, ok := e.(interface{ Is(error) bool }); ok && is.Is(s) {
				return true
			}
		}
		return false
	}
	switch {
	case match(verifyErrors), restore && match(restoreVerifyErrors):
		return exitVerify
	case match(liveErrors):
		return exitLive
	case match(lockedErrors):
		return exitLocked
	case match(usageErrors):
		return exitUsage
	}
	return 0
}

// walkErr visits every node of an error tree (errors.Join and %w chains).
func walkErr(err error, fn func(error)) {
	if err == nil {
		return
	}
	fn(err)
	switch u := err.(type) {
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			walkErr(e, fn)
		}
	case interface{ Unwrap() error }:
		walkErr(u.Unwrap(), fn)
	}
}

// fail prints err for command name (content-free: errors never carry
// plaintext, I7) and returns its exit code. Daemon errors print their
// catalog message; refusals were printed already.
func (a *app) fail(name string, err error) int {
	return a.failWith(name, err, exitFor(err))
}

// failRestore is fail for restore paths (exitForRestore).
func (a *app) failRestore(name string, err error) int {
	return a.failWith(name, err, exitForRestore(err))
}

func (a *app) failWith(name string, err error, code int) int {
	var re refusedError
	var se shownError
	if errors.As(err, &re) || errors.As(err, &se) {
		return code
	}
	var ie *ipc.Error
	if errors.As(err, &ie) && ie.Msg != "" {
		a.say("%s", oneLineText(ie.Msg))
		return code
	}
	if errors.Is(err, ipc.ErrNoDaemon) {
		a.say(textAgentDown)
		return code
	}
	a.say("%s: %s", name, oneLineText(err.Error()))
	return code
}

// oneLineText keeps the first line of s and strips terminal controls.
func oneLineText(s string) string {
	b := ui.SanitizeTerminal([]byte(s))
	for i, c := range b {
		if c == '\n' {
			return string(b[:i])
		}
	}
	return string(b)
}
