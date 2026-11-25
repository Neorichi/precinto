package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/sweep"
	"github.com/Neorichi/precinto/internal/sweep/capslog"
	"github.com/Neorichi/precinto/internal/ui"
	"github.com/Neorichi/precinto/internal/vault"
)

// The table of docs/API.md §5 (SPEC §16.2).
func TestExitCodeTable(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, exitOK},
		{usageErrorf("bad"), exitUsage},
		{&ipc.Error{Code: ipc.CodeBadRequest}, exitUsage},
		{sweep.ErrNotMarker, exitUsage},
		{&ipc.Error{Code: ipc.CodeLocked}, exitLocked},
		{&ipc.Error{Code: ipc.CodeUnauthorized}, exitLocked},
		{&ipc.Error{Code: ipc.CodeAgentContext}, exitLocked},
		{&ipc.Error{Code: ipc.CodeCancelled}, exitLocked},
		{&ipc.Error{Code: ipc.CodeNoUI}, exitLocked},
		{&ipc.Error{Code: ipc.CodeRateLimited}, exitLocked},
		{&ipc.Error{Code: ipc.CodeBadSecret}, exitLocked},
		{sweep.ErrKeyDenied, exitLocked},
		{vault.ErrCancelled, exitLocked},
		{vault.ErrBadSecret, exitLocked},
		{vault.ErrNoUI, exitLocked},
		{vault.ErrLocked, exitLocked},
		{vault.ErrNeedRecovery, exitLocked},
		{ui.ErrCancelled, exitLocked},
		{platform.ErrRoot, exitLocked},
		{sweep.ErrLive, exitLive},
		{capsule.ErrChanged, exitLive},
		{sweep.ErrConflict, exitLive},
		{&ipc.Error{Code: ipc.CodeLive}, exitLive},
		{capsule.ErrVerify, exitVerify},
		{capsule.ErrHeader, exitVerify},
		{capsule.ErrRecipients, exitVerify},
		{capsule.ErrFormat, exitVerify},
		{capsule.ErrUnsafe, exitVerify},
		{capsule.ErrTooLarge, exitVerify},
		{vault.ErrMACMismatch, exitVerify},
		{vault.ErrRecipientsChanged, exitVerify},
		{sweep.ErrTripwire, exitVerify},
		{vault.ErrWrongIdentity, exitVerify},
		{vault.ErrPluginPin, exitVerify},
		{capslog.ErrNotLogged, exitVerify},
		{sweep.ErrNotLogged, exitVerify},
		{&ipc.Error{Code: ipc.CodeVerify}, exitVerify},
		{&ipc.Error{Code: ipc.CodeNotLogged}, exitVerify},
		{ipc.ErrUntrustedServer, exitError},
		{ipc.ErrNoDaemon, exitError},
		{sweep.ErrInaccessible, exitError},
		{errors.New("io"), exitError},
		{&ipc.Error{Code: ipc.CodeInternal}, exitError},
		{&ipc.Error{Code: ipc.CodeVersion}, exitError},
		// Outside restore, an unsafe precinto directory is an error.
		{fsx.ErrUnsafe, exitError},
		{harness.ErrUnitKey, exitError},
		{refusedError{reason: "x"}, exitLocked},
		{notProtectedError{dir: "~/x"}, exitUsage},
	}
	for _, c := range cases {
		if got := exitFor(c.err); got != c.want {
			t.Errorf("exitFor(%v) = %d, want %d", c.err, got, c.want)
		}
		if got := exitFor(fmt.Errorf("wrapped: %w", c.err)); c.err != nil && got != c.want {
			t.Errorf("exitFor(wrapped %v) = %d, want %d", c.err, got, c.want)
		}
	}
}

// From restore and extract, an unsafe path or a unit id that does not
// match its key is a verification failure (docs/API.md §5).
func TestExitCodeRestore(t *testing.T) {
	for _, err := range []error{fsx.ErrUnsafe, harness.ErrUnitKey, fmt.Errorf("x: %w", fsx.ErrUnsafe)} {
		if got := exitForRestore(err); got != exitVerify {
			t.Errorf("exitForRestore(%v) = %d, want 5", err, got)
		}
	}
	if got := exitForRestore(sweep.ErrLive); got != exitLive {
		t.Errorf("exitForRestore(ErrLive) = %d", got)
	}
}

// A joined error takes its most severe code: a verification failure is
// never hidden behind an I/O error or a live unit.
func TestExitCodeJoinedTakesMostSevere(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{errors.Join(errors.New("io"), sweep.ErrLive), exitLive},
		{errors.Join(sweep.ErrLive, capsule.ErrVerify), exitVerify},
		{errors.Join(&ipc.Error{Code: ipc.CodeLocked}, errors.New("io")), exitLocked},
		{errors.Join(fmt.Errorf("a: %w", errors.Join(errors.New("x"), vault.ErrMACMismatch))), exitVerify},
		{errors.Join(errors.New("a"), errors.New("b")), exitError},
	}
	for _, c := range cases {
		if got := exitFor(c.err); got != c.want {
			t.Errorf("exitFor(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

// keyDeniedError keeps the daemon's code: a provenance refusal stays 5.
func TestKeyDeniedExitCodes(t *testing.T) {
	if got := exitFor(&keyDeniedError{codes: []ipc.Code{ipc.CodeLocked}}); got != exitLocked {
		t.Errorf("locked denial = %d", got)
	}
	if got := exitFor(&keyDeniedError{codes: []ipc.Code{ipc.CodeLocked, ipc.CodeNotLogged}}); got != exitVerify {
		t.Errorf("not_logged denial = %d", got)
	}
	if !errors.Is(&keyDeniedError{}, sweep.ErrKeyDenied) {
		t.Error("keyDeniedError does not match sweep.ErrKeyDenied")
	}
	if got := exitFor(&keyDeniedError{cause: ipc.ErrNoDaemon}); got != exitLocked {
		t.Errorf("no daemon denial = %d", got)
	}
}

// An uncomparable error value never panics the mapping.
type sliceErr []string

func (s sliceErr) Error() string { return "slice" }

func TestExitCodeUncomparableError(t *testing.T) {
	if got := exitFor(sliceErr{"a"}); got != exitError {
		t.Errorf("got %d", got)
	}
}

func TestFailPrintsDaemonMessage(t *testing.T) {
	e := newEnv(t)
	a := e.app()
	code := a.fail("unlock", &ipc.Error{Code: ipc.CodeAgentContext, Msg: "precinto: refusing to unlock ~/b from inside an AI agent session.\x1b[31m"})
	if code != exitLocked {
		t.Fatalf("code %d", code)
	}
	if got := e.stderr(); got != "precinto: refusing to unlock ~/b from inside an AI agent session.[31m\n" {
		t.Fatalf("stderr %q (controls must be stripped)", got)
	}
}

func TestOneLineText(t *testing.T) {
	if got := oneLineText("a\x07b\nsecond"); got != "ab" {
		t.Fatalf("got %q", got)
	}
}
