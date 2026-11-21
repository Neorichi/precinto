package sweep

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/vault"
)

// Failure codes carried at the start of UnitResult.Detail ("<code>: …").
// Report.Err maps them back to the sentinel errors cmd/precinto turns into
// exit codes; a Detail without a known code is informational only (for
// example the evidence of a unit a sweep found live). Details never hold
// paths or content (I7).
const (
	codeLive          = "live"
	codeTripwire      = "tripwire"
	codeMAC           = "mac"
	codeWrongIdentity = "wrong-identity"
	codePluginPin     = "plugin-pin"
	codeVerify        = "verify"
	codeHeader        = "header"
	codeRecipients    = "recipients"
	codeFormat        = "format"
	codeUnsafe        = "unsafe"
	codeTooLarge      = "too-large"
	codeNotLogged     = "not-logged"
	codeUnitKey       = "unit-key"
	codeUnregistered  = "unregistered" // no registered home: a configuration gap, exit 1, never 5 (D109)
	codeKeyDenied     = "key-denied"
	codeNoSpace       = "no-space"
	codeInaccessible  = "inaccessible"
	codeConflict      = "conflict"
	codeChanged       = "changed"
	codeFailed        = "failed"
)

// codeErrors maps a failure code to the sentinel Report.Err wraps.
var codeErrors = map[string]error{
	codeLive:          ErrLive,
	codeTripwire:      ErrTripwire,
	codeMAC:           vault.ErrMACMismatch,
	codeWrongIdentity: vault.ErrWrongIdentity,
	codePluginPin:     vault.ErrPluginPin,
	codeVerify:        capsule.ErrVerify,
	codeHeader:        capsule.ErrHeader,
	codeRecipients:    capsule.ErrRecipients,
	codeFormat:        capsule.ErrFormat,
	codeUnsafe:        capsule.ErrUnsafe,
	codeTooLarge:      capsule.ErrTooLarge,
	codeNotLogged:     ErrNotLogged,
	codeUnitKey:       harness.ErrUnitKey,
	codeUnregistered:  harness.ErrUnregistered,
	codeKeyDenied:     ErrKeyDenied,
	codeNoSpace:       ErrNoSpace,
	codeInaccessible:  ErrInaccessible,
	codeConflict:      ErrConflict,
	codeChanged:       capsule.ErrChanged,
}

// Count returns the number of units with outcome o.
func (r *Report) Count(o Outcome) int {
	if r == nil {
		return 0
	}
	n := 0
	for _, u := range r.Units {
		if u.Outcome == o {
			n++
		}
	}
	return n
}

// Err summarizes failures as one error (nil if none). Live, warm and
// leased units are failures (ErrLive, exit 4) only for an explicit Seal of
// named units (their Detail carries the live code); sweeps report them as
// outcomes and exit 0.
func (r *Report) Err() error {
	if r == nil {
		return nil
	}
	var errs []error
	for _, u := range r.Units {
		code, rest, _ := strings.Cut(u.Detail, ": ")
		if sentinel, ok := codeErrors[code]; ok {
			errs = append(errs, fmt.Errorf("%w (%s unit %s: %s)", sentinel, u.Kind, short(u.Unit), rest))
			continue
		}
		if u.Outcome == OutFailed {
			errs = append(errs, fmt.Errorf("sweep: %s unit %s failed (%s)", u.Kind, short(u.Unit), u.Detail))
		}
	}
	return errors.Join(errs...)
}

// short abbreviates a unit key for messages.
func short(unit string) string {
	if len(unit) > 12 {
		return unit[:12]
	}
	return unit
}

// failureCode classifies err into a failure code and an fsx error class.
// It never inspects error strings, only sentinels and errnos.
func failureCode(err error) (string, fsx.Class) {
	switch {
	case err == nil:
		return "", fsx.ClassNone
	case errors.Is(err, vault.ErrRecipientsChanged):
		return codeTripwire, fsx.ClassOther
	case errors.Is(err, vault.ErrMACMismatch):
		return codeMAC, fsx.ClassOther
	case errors.Is(err, vault.ErrWrongIdentity):
		return codeWrongIdentity, fsx.ClassOther
	case errors.Is(err, vault.ErrPluginPin):
		return codePluginPin, fsx.ClassOther
	case errors.Is(err, capsule.ErrVerify):
		return codeVerify, fsx.ClassOther
	case errors.Is(err, capsule.ErrHeader):
		return codeHeader, fsx.ClassOther
	case errors.Is(err, capsule.ErrRecipients):
		return codeRecipients, fsx.ClassOther
	case errors.Is(err, capsule.ErrFormat):
		return codeFormat, fsx.ClassOther
	case errors.Is(err, capsule.ErrTooLarge):
		return codeTooLarge, fsx.ClassOther
	case errors.Is(err, capsule.ErrUnsafe), errors.Is(err, fsx.ErrUnsafe), errors.Is(err, syscall.ELOOP):
		return codeUnsafe, fsx.ClassUnsafe
	case errors.Is(err, capslog.ErrNotLogged):
		return codeNotLogged, fsx.ClassOther
	case errors.Is(err, harness.ErrUnregistered):
		return codeUnregistered, fsx.ClassOther
	case errors.Is(err, harness.ErrUnitKey):
		return codeUnitKey, fsx.ClassOther
	case errors.Is(err, ErrKeyDenied):
		return codeKeyDenied, fsx.ClassOther
	case errors.Is(err, capsule.ErrChanged), errors.Is(err, fsx.ErrChanged):
		return codeChanged, fsx.ClassOther
	case errors.Is(err, ErrLive), errors.Is(err, live.ErrLeaseHeld):
		return codeLive, fsx.ClassOther
	case errors.Is(err, ErrConflict):
		return codeConflict, fsx.ClassOther
	case errors.Is(err, journal.ErrConflict), errors.Is(err, fsx.ErrLocked):
		return codeFailed, fsx.ClassBusy
	}
	class := classOf(err)
	switch class {
	case fsx.ClassNoSpace:
		return codeNoSpace, class
	case fsx.ClassAccess, fsx.ClassReadOnly:
		return codeInaccessible, class
	}
	return codeFailed, class
}

// classOf maps err to an fsx.Class from sentinels and errnos (SPEC §17).
// EPERM and EACCES are never "missing".
func classOf(err error) fsx.Class {
	var errno syscall.Errno
	switch {
	case err == nil:
		return fsx.ClassNone
	case errors.Is(err, ErrNoSpace), errors.Is(err, fsx.ErrNoSpace):
		return fsx.ClassNoSpace
	case errors.Is(err, ErrInaccessible):
		return fsx.ClassAccess
	case errors.Is(err, fsx.ErrUnsafe), errors.Is(err, fsx.ErrHardlink):
		return fsx.ClassUnsafe
	case errors.Is(err, fsx.ErrLocked):
		return fsx.ClassBusy
	case errors.As(err, &errno):
		switch errno {
		case syscall.ENOSPC, syscall.EDQUOT, syscall.EFBIG:
			return fsx.ClassNoSpace
		case syscall.EACCES, syscall.EPERM:
			return fsx.ClassAccess
		case syscall.ENOENT, syscall.ENOTDIR:
			return fsx.ClassMissing
		case syscall.EBUSY, syscall.ETXTBSY, syscall.EDEADLK, syscall.EAGAIN:
			return fsx.ClassBusy
		case syscall.ELOOP, syscall.EMLINK:
			return fsx.ClassUnsafe
		case syscall.EROFS:
			return fsx.ClassReadOnly
		}
		return fsx.ClassIO
	case errors.Is(err, fs.ErrPermission):
		return fsx.ClassAccess
	case errors.Is(err, fs.ErrNotExist):
		return fsx.ClassMissing
	}
	return fsx.ClassOther
}

// isMissing reports a vanished file (never EPERM/EACCES).
func isMissing(err error) bool { return classOf(err) == fsx.ClassMissing }

// isAccess reports EACCES/EPERM (including macOS TCC denials).
func isAccess(err error) bool {
	c := classOf(err)
	return c == fsx.ClassAccess || c == fsx.ClassReadOnly
}

// safeMsg renders err without file paths: for path errors only the
// operation and the errno are kept, for everything else only sentinels
// (I7: errors never carry content, and paths stay out of reports).
func safeMsg(err error) string {
	if err == nil {
		return ""
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Op + ": " + le.Err.Error()
	}
	var se *os.SyscallError
	if errors.As(err, &se) {
		return se.Syscall + ": " + se.Err.Error()
	}
	for _, s := range []error{
		ErrLive, ErrConflict, ErrNoSpace, ErrNotLogged, ErrKeyDenied, ErrTripwire, ErrInaccessible,
		capsule.ErrVerify, capsule.ErrHeader, capsule.ErrRecipients, capsule.ErrFormat, capsule.ErrUnsafe,
		capsule.ErrTooLarge, capsule.ErrChanged, fsx.ErrUnsafe, fsx.ErrChanged, fsx.ErrExist, fsx.ErrLocked,
		fsx.ErrNoSpace, fsx.ErrHardlink, harness.ErrUnitKey, harness.ErrUnregistered, journal.ErrConflict,
		vault.ErrMACMismatch, vault.ErrWrongIdentity, vault.ErrPluginPin, live.ErrLeaseHeld,
	} {
		if errors.Is(err, s) {
			return s.Error()
		}
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	return "error"
}

// failDetail is the Detail of a failed unit: "<code>: <safe message>".
func failDetail(err error) string {
	code, _ := failureCode(err)
	return code + ": " + safeMsg(err)
}
