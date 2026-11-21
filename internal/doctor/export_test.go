package doctor

// Test-only access to doctor's seams and unexported helpers (compiled into
// the test binary only; the external tests in package doctor_test use
// them).

import (
	"context"
	"io"
)

// Deps is the dependency set of a Run (see deps).
type Deps = deps

// RunWith runs doctor with explicit dependencies.
func RunWith(ctx context.Context, o Options, d *Deps) ([]Finding, error) { return run(ctx, o, d) }

// DefaultDeps returns the production dependencies of o (crossgroup tests
// replace the OS facilities and keep the rest).
func DefaultDeps(o Options) *Deps { return defaultDeps(o) }

// InternalErrorText is the message of a check that panicked.
const InternalErrorText = internalErrorText

// HardenedRuntime exposes the Mach-O code-signature reader.
func HardenedRuntime(path string) (hardened, signed, known bool, err error) {
	return hardenedRuntime(path)
}

// VersionInRange parses v and reports whether it satisfies range r.
func VersionInRange(v, r string) (in, ok bool) {
	pv, okV := parseVersion(v)
	if !okV {
		return false, false
	}
	return inRange(pv, r)
}

// ParseVersion reports the canonical form of a version string.
func ParseVersion(s string) (string, bool) {
	v, ok := parseVersion(s)
	if !ok {
		return "", false
	}
	return v.String(), true
}

// CompareVersions orders two versions (both must parse).
func CompareVersions(a, b string) int {
	va, _ := parseVersion(a)
	vb, _ := parseVersion(b)
	return va.compare(vb)
}

// VersionOfExecutable exposes the install-layout version reader.
func VersionOfExecutable(exe, pkg string) (string, bool) {
	v, ok := versionOfExecutable(exe, pkg)
	if !ok {
		return "", false
	}
	return v.String(), true
}

// ShellArg exposes the fix-command quoting.
func ShellArg(home, p string) string { return shellArg(home, p) }

// OneLine exposes the message sanitizer.
func OneLine(s string) string { return oneLine(s) }

// WriteHuman and WriteJSON are Render's two forms.
func WriteHuman(w io.Writer, fs []Finding) error { return Render(w, fs, false) }
func WriteJSON(w io.Writer, fs []Finding) error  { return Render(w, fs, true) }

// RunLoginShell exposes the real `$SHELL -lc true` runner.
var RunLoginShell = runLoginShell
