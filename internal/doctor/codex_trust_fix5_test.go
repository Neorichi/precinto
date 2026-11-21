package doctor_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/harness/codex"
)

// D99, D98 (M2, M3): doctor names why Codex runs none of precinto's hooks.
// A home that does not load precinto's plugin is fixed by integrate (and
// sync-config), never by /hooks, which cannot list those hooks; hooks
// trusted for other declarations need a review in /hooks.
func TestCodexHooksTrustNamesTheCause(t *testing.T) {
	f := newFixture(t)
	home := f.perRootHome(0)
	folder := f.tilde(f.h.Root)
	state := func(perRoot, own error) {
		f.d.CodexHooksTrusted = func(h string) (bool, bool, error) {
			err := own
			if h == home {
				err = perRoot
			}
			return err == nil, true, err
		}
	}
	state(codex.ErrPluginMissing, nil)
	got := want(t, f.run(), doctor.CheckCodexHooksTrust, doctor.Warn, "the sealed Codex home of "+folder+" does not load precinto's Codex plugin")
	if !strings.Contains(got.Fix, "precinto integrate codex") || !strings.Contains(got.Fix, "precinto codex sync-config --root "+folder) || strings.Contains(got.Fix, "/hooks") {
		t.Errorf("plugin missing: fix %q", got.Fix)
	}
	state(codex.ErrHooksModified, nil)
	got = want(t, f.run(), doctor.CheckCodexHooksTrust, doctor.Warn, "trusted another version of precinto's hooks in the sealed Codex home of "+folder,
		"if it is a verified version (precinto could not tell its version)")
	if !strings.Contains(got.Fix, "/hooks") || !strings.Contains(got.Fix, "again") {
		t.Errorf("modified: fix %q", got.Fix)
	}
	state(nil, codex.ErrPluginMissing)
	got = want(t, f.run(), doctor.CheckCodexHooksTrust, doctor.Warn, "your own Codex home", "does not load precinto's Codex plugin")
	if got.Fix != "precinto integrate codex" {
		t.Errorf("own home without the plugin: fix %q", got.Fix)
	}
	state(nil, codex.ErrHooksModified)
	want(t, f.run(), doctor.CheckCodexHooksTrust, doctor.Warn, "another version of precinto's hooks in your own Codex home")

	// The real check on a sealed home seeded before `precinto integrate
	// codex` (its config enables no precinto plugin).
	f.d.CodexHooksTrusted = codex.HooksTrusted
	want(t, f.run(), doctor.CheckCodexHooksTrust, doctor.Warn, "the sealed Codex home of "+folder+" does not load precinto's Codex plugin")
}

// D99: directories PrepareHome moved out of a sealed home (never deleted)
// are reported with the place they are kept.
func TestCodexDisplacedDirectoriesReported(t *testing.T) {
	f := newFixture(t)
	f.cellarCodex("0.154.0")
	home := f.perRootHome(0)
	want(t, f.run(), doctor.CheckCodexVersion, doctor.OK, "0.154.0")
	mkdir(t, filepath.Join(home+".displaced", "plugins-20261121T090000.000000000Z", "cache"), 0o700)
	got := want(t, f.run(), doctor.CheckCodexVersion, doctor.Info, "1 directory that Codex had created in the sealed Codex home of "+f.tilde(f.h.Root)+" was moved to")
	if !strings.Contains(got.Fix, ".displaced") {
		t.Errorf("fix %q", got.Fix)
	}
}

// D98: trust hashes are Codex 0.154's, so only a verified Codex is known
// to skip hooks whose trust entries hold other hashes. For a Codex doctor
// finds outside the verified versions it says it cannot tell (no
// warning); for a verified one it warns plainly.
func TestCodexModifiedTrustDependsOnTheCodexVersion(t *testing.T) {
	for _, tc := range []struct {
		keg  string
		sev  doctor.Severity
		text []string
		not  string
	}{
		{"0.154.0", doctor.Warn, []string{"trusted another version of precinto's hooks in the sealed Codex home of", "and skips them until you review them"}, "if it is a verified version"},
		{"0.160.0", doctor.Info, []string{"Codex 0.160.0 is outside the versions precinto was verified with", "cannot tell whether it runs precinto's hooks in the sealed Codex home of"}, "skips them"},
	} {
		f := newFixture(t)
		f.cellarCodex(tc.keg)
		home := f.perRootHome(0)
		f.d.CodexHooksTrusted = func(h string) (bool, bool, error) {
			if h == home {
				return false, true, codex.ErrHooksModified
			}
			return true, true, nil
		}
		fs := f.run()
		got := want(t, fs, doctor.CheckCodexHooksTrust, tc.sev, tc.text...)
		if strings.Contains(got.Message, tc.not) || !strings.Contains(got.Fix, "/hooks") {
			t.Errorf("Codex %s: %q, fix %q", tc.keg, got.Message, got.Fix)
		}
		for _, fd := range fs {
			if fd.Code == doctor.CheckCodexHooksTrust && fd.Severity == doctor.Warn && tc.sev == doctor.Info {
				t.Errorf("Codex %s: unexpected warning %q", tc.keg, fd.Message)
			}
		}
	}
}
