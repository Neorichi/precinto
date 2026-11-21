package doctor_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/sweep"
)

// UX-17, D113 (group w): sweeps never seal sessions found only by their
// transcripts' cwd, so doctor's fix for a locked folder holding them is
// seal --adopt, the command status names too, not precinto sweep.
func TestUnsealedAdoptedNamesSealAdopt(t *testing.T) {
	f := newFixture(t)
	f.d.Plaintext = func(context.Context) ([]sweep.Plaintext, error) {
		return []sweep.Plaintext{{RootID: "root-acme", Files: 2, Bytes: 600, ByReason: map[string]int{"adopted": 1, "deferred": 1}}}, nil
	}
	got := want(t, f.run(), doctor.CheckUnsealed, doctor.Warn, "adopted 1, deferred 1")
	if fix := "precinto seal --adopt --root " + f.tilde(f.h.Root); got.Fix != fix {
		t.Errorf("fix %q, want %q", got.Fix, fix)
	}
}

// The folder in that fix is one shell word, and only a configured folder
// is named with --root (the global vault is no folder).
func TestUnsealedAdoptedFixIsOneShellWord(t *testing.T) {
	f := newFixture(t)
	spaced := filepath.Join(f.h.HomeDir, "My Work", "it's")
	f.o.Cfg.Roots = append(f.o.Cfg.Roots, config.Root{ID: "root-spaced", Path: spaced})
	f.d.Plaintext = func(context.Context) ([]sweep.Plaintext, error) {
		return []sweep.Plaintext{{RootID: "root-spaced", Files: 1, Bytes: 10, ByReason: map[string]int{"adopted": 1}}}, nil
	}
	got := want(t, f.run(), doctor.CheckUnsealed, doctor.Warn, "adopted 1")
	arg := doctor.ShellArg(f.h.HomeDir, spaced)
	if !strings.HasPrefix(arg, "'") || got.Fix != "precinto seal --adopt --root "+arg {
		t.Errorf("fix %q, want the folder quoted as one word (%s)", got.Fix, arg)
	}
	f = newFixture(t)
	f.d.Plaintext = func(context.Context) ([]sweep.Plaintext, error) {
		return []sweep.Plaintext{{RootID: "global", Files: 1, Bytes: 10, ByReason: map[string]int{"adopted": 1}}}, nil
	}
	if got := want(t, f.run(), doctor.CheckUnsealed, doctor.Warn, "adopted 1"); strings.Contains(got.Fix, "--root") {
		t.Errorf("fix %q names --root for the global vault", got.Fix)
	}
}
