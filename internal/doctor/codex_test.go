package doctor_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/codex/codextest"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/testkit"
)

// metaLine is a Codex 0.154 session_meta first line with cwd.
func metaLine(cwd string) string {
	return `{"timestamp":"2026-11-21T09:00:00.000Z","ordinal":0,"type":"session_meta","payload":{"session_id":"00000000-0000-7000-8000-000000000001","id":"00000000-0000-7000-8000-000000000001","cwd":"` + cwd + `","originator":"codex_cli_rs","cli_version":"0.154.0"}}`
}

// userCodexHome writes a synthetic Codex home of the user whose sessions
// ran in ~/work/codextest-workspace, protects that folder and points
// CODEX_HOME at the home.
func (f *fixture) userCodexHome(rollouts int) (*codextest.Home, config.Root) {
	f.t.Helper()
	marker := testkit.Marker(f.t)
	f.secret(marker)
	h := codextest.New(f.t, filepath.Join(f.h.HomeDir, "work", "codex-home"), codextest.Options{Rollouts: rollouts, Marker: marker})
	r := f.h.Protect(f.t, "work/codextest-workspace")
	f.o.Cfg = f.h.Cfg
	f.setEnv("CODEX_HOME", h.Dir)
	return h, r
}

func TestCodexWrongHome(t *testing.T) {
	f := newFixture(t)
	want(t, f.run(), doctor.CheckCodexWrongHome, doctor.OK)

	h, r := f.userCodexHome(2)
	// One more conversation from outside every folder, and one whose first
	// line cannot be read.
	writeFile(t, filepath.Join(h.Dir, "sessions", "2026", "11", "20", "rollout-2026-11-20T10-00-00-00000000-0000-7000-8000-0000000000aa.jsonl"), metaLine(filepath.Join(f.h.Dir, "elsewhere"))+"\n", 0o600)
	writeFile(t, filepath.Join(h.Dir, "archived_sessions", "rollout-2026-11-19T10-00-00-00000000-0000-7000-8000-0000000000bb.jsonl"), "{broken\n", 0o600)
	writeFile(t, filepath.Join(h.Dir, "archived_sessions", "rollout-2026-11-18T10-00-00-00000000-0000-7000-8000-0000000000cc.jsonl.zst"), "\x28\xb5\x2f\xfd", 0o600)
	fs := f.run()
	got := want(t, fs, doctor.CheckCodexWrongHome, doctor.Warn, "2 Codex conversation(s) from "+f.tilde(r.Path)+" were saved in your own Codex history")
	if got.Fix != "precinto run codex" {
		t.Errorf("fix %q", got.Fix)
	}
	want(t, fs, doctor.CheckCodexWrongHome, doctor.Info, "2 conversations in "+f.tilde(h.Dir)+" could not be checked")

	// A folder that does not protect Codex does not count.
	f.o.Cfg.Roots[len(f.o.Cfg.Roots)-1].Harnesses = []string{"claude-code"}
	none(t, f.run(), doctor.CheckCodexWrongHome, doctor.Warn)
}

func TestCodexWrongHomeIgnoresPerRootHomes(t *testing.T) {
	// doctor run from inside `precinto run codex`: CODEX_HOME is a sealed
	// per-root home, not the user's own; ~/.codex is checked instead.
	f := newFixture(t)
	marker := testkit.Marker(t)
	f.secret(marker)
	per := f.h.Layout.CodexHome("root-acme")
	codextest.New(t, per, codextest.Options{Rollouts: 1, Marker: marker})
	f.setEnv("CODEX_HOME", per)
	none(t, f.run(), doctor.CheckCodexWrongHome, doctor.Warn, doctor.Info)
}

// perRootHome writes a sealed Codex home of root-acme with rollouts whose
// cwd is the root.
func (f *fixture) perRootHome(rollouts int) string {
	f.t.Helper()
	marker := testkit.Marker(f.t)
	f.secret(marker)
	dir := f.h.Layout.CodexHome("root-acme")
	codextest.New(f.t, dir, codextest.Options{Rollouts: rollouts, Marker: marker})
	return dir
}

func TestCodexOutsideRuns(t *testing.T) {
	f := newFixture(t)
	none(t, f.run(), doctor.CheckCodexOutsideRuns) // no per-root home
	home := f.perRootHome(2)
	got := want(t, f.run(), doctor.CheckCodexOutsideRuns, doctor.Warn, "2 Codex conversations in the sealed Codex home of "+f.tilde(f.h.Root))
	if !strings.HasSuffix(got.Fix, "precinto codex reconcile --root "+f.tilde(f.h.Root)+" --prefer capsule|plaintext") {
		t.Errorf("fix %q", got.Fix)
	}

	// A held launch lease: a precinto run is active.
	writeFile(t, f.h.Layout.NameSalt, strings.Repeat("s", 32), 0o600)
	salt := []byte(strings.Repeat("s", 32))
	key, err := harness.UnitKeyFor(salt, capsule.KindCodexHome, harness.Codex, "", "root-acme", "")
	if err != nil {
		t.Fatal(err)
	}
	var probed string
	f.d.LeaseHeld = func(k string) (bool, error) { probed = k; return true, nil }
	want(t, f.run(), doctor.CheckCodexOutsideRuns, doctor.OK)
	if probed != key {
		t.Errorf("lease probed for %q, want the codex-home unit key %q", probed, key)
	}
	f.d.LeaseHeld = func(string) (bool, error) { return false, errors.New("probe failed") }
	want(t, f.run(), doctor.CheckCodexOutsideRuns, doctor.OK) // doubt means in use

	// A receipt covering every rollout: they were restored by precinto.
	f.d.LeaseHeld = func(string) (bool, error) { return false, nil }
	var files []sweep.ReceiptFile
	for _, p := range (&codextest.Home{Dir: home}).Rollouts(t) {
		rel, _ := filepath.Rel(home, p)
		files = append(files, sweep.ReceiptFile{Base: capsule.BaseCodexHome, Rel: filepath.ToSlash(rel)})
	}
	f.d.Receipt = func(unit string) (sweep.Receipt, bool, error) {
		if unit != key {
			return sweep.Receipt{}, false, nil
		}
		return sweep.Receipt{Unit: unit, Files: files}, true, nil
	}
	want(t, f.run(), doctor.CheckCodexOutsideRuns, doctor.OK)
	f.d.Receipt = func(string) (sweep.Receipt, bool, error) {
		return sweep.Receipt{Unit: key, Files: files[:1]}, true, nil
	}
	want(t, f.run(), doctor.CheckCodexOutsideRuns, doctor.Warn, "1 Codex conversation in")

	// Files held open by a process: a run is active.
	f.h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 4200, StartUS: 1}, PPID: 1, Exe: "/usr/local/bin/codex"})
	f.h.Procs.SetOpenFiles(4200, filepath.Join(home, "state_5.sqlite"))
	want(t, f.run(), doctor.CheckCodexOutsideRuns, doctor.OK)
	f.h.Procs.SetOpenFiles(4200)

	// A queued seal for that home: the run ended, its seal waits.
	mkdir(t, f.h.Layout.QueueDir, 0o700)
	f.d.QueueList = func() ([]queue.Request, error) {
		return []queue.Request{{ID: "q1", Harness: "codex", ConfigDir: home, Reason: "codex-exit", At: now}}, nil
	}
	want(t, f.run(), doctor.CheckCodexOutsideRuns, doctor.OK)
	f.d.QueueList = func() ([]queue.Request, error) { return nil, nil }

	// An unlocked folder's home is in use by definition.
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) {
		return ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}}}, nil
	}
	want(t, f.run(), doctor.CheckCodexOutsideRuns, doctor.OK)
}

func TestCodexHooksTrust(t *testing.T) {
	f := newFixture(t)
	home := f.perRootHome(0)
	f.d.CodexHooksTrusted = func(h string) (bool, bool, error) { return h != home, true, nil }
	got := want(t, f.run(), doctor.CheckCodexHooksTrust, doctor.Warn, "has not trusted precinto's hooks in the sealed Codex home of "+f.tilde(f.h.Root))
	if !strings.Contains(got.Fix, "/hooks") {
		t.Errorf("fix %q", got.Fix)
	}
	f.d.CodexHooksTrusted = func(h string) (bool, bool, error) { return h == home, true, nil }
	want(t, f.run(), doctor.CheckCodexHooksTrust, doctor.Warn, "in your own Codex home")
	f.d.CodexHooksTrusted = func(string) (bool, bool, error) { return false, false, nil }
	want(t, f.run(), doctor.CheckCodexHooksTrust, doctor.Info, "could not tell")
}

func TestCodexShellNoise(t *testing.T) {
	f := newFixture(t)
	f.setEnv("SHELL", "/bin/zsh")
	var gotShell string
	var gotEnv []string
	f.d.RunShell = func(_ context.Context, shell string, env []string, dir string) (int, time.Duration, error) {
		gotShell, gotEnv = shell, env
		return 12, 30 * time.Millisecond, nil
	}
	// The login profile runs only when a per-root Codex home exists (SPEC
	// §16.1): Codex installed or used outside precinto is not enough.
	f.cellarCodex("0.154.0")
	none(t, f.run(), doctor.CheckCodexShellNoise)
	if gotShell != "" {
		t.Fatalf("%s -lc true ran without a per-root Codex home", gotShell)
	}
	f.perRootHome(0)
	want(t, f.run(), doctor.CheckCodexShellNoise, doctor.Warn, "zsh -lc true prints 12 bytes on stdout")
	if gotShell != "/bin/zsh" || len(gotEnv) == 0 {
		t.Errorf("shell %q env %d", gotShell, len(gotEnv))
	}
	f.d.RunShell = func(context.Context, string, []string, string) (int, time.Duration, error) {
		return 0, 2 * time.Second, nil
	}
	want(t, f.run(), doctor.CheckCodexShellNoise, doctor.Warn, "takes 2.0 s")
	f.d.RunShell = func(context.Context, string, []string, string) (int, time.Duration, error) {
		return 0, 0, context.DeadlineExceeded
	}
	want(t, f.run(), doctor.CheckCodexShellNoise, doctor.Warn, "did not finish")
	f.d.RunShell = func(context.Context, string, []string, string) (int, time.Duration, error) {
		return 0, 0, errors.New("exit 1")
	}
	want(t, f.run(), doctor.CheckCodexShellNoise, doctor.Info, "failed")
}

// TestRunLoginShell runs the real runner on scripts the test owns (never
// the user's shell: it would read real profiles).
func TestRunLoginShell(t *testing.T) {
	dir := t.TempDir()
	noisy := writeFile(t, filepath.Join(dir, "noisy-shell"), "#!/bin/sh\necho 'profile says hi'\n", 0o700)
	quiet := writeFile(t, filepath.Join(dir, "quiet-shell"), "#!/bin/sh\n[ \"$1\" = -lc ] && [ \"$2\" = true ] || exit 3\nexit 0\n", 0o700)
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + dir}
	n, _, err := doctor.RunLoginShell(context.Background(), noisy, env, dir)
	if err != nil || n != len("profile says hi\n") {
		t.Errorf("noisy shell: printed %d, err %v", n, err)
	}
	n, _, err = doctor.RunLoginShell(context.Background(), quiet, env, dir)
	if err != nil || n != 0 {
		t.Errorf("quiet shell: printed %d, err %v (argv must be -lc true)", n, err)
	}
	if _, _, err := doctor.RunLoginShell(context.Background(), "sh", env, dir); err == nil {
		t.Error("a relative shell was run")
	}
}

// cellarCodex installs a fake Homebrew Codex keg and puts it on PATH.
func (f *fixture) cellarCodex(keg string) {
	f.t.Helper()
	dir := filepath.Join(f.h.Dir, "brew-"+keg)
	exe := writeFile(f.t, filepath.Join(dir, "Cellar", "codex", keg, "bin", "codex"), "#!/bin/sh\n", 0o700)
	bin := mkdir(f.t, filepath.Join(dir, "bin"), 0o700)
	if err := os.Symlink(exe, filepath.Join(bin, "codex")); err != nil {
		f.t.Fatal(err)
	}
	f.setEnv("PATH", bin)
}

func TestCodexVersion(t *testing.T) {
	f := newFixture(t)
	f.cellarCodex("0.154.0")
	want(t, f.run(), doctor.CheckCodexVersion, doctor.OK, "0.154.0")

	f = newFixture(t)
	f.cellarCodex("0.154.2_1")
	want(t, f.run(), doctor.CheckCodexVersion, doctor.OK, "0.154.2")

	f = newFixture(t)
	f.cellarCodex("0.160.0")
	want(t, f.run(), doctor.CheckCodexVersion, doctor.Warn, "0.160.0 is outside the versions precinto was verified with (>=0.154.0 <0.155.0)")

	// The inventory's verified range is used when it can be read.
	f = newFixture(t)
	f.cellarCodex("0.154.0")
	f.d.Inventory = func(id string) (harness.Inventory, error) {
		return harness.Inventory{ID: id, VerifiedVersions: ">=0.155.0 <0.156.0"}, nil
	}
	want(t, f.run(), doctor.CheckCodexVersion, doctor.Warn, "(>=0.155.0 <0.156.0)")

	// npm install.
	f = newFixture(t)
	pkg := filepath.Join(f.h.Dir, "npm", "lib", "node_modules", "@openai", "codex")
	js := writeFile(t, filepath.Join(pkg, "bin", "codex.js"), "#!/usr/bin/env node\n", 0o700)
	writeJSON(t, filepath.Join(pkg, "package.json"), map[string]string{"name": "@openai/codex", "version": "0.154.1"})
	bin := mkdir(t, filepath.Join(f.h.Dir, "npm", "bin"), 0o700)
	if err := os.Symlink(js, filepath.Join(bin, "codex")); err != nil {
		t.Fatal(err)
	}
	f.setEnv("PATH", bin)
	want(t, f.run(), doctor.CheckCodexVersion, doctor.OK, "0.154.1")

	// Unknown top-level entries of a sealed home (a new Codex layout).
	f = newFixture(t)
	f.cellarCodex("0.154.0")
	home := f.perRootHome(1)
	mkdir(t, filepath.Join(home, "future_store"), 0o700)
	writeFile(t, filepath.Join(f.h.CodexUser, "skills", "s.md"), "", 0o600)
	if err := os.Symlink(filepath.Join(f.h.CodexUser, "skills"), filepath.Join(home, "skills")); err != nil {
		t.Fatal(err) // PrepareHome links skills/ and plugins/ to the user's home
	}
	writeFile(t, filepath.Join(home, "plugins", "x"), "", 0o600)
	got := want(t, f.run(), doctor.CheckCodexVersion, doctor.Info, "has entries precinto does not know (future_store)")
	if strings.Contains(got.Message, "plugins") || strings.Contains(got.Message, "skills") || strings.Contains(got.Message, "sessions") {
		t.Errorf("known entries reported: %q", got.Message)
	}
}

func TestVersionParsing(t *testing.T) {
	for _, c := range []struct {
		v, r   string
		in, ok bool
	}{
		{"0.154.0", ">=0.154.0 <0.155.0", true, true},
		{"0.154.9", ">=0.154.0 <0.155.0", true, true},
		{"0.155.0", ">=0.154.0 <0.155.0", false, true},
		{"0.155.0-alpha.1", ">=0.154.0 <0.155.0", false, true},
		{"0.154.0-alpha.1", ">=0.154.0", false, true},
		{"2.1.329", "<=2.1.329", true, true},
		{"2.1.330", ">2.1.329", true, true},
		{"2.1.329", "=2.1.329", true, true},
		{"2.1.329", "~2.1", false, false},
		{"2.1.329", "", false, false},
		{"v2.1.329", ">=2.1.295", true, true},
	} {
		in, ok := doctor.VersionInRange(c.v, c.r)
		if in != c.in || ok != c.ok {
			t.Errorf("VersionInRange(%q, %q) = %v, %v; want %v, %v", c.v, c.r, in, ok, c.in, c.ok)
		}
	}
	for _, bad := range []string{"", "2.1", "2.1.x", "a.b.c", "2.1.3.4", "1.2.3 extra"} {
		if _, ok := doctor.ParseVersion(bad); ok {
			t.Errorf("ParseVersion(%q) accepted", bad)
		}
	}
	if doctor.CompareVersions("2.1.295", "2.1.300") >= 0 || doctor.CompareVersions("1.0.0", "1.0.0-rc.1") <= 0 {
		t.Error("version order")
	}
	if v, ok := doctor.VersionOfExecutable("/opt/claude/versions/2.1.329", "x"); !ok || v != "2.1.329" {
		t.Errorf("versioned install: %q %v", v, ok)
	}
}

// An unreadable open-file view (lsof missing, TCC) counts as "in use"
// (D62, HA9): doctor never calls a possibly live run an outside one.
func TestCodexOutsideRunsUnreadableProcessTable(t *testing.T) {
	f := newFixture(t)
	f.perRootHome(1)
	want(t, f.run(), doctor.CheckCodexOutsideRuns, doctor.Warn, "1 Codex conversation in")
	f.h.Procs.SetErr(fakeplatform.OpOpenFilesUnder, errors.New("lsof not found"))
	want(t, f.run(), doctor.CheckCodexOutsideRuns, doctor.OK)
	f.o.Procs = nil
	want(t, f.run(), doctor.CheckCodexOutsideRuns, doctor.OK)
}
