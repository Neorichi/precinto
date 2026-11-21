package doctor_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
)

func TestServiceRunningAgent(t *testing.T) {
	f := newFixture(t)
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) { return ipc.StatusResp{}, ipc.ErrUntrustedServer }
	got := want(t, f.run(), doctor.CheckServiceRunning, doctor.Fail, "not this precinto binary")
	if got.Fix != "precinto agent --restart" {
		t.Errorf("fix %q", got.Fix)
	}
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) { return ipc.StatusResp{}, context.DeadlineExceeded }
	want(t, f.run(), doctor.CheckServiceRunning, doctor.Warn, "did not answer within 2s")
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) { return ipc.StatusResp{}, errors.New("protocol") }
	want(t, f.run(), doctor.CheckServiceRunning, doctor.Warn, "could not be asked")
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) { return ipc.StatusResp{PID: 7}, nil }
	none(t, f.run(), doctor.CheckServiceRunning, doctor.Warn, doctor.Fail)
}

func TestServiceRunningSocket(t *testing.T) {
	f := newFixture(t)
	if err := os.Chmod(f.h.RunDir, 0o755); err != nil {
		t.Fatal(err)
	}
	got := want(t, f.run(), doctor.CheckAgentSocket, doctor.Fail, "socket folder", "mode 0755")
	if got.Fix != "chmod 700 "+f.h.RunDir {
		t.Errorf("fix %q", got.Fix)
	}
	if err := os.Chmod(f.h.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// A regular file squatting the socket path.
	writeFile(t, f.h.Layout.Socket, "", 0o600)
	want(t, f.run(), doctor.CheckAgentSocket, doctor.Fail, "is not a socket")
	os.Remove(f.h.Layout.Socket)

	// A socket nobody listens on: stale, replaced at the next start.
	l, err := net.Listen("unix", f.h.Layout.Socket)
	if err != nil {
		t.Skip("unix socket:", err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if err := os.Chmod(f.h.Layout.Socket, 0o755); err != nil {
		t.Fatal(err)
	}
	want(t, f.run(), doctor.CheckAgentSocket, doctor.Fail, "can be used by other users")
	if err := os.Chmod(f.h.Layout.Socket, 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, f.run(), doctor.CheckAgentSocket, doctor.Info, "stale agent socket")
}

func TestServiceRunningPermissions(t *testing.T) {
	f := newFixture(t)
	state := f.h.Layout.StateDir
	if err := os.Chmod(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.h.Layout.CapsulesDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.h.Layout.ConfigFile, 0o644); err != nil {
		t.Fatal(err)
	}
	vfile := writeFile(t, filepath.Join(f.h.Layout.VaultDir("root-acme"), "vault.toml"), "format = 1\n", 0o644)
	if err := os.RemoveAll(f.h.Layout.LocksDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.h.Dir, f.h.Layout.LocksDir); err != nil {
		t.Fatal(err)
	}
	fs := f.run()
	got := want(t, fs, doctor.CheckPermissions, doctor.Warn, f.h.Layout.StateDir+" can be read by other users (mode 0755)")
	if got.Fix != "chmod 700 "+state {
		t.Errorf("fix %q", got.Fix)
	}
	want(t, fs, doctor.CheckPermissions, doctor.Fail, f.h.Layout.CapsulesDir+" can be changed by other users (mode 0777)")
	want(t, fs, doctor.CheckPermissions, doctor.Warn, "config.toml can be read by other users (mode 0644)")
	want(t, fs, doctor.CheckPermissions, doctor.Warn, vfile+" can be read by other users")
	got = want(t, fs, doctor.CheckPermissions, doctor.Fail, f.h.Layout.LocksDir+" is a symbolic link")
	if !strings.HasPrefix(got.Fix, "move ") {
		t.Errorf("fix %q", got.Fix)
	}
}

// UX-05: vaults/ holds the vault folders and, next to them, the lock files
// that serialize vault.toml rewrites (.<id>.lock, never deleted). A lock
// file is one of precinto's private files, never a broken vault folder, and
// doctor never advises moving one aside (a process holding the old inode
// would no longer exclude the next writer).
func TestPermissionsVaultLockFiles(t *testing.T) {
	f := newFixture(t)
	mkdir(t, f.h.Layout.VaultDir("global"), 0o700)
	mkdir(t, f.h.Layout.VaultDir("root-acme"), 0o700)
	global := writeFile(t, filepath.Join(f.h.Layout.VaultsDir, ".global.lock"), "", 0o600)
	acme := writeFile(t, filepath.Join(f.h.Layout.VaultsDir, ".root-acme.lock"), "", 0o600)
	none(t, f.run(), doctor.CheckPermissions, doctor.Warn, doctor.Fail)

	if err := os.Chmod(acme, 0o644); err != nil {
		t.Fatal(err)
	}
	fs := f.run()
	got := want(t, fs, doctor.CheckPermissions, doctor.Warn, acme+" can be read by other users (mode 0644)")
	if got.Fix != "chmod 600 "+acme {
		t.Errorf("fix %q", got.Fix)
	}
	if err := os.Chmod(global, 0o666); err != nil {
		t.Fatal(err)
	}
	fs = f.run()
	want(t, fs, doctor.CheckPermissions, doctor.Fail, global+" can be changed by other users (mode 0666)")
	for _, x := range of(fs, doctor.CheckPermissions) {
		if strings.Contains(x.Message, "is not a directory") || strings.Contains(x.Fix, "aside") {
			t.Errorf("a vault lock file reported as a vault folder: %q (fix %q)", x.Message, x.Fix)
		}
	}
	// A lock file that is not a regular file is reported, with a fix that
	// waits for precinto to stop instead of moving it aside.
	if err := os.Remove(acme); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.h.Dir, acme); err != nil {
		t.Fatal(err)
	}
	got = want(t, f.run(), doctor.CheckPermissions, doctor.Fail, acme+" is a symbolic link")
	if strings.Contains(got.Fix, "aside") || !strings.Contains(got.Fix, "no precinto command") {
		t.Errorf("fix %q", got.Fix)
	}
	// A crashed vault creation's staging folder (.<id>.new-…) is no vault,
	// whatever its mode.
	mkdir(t, filepath.Join(f.h.Layout.VaultsDir, ".root-new.new-0a1b2c"), 0o755)
	for _, x := range of(f.run(), doctor.CheckPermissions) {
		if strings.Contains(x.Message, ".root-new.new-") {
			t.Errorf("an interrupted vault creation reported as a vault folder: %q", x.Message)
		}
	}
}

// CC-34: state/hookdedupe and state/notes.json are precinto's own paths
// and must be private too.
func TestPermissionsHookDedupeAndNotesIndex(t *testing.T) {
	f := newFixture(t)
	dedupe := mkdir(t, f.h.Layout.HookDedupeDir, 0o700)
	notes := writeFile(t, f.h.Layout.NotesIndex, "{}", 0o600)
	none(t, f.run(), doctor.CheckPermissions, doctor.Warn, doctor.Fail)

	if err := os.Chmod(dedupe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(notes, 0o644); err != nil {
		t.Fatal(err)
	}
	fs := f.run()
	got := want(t, fs, doctor.CheckPermissions, doctor.Warn, dedupe+" can be read by other users (mode 0755)")
	if got.Fix != "chmod 700 "+dedupe {
		t.Errorf("fix %q", got.Fix)
	}
	got = want(t, fs, doctor.CheckPermissions, doctor.Warn, notes+" can be read by other users (mode 0644)")
	if got.Fix != "chmod 600 "+notes {
		t.Errorf("fix %q", got.Fix)
	}
}

func TestServiceRunningSweeps(t *testing.T) {
	f := newFixture(t)
	f.d.GOOS = "darwin"
	got := want(t, f.run(), doctor.CheckServiceRunning, doctor.Info, "background sealing is not installed")
	if got.Fix != "precinto service install" {
		t.Errorf("fix %q", got.Fix)
	}
	// Only precinto's own label counts (paths.ServiceLabel, CC-37): another
	// plist whose name mentions precinto is not the service.
	writeFile(t, filepath.Join(f.h.HomeDir, "Library", "LaunchAgents", "dev.precinto.sweep.plist"), "<plist/>", 0o644)
	want(t, f.run(), doctor.CheckServiceRunning, doctor.Info, "background sealing is not installed")
	writeFile(t, filepath.Join(f.h.HomeDir, "Library", "LaunchAgents", paths.ServiceLabel+".plist"), "<plist/>", 0o644)
	want(t, f.run(), doctor.CheckServiceRunning, doctor.Warn, "never completed a sweep")
	writeFile(t, f.h.Layout.SweepLast, "", 0o600)
	setMtime(t, f.h.Layout.SweepLast, 2*time.Hour)
	want(t, f.run(), doctor.CheckServiceRunning, doctor.Warn, "last completed a sweep 2 hours ago")
	setMtime(t, f.h.Layout.SweepLast, 5*time.Minute)
	none(t, f.run(), doctor.CheckServiceRunning, doctor.Warn)

	// A requested sweep that never ran.
	writeFile(t, f.h.Layout.SweepRequested, "", 0o600)
	setMtime(t, f.h.Layout.SweepLast, 3*time.Hour)
	setMtime(t, f.h.Layout.SweepRequested, 2*time.Hour)
	want(t, f.run(), doctor.CheckServiceRunning, doctor.Warn, "a sweep was requested 2 hours ago")

	// linux has no service (D49): nothing about it.
	g := newFixture(t)
	g.d.GOOS = "linux"
	for _, x := range of(g.run(), doctor.CheckServiceRunning) {
		if x.Severity != doctor.OK && strings.Contains(x.Message, "background sealing") {
			t.Errorf("linux: %q", x.Message)
		}
	}
}

func TestServiceRunningStuckLock(t *testing.T) {
	f := newFixture(t)
	lock := writeFile(t, f.h.Layout.LockFile("sweep"), "", 0o600)
	f.h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 4300, StartUS: now.Add(-3 * time.Hour).UnixMicro()}, PPID: 1, Exe: "/usr/local/bin/precinto"})
	f.h.Procs.SetOpenFiles(4300, lock)
	want(t, f.run(), doctor.CheckServiceRunning, doctor.Warn, "sweep lock has been held for 3 hours by pid 4300")
	f.h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 4300, StartUS: now.Add(-time.Minute).UnixMicro()}, PPID: 1, Exe: "/usr/local/bin/precinto"})
	none(t, f.run(), doctor.CheckServiceRunning, doctor.Warn)
}

func TestServiceTCC(t *testing.T) {
	f := newFixture(t)
	f.d.GOOS = "darwin"
	docs := f.h.Protect(t, "Documents/notes")
	f.o.Cfg = f.h.Cfg
	none(t, f.run(), doctor.CheckServiceTCC) // no LaunchAgent: nothing runs outside the terminal
	writeFile(t, filepath.Join(f.h.HomeDir, "Library", "LaunchAgents", paths.ServiceLabel+".plist"), "<plist/>", 0o644)
	fs := f.run()
	want(t, fs, doctor.CheckServiceTCC, doctor.Warn, f.tilde(docs.Path)+" (in Documents)")
	for _, x := range of(fs, doctor.CheckServiceTCC) {
		if strings.Contains(x.Message, f.tilde(f.h.Root)+" (in") {
			t.Errorf("a folder outside the guarded locations reported: %q", x.Message)
		}
	}
	f.d.Plaintext = func(context.Context) ([]sweep.Plaintext, error) {
		return []sweep.Plaintext{{RootID: "root-acme", Files: 4, Bytes: 100, ByReason: map[string]int{"inaccessible": 4}}}, nil
	}
	want(t, f.run(), doctor.CheckServiceTCC, doctor.Warn, "4 files of "+f.tilde(f.h.Root)+" could not be read by precinto")
}
