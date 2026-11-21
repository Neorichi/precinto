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
	got := want(t, f.run(), doctor.CheckServiceRunning, doctor.Fail, "socket folder", "mode 0755")
	if got.Fix != "chmod 700 "+f.h.RunDir {
		t.Errorf("fix %q", got.Fix)
	}
	if err := os.Chmod(f.h.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// A regular file squatting the socket path.
	writeFile(t, f.h.Layout.Socket, "", 0o600)
	want(t, f.run(), doctor.CheckServiceRunning, doctor.Fail, "is not a socket")
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
	want(t, f.run(), doctor.CheckServiceRunning, doctor.Fail, "can be used by other users")
	if err := os.Chmod(f.h.Layout.Socket, 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, f.run(), doctor.CheckServiceRunning, doctor.Info, "stale agent socket")
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
	got := want(t, fs, doctor.CheckServiceRunning, doctor.Warn, f.h.Layout.StateDir+" can be read by other users (mode 0755)")
	if got.Fix != "chmod 700 "+state {
		t.Errorf("fix %q", got.Fix)
	}
	want(t, fs, doctor.CheckServiceRunning, doctor.Fail, f.h.Layout.CapsulesDir+" can be changed by other users (mode 0777)")
	want(t, fs, doctor.CheckServiceRunning, doctor.Warn, "config.toml can be read by other users (mode 0644)")
	want(t, fs, doctor.CheckServiceRunning, doctor.Warn, vfile+" can be read by other users")
	got = want(t, fs, doctor.CheckServiceRunning, doctor.Fail, f.h.Layout.LocksDir+" is a symbolic link")
	if !strings.HasPrefix(got.Fix, "move ") {
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
	writeFile(t, filepath.Join(f.h.HomeDir, "Library", "LaunchAgents", "dev.precinto.sweep.plist"), "<plist/>", 0o644)
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
	writeFile(t, filepath.Join(f.h.HomeDir, "Library", "LaunchAgents", "dev.precinto.sweep.plist"), "<plist/>", 0o644)
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
