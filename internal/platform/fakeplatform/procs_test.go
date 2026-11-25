package fakeplatform_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/platform/fakeplatform"
)

func id(pid int, start int64) platform.ProcID { return platform.ProcID{PID: pid, StartUS: start} }

func proc(pid, ppid int, start int64) platform.ProcInfo {
	return platform.ProcInfo{ID: id(pid, start), PPID: ppid, UID: 501, Exe: "/bin/p" + strconv.Itoa(pid)}
}

// fmtID formats id without platform.ProcID.String, which the platform
// package implements separately.
func fmtID(id platform.ProcID) string {
	return fmt.Sprintf("%d:%d(boot %q)", id.PID, id.StartUS, id.BootID)
}

func fmtInfo(p platform.ProcInfo) string {
	return fmt.Sprintf("{ID:%s PPID:%d UID:%d PGID:%d SID:%d State:%q Exe:%q Comm:%q Argv:%q TTY:%q}",
		fmtID(p.ID), p.PPID, p.UID, p.PGID, p.SID, p.State, p.Exe, p.Comm, p.Argv, p.TTY)
}

func pidsOf(list []platform.ProcInfo) []int {
	out := []int{}
	for _, p := range list {
		out = append(out, p.ID.PID)
	}
	return out
}

type held struct {
	pid  int
	path string
}

func heldOf(hs []platform.Holder) []held {
	out := []held{}
	for _, h := range hs {
		out = append(out, held{h.Proc.ID.PID, h.Path})
	}
	return out
}

func mustLookup(t *testing.T, p *fakeplatform.Procs, pid int) platform.ProcInfo {
	t.Helper()
	info, err := p.Lookup(pid)
	if err != nil {
		t.Fatalf("Lookup(%d): %v", pid, err)
	}
	return info
}

func mustHolders(t *testing.T, p *fakeplatform.Procs, dirs ...string) []held {
	t.Helper()
	hs, err := p.OpenFilesUnder(context.Background(), dirs)
	if err != nil {
		t.Fatalf("OpenFilesUnder(%q): %v", dirs, err)
	}
	return heldOf(hs)
}

func wantGone(t *testing.T, p *fakeplatform.Procs, info platform.ProcInfo) {
	t.Helper()
	if _, err := p.Lookup(info.ID.PID); !errors.Is(err, platform.ErrNoProcess) {
		t.Errorf("Lookup(%d) error = %v, want ErrNoProcess", info.ID.PID, err)
	}
	if p.Alive(info.ID) {
		t.Errorf("Alive(%s) = true for a removed process", fmtID(info.ID))
	}
	if _, err := p.Cwd(info.ID); !errors.Is(err, platform.ErrNotSame) {
		t.Errorf("Cwd(%s) error = %v, want ErrNotSame", fmtID(info.ID), err)
	}
}

func TestNewProcsIsEmpty(t *testing.T) {
	p := fakeplatform.NewProcs()
	for _, pid := range []int{1, 42, 99999} {
		info, err := p.Lookup(pid)
		if !errors.Is(err, platform.ErrNoProcess) || errors.Is(err, platform.ErrNotSame) {
			t.Errorf("Lookup(%d) error = %v, want only ErrNoProcess", pid, err)
		}
		if !reflect.DeepEqual(info, platform.ProcInfo{}) {
			t.Errorf("Lookup(%d) returned %s with its error", pid, fmtInfo(info))
		}
	}
	if p.Alive(id(1, 1)) {
		t.Error("Alive on an empty table")
	}
	if list, err := p.List(); err != nil || len(list) != 0 {
		t.Errorf("List = %v, %v; want empty", pidsOf(list), err)
	}
	if cwd, err := p.Cwd(id(1, 1)); !errors.Is(err, platform.ErrNotSame) || cwd != "" {
		t.Errorf("Cwd = %q, %v; want ErrNotSame", cwd, err)
	}
	if hs := mustHolders(t, p, "/"); len(hs) != 0 {
		t.Errorf("OpenFilesUnder = %v, want none", hs)
	}
}

func TestZeroValueProcsIsUsable(t *testing.T) {
	var empty fakeplatform.Procs
	if _, err := empty.Lookup(1); !errors.Is(err, platform.ErrNoProcess) {
		t.Errorf("Lookup on a zero Procs: %v", err)
	}
	if list, err := empty.List(); err != nil || len(list) != 0 {
		t.Errorf("List on a zero Procs = %v, %v", pidsOf(list), err)
	}
	if hs := mustHolders(t, &empty, "/"); len(hs) != 0 {
		t.Errorf("OpenFilesUnder on a zero Procs = %v", hs)
	}
	empty.Exit(1, true) // must not panic or create anything
	if _, err := empty.Lookup(1); !errors.Is(err, platform.ErrNoProcess) {
		t.Errorf("Exit of a missing pid created a process: %v", err)
	}

	var p fakeplatform.Procs
	p.SetCwd(10, "/w/acme")
	p.Add(proc(10, 1, 100))
	p.SetOpenFiles(10, "/w/acme/f")
	if cwd, err := p.Cwd(id(10, 100)); err != nil || cwd != "/w/acme" {
		t.Errorf("Cwd = %q, %v", cwd, err)
	}
	if hs := mustHolders(t, &p, "/w"); !slices.Equal(hs, []held{{10, "/w/acme/f"}}) {
		t.Errorf("OpenFilesUnder = %v", hs)
	}
	var r fakeplatform.Procs
	r.Reuse(20, 200, "/bin/x")
	if !r.Alive(id(20, 200)) {
		t.Error("Reuse on a zero Procs did not install the process")
	}
}

func TestAddDefaultsStateAndCopies(t *testing.T) {
	p := fakeplatform.NewProcs()
	in := platform.ProcInfo{
		ID:   platform.ProcID{PID: 20, StartUS: 1_700_000_000_000_000, BootID: "boot-1"},
		PPID: 10, UID: 501, PGID: 20, SID: 10,
		Exe: "/opt/claude/bin/claude", Comm: "2.1.0",
		Argv: []string{"claude", "--resume"}, TTY: "/dev/ttys003",
	}
	p.Add(in)
	want := in
	want.Argv = []string{"claude", "--resume"}
	want.State = platform.StateRunning
	got := mustLookup(t, p, 20)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Lookup = %s\nwant      %s", fmtInfo(got), fmtInfo(want))
	}

	in.Argv[0] = "changed by the caller after Add"
	got.Argv[1] = "changed by the caller after Lookup"
	if again := mustLookup(t, p, 20); !reflect.DeepEqual(again, want) {
		t.Errorf("the table shares memory with its callers: %s", fmtInfo(again))
	}

	for i, st := range []platform.ProcState{platform.StateStopped, platform.StateUnknown, platform.StateZombie} {
		info := proc(30+i, 1, 300)
		info.State = st
		p.Add(info)
		if got := mustLookup(t, p, 30+i); got.State != st {
			t.Errorf("Add kept State %q as %q", st, got.State)
		}
	}
}

func TestAddReplaces(t *testing.T) {
	p := fakeplatform.NewProcs()
	p.Add(proc(30, 20, 300))
	p.SetCwd(30, "/w/acme")
	p.SetOpenFiles(30, "/w/acme/f")

	// The same incarnation updated in place keeps its cwd and descriptors.
	upd := proc(30, 20, 300)
	upd.State = platform.StateStopped
	upd.Exe = "/bin/updated"
	p.Add(upd)
	if got := mustLookup(t, p, 30); got.State != platform.StateStopped || got.Exe != "/bin/updated" {
		t.Errorf("Add did not replace: %s", fmtInfo(got))
	}
	if !p.Alive(upd.ID) {
		t.Error("a stopped process is still alive")
	}
	if cwd, err := p.Cwd(upd.ID); err != nil || cwd != "/w/acme" {
		t.Errorf("Cwd after an in-place update = %q, %v", cwd, err)
	}
	if hs := mustHolders(t, p, "/w"); !slices.Equal(hs, []held{{30, "/w/acme/f"}}) {
		t.Errorf("OpenFilesUnder after an in-place update = %v", hs)
	}

	// Another incarnation at the same pid inherits nothing.
	p.Add(proc(30, 20, 999))
	if p.Alive(id(30, 300)) || !p.Alive(id(30, 999)) {
		t.Error("Add of another incarnation did not replace the identity")
	}
	if cwd, err := p.Cwd(id(30, 999)); err != nil || cwd != "" {
		t.Errorf("new incarnation inherited cwd %q (%v)", cwd, err)
	}
	if hs := mustHolders(t, p, "/w"); len(hs) != 0 {
		t.Errorf("new incarnation inherited open files %v", hs)
	}
	if list, _ := p.List(); !slices.Equal(pidsOf(list), []int{30}) {
		t.Errorf("List = %v, want one entry for pid 30", pidsOf(list))
	}
}

func TestNonPositivePIDsNeverExist(t *testing.T) {
	p := fakeplatform.NewProcs()
	p.Add(platform.ProcInfo{})
	p.Add(proc(0, 1, 5))
	p.Add(proc(-3, 1, 5))
	p.Reuse(0, 5, "/bin/x")
	p.Reuse(-1, 5, "/bin/x")
	p.SetCwd(0, "/w")
	p.SetOpenFiles(-1, "/w/f")
	p.Exit(0, true)
	if list, err := p.List(); err != nil || len(list) != 0 {
		t.Fatalf("List = %v, %v; want empty", pidsOf(list), err)
	}
	for _, pid := range []int{0, -1, -3} {
		if _, err := p.Lookup(pid); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("Lookup(%d) error = %v", pid, err)
		}
	}
	for _, pid := range []platform.ProcID{{}, id(0, 5), id(-3, 5)} {
		if p.Alive(pid) {
			t.Errorf("Alive(%s) = true", fmtID(pid))
		}
		if _, err := p.Cwd(pid); !errors.Is(err, platform.ErrNotSame) {
			t.Errorf("Cwd(%s) error = %v", fmtID(pid), err)
		}
	}
}

func TestAliveComparesTheWholeProcID(t *testing.T) {
	p := fakeplatform.NewProcs()
	cur := platform.ProcID{PID: 40, StartUS: 4000, BootID: "b1"}
	p.Add(platform.ProcInfo{ID: cur})
	for _, c := range []struct {
		id   platform.ProcID
		want bool
	}{
		{cur, true},
		{platform.ProcID{PID: 40, StartUS: 4001, BootID: "b1"}, false}, // pid reused
		{platform.ProcID{PID: 40, StartUS: 4000, BootID: "b2"}, false}, // other boot
		{platform.ProcID{PID: 40, StartUS: 4000}, false},               // boot id missing
		{platform.ProcID{PID: 41, StartUS: 4000, BootID: "b1"}, false}, // other pid
		{platform.ProcID{PID: 40}, false},                              // start unknown
		{platform.ProcID{}, false},
	} {
		if got := p.Alive(c.id); got != c.want {
			t.Errorf("Alive(%s) = %v, want %v", fmtID(c.id), got, c.want)
		}
	}
	for _, c := range []struct {
		state platform.ProcState
		alive bool
	}{
		{platform.StateRunning, true},
		{platform.StateStopped, true},
		{platform.StateUnknown, true},
		{platform.StateZombie, false}, // counts as exited everywhere (R8)
	} {
		p.Add(platform.ProcInfo{ID: cur, State: c.state})
		if got := p.Alive(cur); got != c.alive {
			t.Errorf("Alive with State %q = %v, want %v", c.state, got, c.alive)
		}
	}
}

func TestExitRemoves(t *testing.T) {
	p := fakeplatform.NewProcs()
	info := proc(50, 1, 500)
	p.Add(info)
	p.SetCwd(50, "/w/acme")
	p.SetOpenFiles(50, "/w/acme/f")
	p.Exit(50, false)
	wantGone(t, p, info)
	if list, _ := p.List(); len(list) != 0 {
		t.Errorf("List = %v after Exit", pidsOf(list))
	}
	if hs := mustHolders(t, p, "/w"); len(hs) != 0 {
		t.Errorf("an exited process still holds %v", hs)
	}

	// Repeated exits and exits of unknown pids are no-ops; they never
	// create a zombie.
	p.Exit(50, false)
	p.Exit(50, true)
	p.Exit(12345, true)
	wantGone(t, p, info)
	if _, err := p.Lookup(12345); !errors.Is(err, platform.ErrNoProcess) {
		t.Errorf("Exit of an unknown pid created it: %v", err)
	}

	// A later process at the pid starts with nothing of the old one.
	p.Add(proc(50, 1, 600))
	if cwd, err := p.Cwd(id(50, 600)); err != nil || cwd != "" {
		t.Errorf("Cwd of the next process at the pid = %q, %v", cwd, err)
	}
	if hs := mustHolders(t, p, "/w"); len(hs) != 0 {
		t.Errorf("the next process at the pid holds %v", hs)
	}
}

func TestExitZombie(t *testing.T) {
	p := fakeplatform.NewProcs()
	in := proc(60, 1, 600)
	in.Argv = []string{"claude"}
	in.TTY = "/dev/ttys004"
	p.Add(in)
	p.SetCwd(60, "/w/acme")
	p.SetOpenFiles(60, "/w/acme/f")
	p.Exit(60, true)

	want := in
	want.State = platform.StateZombie
	if got := mustLookup(t, p, 60); !reflect.DeepEqual(got, want) {
		t.Errorf("Lookup of a zombie = %s\nwant               %s", fmtInfo(got), fmtInfo(want))
	}
	if p.Alive(in.ID) {
		t.Error("a zombie is alive")
	}
	list, _ := p.List()
	if len(list) != 1 || list[0].ID != in.ID || list[0].State != platform.StateZombie {
		t.Errorf("List does not show the zombie: %v", pidsOf(list))
	}
	if _, err := p.Cwd(in.ID); !errors.Is(err, platform.ErrNotSame) {
		t.Errorf("Cwd of a zombie: %v, want ErrNotSame", err)
	}
	if hs := mustHolders(t, p, "/w"); len(hs) != 0 {
		t.Errorf("a zombie holds %v", hs)
	}

	p.Exit(60, true)
	if got := mustLookup(t, p, 60); got.State != platform.StateZombie {
		t.Errorf("second Exit(zombie) changed the state to %q", got.State)
	}
	p.Exit(60, false) // reaped
	wantGone(t, p, in)
}

func TestExitReparentsChildren(t *testing.T) {
	p := fakeplatform.NewProcs()
	for _, info := range []platform.ProcInfo{
		proc(1, 0, 1),     // launchd
		proc(10, 1, 100),  // login shell
		proc(20, 10, 200), // claude
		proc(30, 20, 300), // its MCP server
		proc(31, 30, 310), // grandchild
		proc(50, 10, 500), // sibling job of the shell
	} {
		p.Add(info)
	}
	p.Exit(20, false)
	for pid, ppid := range map[int]int{30: 1, 31: 30, 50: 10, 10: 1} {
		if got := mustLookup(t, p, pid).PPID; got != ppid {
			t.Errorf("after claude exited, PPID of %d = %d, want %d", pid, got, ppid)
		}
	}

	p.Exit(30, true) // becoming a zombie reparents too
	if got := mustLookup(t, p, 31).PPID; got != 1 {
		t.Errorf("PPID of 31 after its parent became a zombie = %d, want 1", got)
	}
	if got := mustLookup(t, p, 30).PPID; got != 1 {
		t.Errorf("PPID of the zombie 30 = %d, want 1 (reparented when 20 exited)", got)
	}

	p.Exit(1, false) // the reaper itself: nothing to reparent to
	if got := mustLookup(t, p, 10).PPID; got != 1 {
		t.Errorf("PPID of 10 after pid 1 exited = %d", got)
	}
}

func TestReuse(t *testing.T) {
	p := fakeplatform.NewProcs()
	old := platform.ProcInfo{
		ID:   platform.ProcID{PID: 70, StartUS: 7000, BootID: "b1"},
		PPID: 20, UID: 501, PGID: 20, SID: 10,
		Exe: "/opt/claude/bin/claude", Comm: "2.1.0", Argv: []string{"claude"}, TTY: "/dev/ttys001",
	}
	p.Add(proc(20, 10, 200))
	p.Add(old)
	p.Add(proc(71, 70, 7100)) // a child of the old incarnation
	p.SetCwd(70, "/w/acme")
	p.SetOpenFiles(70, "/w/acme/f")

	p.Reuse(70, 9000, "/usr/bin/other")
	if p.Alive(old.ID) {
		t.Error("the old incarnation is still alive after Reuse")
	}
	want := platform.ProcInfo{
		ID:   platform.ProcID{PID: 70, StartUS: 9000, BootID: "b1"},
		PPID: 1, UID: 501, State: platform.StateRunning, Exe: "/usr/bin/other",
	}
	got := mustLookup(t, p, 70)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Lookup after Reuse = %s\nwant                 %s", fmtInfo(got), fmtInfo(want))
	}
	if !p.Alive(want.ID) {
		t.Error("the new incarnation is not alive")
	}
	if cwd, err := p.Cwd(old.ID); !errors.Is(err, platform.ErrNotSame) {
		t.Errorf("Cwd of the old incarnation = %q, %v; want ErrNotSame", cwd, err)
	}
	if cwd, err := p.Cwd(want.ID); err != nil || cwd != "" {
		t.Errorf("the new incarnation inherited cwd %q (%v)", cwd, err)
	}
	if hs := mustHolders(t, p, "/w"); len(hs) != 0 {
		t.Errorf("the new incarnation inherited open files %v", hs)
	}
	if got := mustLookup(t, p, 71).PPID; got != 1 {
		t.Errorf("child of the old incarnation has PPID %d, want 1 (reparented)", got)
	}
}

func TestReuseAlwaysChangesTheIdentity(t *testing.T) {
	p := fakeplatform.NewProcs()
	for _, start := range []int64{8000, 0, math.MaxInt64, math.MinInt64} {
		p.Add(platform.ProcInfo{ID: id(80, start)})
		p.Reuse(80, start, "/bin/x")
		got := mustLookup(t, p, 80)
		if got.ID.StartUS == start || p.Alive(id(80, start)) {
			t.Errorf("Reuse with the old start time %d kept the identity: %s", start, fmtID(got.ID))
		}
		if !p.Alive(got.ID) || got.Exe != "/bin/x" {
			t.Errorf("Reuse(%d) installed %s", start, fmtInfo(got))
		}
	}
	// An earlier start time is a valid other incarnation (darwin start
	// times follow the wall clock, which may have been stepped back).
	p.Add(platform.ProcInfo{ID: id(81, 5000)})
	p.Reuse(81, 4000, "/bin/y")
	if !p.Alive(id(81, 4000)) {
		t.Error("Reuse with an earlier start time did not keep it")
	}
}

func TestReuseOfAFreeOrZombiePID(t *testing.T) {
	p := fakeplatform.NewProcs()
	p.Reuse(90, 9000, "/bin/x")
	want := platform.ProcInfo{ID: id(90, 9000), PPID: 1, State: platform.StateRunning, Exe: "/bin/x"}
	if got := mustLookup(t, p, 90); !reflect.DeepEqual(got, want) {
		t.Errorf("Reuse of a free pid = %s\nwant                 %s", fmtInfo(got), fmtInfo(want))
	}

	p.Add(proc(91, 1, 100))
	p.Exit(91, true)
	p.Reuse(91, 200, "/bin/y")
	if got := mustLookup(t, p, 91); !p.Alive(id(91, 200)) || got.State != platform.StateRunning {
		t.Errorf("Reuse of a zombie's pid = %s", fmtInfo(got))
	}

	p.Add(proc(92, 1, 100))
	p.Exit(92, false)
	p.Reuse(92, 300, "/bin/z")
	if !p.Alive(id(92, 300)) || p.Alive(id(92, 100)) {
		t.Error("Reuse of an exited process's pid")
	}
}

func TestCwd(t *testing.T) {
	p := fakeplatform.NewProcs()
	info := proc(100, 1, 1000)
	p.Add(info)
	if cwd, err := p.Cwd(info.ID); err != nil || cwd != "" {
		t.Errorf("Cwd before SetCwd = %q, %v; want unknown", cwd, err)
	}
	p.SetCwd(100, "/w/acme")
	if cwd, err := p.Cwd(info.ID); err != nil || cwd != "/w/acme" {
		t.Errorf("Cwd = %q, %v", cwd, err)
	}
	p.SetCwd(100, "/w/beta")
	if cwd, _ := p.Cwd(info.ID); cwd != "/w/beta" {
		t.Errorf("SetCwd did not replace: %q", cwd)
	}
	p.SetCwd(100, "")
	if cwd, err := p.Cwd(info.ID); err != nil || cwd != "" {
		t.Errorf("Cwd after SetCwd(\"\") = %q, %v; want unknown", cwd, err)
	}
	for _, other := range []platform.ProcID{id(100, 999), id(100, 1001), id(101, 1000)} {
		if _, err := p.Cwd(other); !errors.Is(err, platform.ErrNotSame) {
			t.Errorf("Cwd(%s) error = %v, want ErrNotSame", fmtID(other), err)
		}
	}

	stopped := proc(101, 1, 10)
	stopped.State = platform.StateStopped
	p.Add(stopped)
	p.SetCwd(101, "/w/stopped")
	if cwd, err := p.Cwd(stopped.ID); err != nil || cwd != "/w/stopped" {
		t.Errorf("Cwd of a stopped process = %q, %v", cwd, err)
	}

	// Set before the process exists: it applies to the process added there.
	p.SetCwd(102, "/w/pre")
	if _, err := p.Cwd(id(102, 5)); !errors.Is(err, platform.ErrNotSame) {
		t.Errorf("Cwd of a pid nobody holds: %v", err)
	}
	p.Add(proc(102, 1, 5))
	if cwd, err := p.Cwd(id(102, 5)); err != nil || cwd != "/w/pre" {
		t.Errorf("Cwd set before Add = %q, %v", cwd, err)
	}
}

func TestOpenFilesUnderHasWithinSemantics(t *testing.T) {
	for _, c := range []struct {
		dir, file string
		want      bool
	}{
		{"/u/work/acme", "/u/work/acme", true}, // the directory itself
		{"/u/work/acme", "/u/work/acme/docs/x.md", true},
		{"/u/work/acme", "/u/work/acme-other/x.md", false}, // never a string prefix
		{"/u/work/acme", "/u/work", false},
		{"/u/work/acme", "/u/work/acme/../beta", false},
		{"/u/work/acme", "work/acme", false}, // relative paths are never within
		{"/u/work/acme/", "/u/work/acme/x", true},
		{"/u/work/./acme", "/u/work/acme//x", true},
		{"/", "/anything", true},
		{"/u/Work/Acme", "/u/work/acme/x", runtime.GOOS == "darwin"}, // ASCII case folding on darwin only
	} {
		p := fakeplatform.NewProcs()
		p.Add(proc(10, 1, 1))
		p.SetOpenFiles(10, c.file)
		hs := mustHolders(t, p, c.dir)
		if got := len(hs) == 1; got != c.want {
			t.Errorf("OpenFilesUnder(%q) with %q open = %v, want held=%v", c.dir, c.file, hs, c.want)
		}
		if len(hs) == 1 && hs[0].path != c.file {
			t.Errorf("Holder.Path = %q, want %q as set", hs[0].path, c.file)
		}
	}
}

func TestOpenFilesUnder(t *testing.T) {
	p := fakeplatform.NewProcs()
	a, b, c := proc(200, 1, 1), proc(201, 1, 2), proc(202, 1, 3)
	b.Argv = []string{"node", "server.js"}
	p.Add(b)
	p.Add(a)
	p.Add(c)
	p.SetOpenFiles(201, "/w/acme/z.jsonl", "/w/acme/a.jsonl", "/w/acme/a.jsonl", "/elsewhere/x")
	p.SetOpenFiles(200, "/w/acme/tasks/t1", "/w/beta/y")
	p.SetOpenFiles(202)

	hs, err := p.OpenFilesUnder(context.Background(), []string{"/w/acme", "/w/acme/tasks", "/w/beta"})
	if err != nil {
		t.Fatal(err)
	}
	want := []held{{200, "/w/acme/tasks/t1"}, {200, "/w/beta/y"}, {201, "/w/acme/a.jsonl"}, {201, "/w/acme/z.jsonl"}}
	if got := heldOf(hs); !slices.Equal(got, want) {
		t.Fatalf("OpenFilesUnder = %v, want %v (sorted, one per pid and path)", got, want)
	}
	for _, h := range hs {
		if info := mustLookup(t, p, h.Proc.ID.PID); !reflect.DeepEqual(h.Proc, info) {
			t.Errorf("Holder.Proc = %s, want %s", fmtInfo(h.Proc), fmtInfo(info))
		}
	}
	hs[2].Proc.Argv[0] = "changed by the caller"
	if got := mustLookup(t, p, 201); got.Argv[0] != "node" {
		t.Errorf("Holder.Proc shares memory with the table: %q", got.Argv)
	}

	if got := mustHolders(t, p); len(got) != 0 {
		t.Errorf("OpenFilesUnder with no directories = %v", got)
	}
	if got := mustHolders(t, p, "/w/gamma"); len(got) != 0 {
		t.Errorf("OpenFilesUnder of an unrelated directory = %v", got)
	}

	p.SetOpenFiles(201, "/w/acme/new")
	if got := mustHolders(t, p, "/w/acme"); !slices.Equal(got, []held{{200, "/w/acme/tasks/t1"}, {201, "/w/acme/new"}}) {
		t.Errorf("SetOpenFiles did not replace the set: %v", got)
	}
	p.SetOpenFiles(201)
	if got := mustHolders(t, p, "/w/acme"); !slices.Equal(got, []held{{200, "/w/acme/tasks/t1"}}) {
		t.Errorf("SetOpenFiles with no paths did not clear: %v", got)
	}

	files := []string{"/w/acme/q"}
	p.SetOpenFiles(202, files...)
	files[0] = "/elsewhere/q"
	if got := mustHolders(t, p, "/w/acme"); !slices.Contains(got, held{202, "/w/acme/q"}) {
		t.Errorf("SetOpenFiles shares the caller's slice: %v", got)
	}

	// Set before the process exists: reported once a process holds the pid.
	p.SetOpenFiles(203, "/w/acme/pre")
	if got := mustHolders(t, p, "/w/acme/pre"); len(got) != 0 {
		t.Errorf("a pid nobody holds is reported: %v", got)
	}
	p.Add(proc(203, 1, 4))
	if got := mustHolders(t, p, "/w/acme/pre"); !slices.Equal(got, []held{{203, "/w/acme/pre"}}) {
		t.Errorf("files set before Add = %v", got)
	}

	stopped := proc(204, 1, 5)
	stopped.State = platform.StateStopped
	p.Add(stopped)
	p.SetOpenFiles(204, "/w/acme/stopped")
	if got := mustHolders(t, p, "/w/acme/stopped"); !slices.Equal(got, []held{{204, "/w/acme/stopped"}}) {
		t.Errorf("a stopped process still holds its descriptors: %v", got)
	}
}

func TestOpenFilesUnderErrorsMeanLive(t *testing.T) {
	p := fakeplatform.NewProcs()
	p.Add(proc(10, 1, 1))
	p.SetOpenFiles(10, "/w/acme/f")

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if hs, err := p.OpenFilesUnder(cancelled, []string{"/w"}); !errors.Is(err, context.Canceled) || hs != nil {
		t.Errorf("cancelled context: %v, %v", heldOf(hs), err)
	}
	expired, cancel2 := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancel2()
	if _, err := p.OpenFilesUnder(expired, []string{"/w"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expired context: %v", err)
	}
	var nilCtx context.Context
	if _, err := p.OpenFilesUnder(nilCtx, []string{"/w"}); err == nil {
		t.Error("nil context accepted")
	}
	for _, dirs := range [][]string{{"w/acme"}, {""}, {"/w", "relative"}, {"./w"}} {
		if hs, err := p.OpenFilesUnder(context.Background(), dirs); err == nil {
			t.Errorf("OpenFilesUnder(%q) = %v, nil; want an error", dirs, heldOf(hs))
		}
	}
}

func TestListIsSortedAndCopied(t *testing.T) {
	p := fakeplatform.NewProcs()
	for _, pid := range []int{30, 10, 40, 20} {
		info := proc(pid, 1, int64(pid))
		info.Argv = []string{"argv0"}
		p.Add(info)
	}
	p.Exit(40, true)
	list, err := p.List()
	if err != nil {
		t.Fatal(err)
	}
	if got := pidsOf(list); !slices.Equal(got, []int{10, 20, 30, 40}) {
		t.Fatalf("List = %v, want sorted by pid", got)
	}
	if list[3].State != platform.StateZombie {
		t.Errorf("List shows the zombie as %q", list[3].State)
	}
	list[0].Argv[0] = "changed by the caller"
	list[1].PPID = 999
	if got := mustLookup(t, p, 10); got.Argv[0] != "argv0" {
		t.Errorf("List shares memory with the table: %q", got.Argv)
	}
	if got := mustLookup(t, p, 20); got.PPID != 1 {
		t.Errorf("List returned a reference into the table: PPID %d", got.PPID)
	}
}

// TestPlatformWalksOverProcs runs the scaffold's PPID walks over the fake:
// reused pids and zombies are never descendants, and once a parent exits
// its children are reparented and no longer found (platform.Descendants).
func TestPlatformWalksOverProcs(t *testing.T) {
	p := fakeplatform.NewProcs()
	for _, info := range []platform.ProcInfo{
		proc(1, 0, 1),
		proc(10, 1, 100),  // login shell (same Unix session as claude)
		proc(20, 10, 200), // unwrapped claude
		proc(30, 20, 300), // its MCP server
		proc(31, 30, 310), // grandchild
		proc(40, 20, 150), // reused pid: started before claude, not its child
		proc(50, 10, 500), // sibling job of the shell
		proc(60, 20, 600), // a child that exited but was not reaped
	} {
		p.Add(info)
	}
	p.Exit(60, true)
	claude := id(20, 200)

	anc, err := platform.Ancestors(p, 31, 10)
	if err != nil || !slices.Equal(pidsOf(anc), []int{30, 20, 10}) {
		t.Fatalf("Ancestors = %v, %v", pidsOf(anc), err)
	}
	if _, err := platform.Ancestors(p, 99, 10); !errors.Is(err, platform.ErrNoProcess) {
		t.Errorf("Ancestors of a missing pid: %v", err)
	}
	ds, err := platform.Descendants(p, claude)
	if err != nil || !slices.Equal(pidsOf(ds), []int{30, 31}) {
		t.Fatalf("Descendants = %v, %v; want [30 31]", pidsOf(ds), err)
	}

	p.Reuse(31, 900, "/usr/bin/unrelated") // the grandchild's pid is reused
	ds, _ = platform.Descendants(p, claude)
	if !slices.Equal(pidsOf(ds), []int{30}) {
		t.Errorf("Descendants after pid reuse = %v, want [30]", pidsOf(ds))
	}

	p.Exit(20, false)
	ds, _ = platform.Descendants(p, claude)
	if len(ds) != 0 {
		t.Errorf("Descendants after the root exited = %v, want none (children reparented)", pidsOf(ds))
	}
}

func TestProcsConcurrentUse(t *testing.T) {
	p := fakeplatform.NewProcs()
	ctx := context.Background()
	const workers, iters = 8, 300
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			base := 1000 * (w + 1)
			for i := range iters {
				pid := base + i%7
				start := int64(i + 1)
				info := proc(pid, base, start)
				info.Argv = []string{"argv0", "argv1"}
				p.Add(info)
				p.SetCwd(pid, "/w/acme")
				p.SetOpenFiles(pid, "/w/acme/f", "/w/other/g")
				if got, err := p.Lookup(pid); err == nil && len(got.Argv) > 0 {
					got.Argv[0] = "mutated"
				}
				if list, err := p.List(); err == nil {
					for j := range list {
						if len(list[j].Argv) > 0 {
							list[j].Argv[0] = "mutated"
						}
					}
				}
				if hs, err := p.OpenFilesUnder(ctx, []string{"/w/acme"}); err == nil {
					for j := range hs {
						if len(hs[j].Proc.Argv) > 0 {
							hs[j].Proc.Argv[0] = "mutated"
						}
					}
				}
				_ = p.Alive(id(pid, start))
				_, _ = p.Cwd(id(pid, start))
				_, _ = platform.Descendants(p, id(base, 0))
				switch i % 3 {
				case 0:
					p.Exit(pid, false)
				case 1:
					p.Exit(pid, true)
				default:
					p.Reuse(pid, start+1_000_000, "/bin/reused")
				}
			}
		}()
	}
	wg.Wait()

	list, err := p.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range list {
		got := mustLookup(t, p, info.ID.PID)
		if !reflect.DeepEqual(got, info) {
			t.Errorf("List and Lookup disagree on %d: %s vs %s", info.ID.PID, fmtInfo(info), fmtInfo(got))
		}
		if slices.Contains(got.Argv, "mutated") {
			t.Errorf("a caller's mutation reached the table: %s", fmtInfo(got))
		}
	}
}
