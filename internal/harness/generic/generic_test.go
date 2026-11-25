package generic_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/harness/generic"
	"github.com/Neorichi/precinto/internal/live"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/platform/fakeplatform"
	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/inventories"
)

var salt = []byte("precinto-test-salt-0123456789abc")

const demoInventory = `schema = 1
id = "demo"
name = "Demo CLI"
status = "experimental"
verified_versions = ""
mode = "home"
open_fd_check = true
partition = "project-dir"
content = ["demo_home:sessions/**", "demo_home:history.jsonl", "demo_home:data.db"]
exclude = ["demo_home:sessions/cache/**"]
passthrough = [["--version"]]
direct = [["run"]]

[[bases]]
name = "demo_home"
default = "~/.demo"
env = "DEMO_HOME"

[process]
exe_basenames = ["demo"]

[[locks]]
glob = "demo_home:locks/*.lock"
kind = "json-pid"

[[locks]]
glob = "demo_home:writer.lock"
kind = "flock"
`

// Experimental inventories are returned only with --experimental (D33);
// the built-in ones never.
func TestAdaptersExperimentalGating(t *testing.T) {
	t.Parallel()
	none, err := generic.Adapters(inventories.FS, false)
	if err != nil || len(none) != 0 {
		t.Fatalf("without --experimental: %d adapters, %v", len(none), err)
	}
	all, err := generic.Adapters(inventories.FS, true)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, a := range all {
		ids = append(ids, string(a.ID()))
	}
	sort.Strings(ids)
	if strings.Join(ids, ",") != "gemini,kimi,opencode,qwen" {
		t.Fatalf("experimental adapters = %v", ids)
	}
	if _, err := generic.Adapters(fstest.MapFS{"bad.toml": {Data: []byte("schema = 2")}}, true); err == nil {
		t.Fatal("an invalid inventory was accepted")
	}
}

type fx struct {
	t    *testing.T
	h    *testkit.Home
	e    harness.Env
	a    harness.Adapter
	home string
}

func newFx(t *testing.T) *fx {
	t.Helper()
	h := testkit.NewHome(t)
	h.Clock = fakeplatform.NewClock(time.Now())
	inv, err := harness.LoadInventory(fstest.MapFS{"demo.toml": {Data: []byte(demoInventory)}}, "demo")
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(h.HomeDir, ".demo")
	f := &fx{t: t, h: h, a: generic.New(inv), home: home}
	f.e = harness.Env{Cfg: h.Cfg, Layout: h.Layout, Procs: h.Procs, Clock: h.Clock, Salt: salt, Host: h.Env}
	return f
}

func (f *fx) write(rel, data string) string {
	f.t.Helper()
	p := filepath.Join(f.home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return p
}

var dormant = harness.Scope{Kinds: []capsule.Kind{capsule.KindGeneric}}

func TestScanOnlyWhenDormantAndPartitions(t *testing.T) {
	t.Parallel()
	f := newFx(t)
	marker := testkit.Marker(t)
	f.write("sessions/ws-a/s1/wire.jsonl", marker)
	f.write("sessions/ws-a/s1/state.json", marker)
	f.write("sessions/ws-b/s2/wire.jsonl", marker)
	f.write("sessions/cache/x.bin", "excluded")
	f.write("history.jsonl", marker)
	f.write("config.json", "not content")
	os.Symlink("/etc/hosts", filepath.Join(f.home, "sessions", "ws-a", "link"))
	ctx := context.Background()
	for _, s := range []harness.Scope{{}, {Adopt: true}, {Global: true}, {Kinds: []capsule.Kind{capsule.KindClaudeSession}}} {
		if units, err := f.a.Scan(ctx, f.e, s); err != nil || len(units) != 0 {
			t.Fatalf("scope %+v: %d units, %v (only seal --dormant scans experimental harnesses)", s, len(units), err)
		}
	}
	units, err := f.a.Scan(ctx, f.e, dormant)
	if err != nil {
		t.Fatal(err)
	}
	byPart := map[string]harness.Unit{}
	for _, u := range units {
		byPart[u.UnitID] = u
		if u.Kind != capsule.KindGeneric || u.VaultID != "global" || len(u.RootIDs) != 0 || u.Harness != "demo" || u.Key == "" {
			t.Errorf("unit %+v", u.Ref())
		}
	}
	if len(units) != 3 {
		t.Fatalf("partitions = %v", keys(byPart))
	}
	// CC-21: Scope.Procs and Scope.Adopt change nothing for partitions; a
	// scope naming sessions gets none (partitions are no sessions), and
	// the wrapper's seal after exit (Procs only) seals nothing.
	for _, s := range []harness.Scope{
		{Kinds: dormant.Kinds, Procs: []platform.ProcID{{PID: 7, StartUS: 7}}},
		{Kinds: dormant.Kinds, Adopt: true},
	} {
		if got, err := f.a.Scan(ctx, f.e, s); err != nil || len(got) != 3 {
			t.Errorf("scope %+v: %d units, %v", s, len(got), err)
		}
	}
	for _, s := range []harness.Scope{
		{Kinds: dormant.Kinds, SIDs: []string{"s1"}},
		{Procs: []platform.ProcID{{PID: 7, StartUS: 7}}},
	} {
		if got, err := f.a.Scan(ctx, f.e, s); err != nil || len(got) != 0 {
			t.Errorf("scope %+v: %d units, %v", s, len(got), err)
		}
	}
	a := byPart["demo_home/sessions/ws-a"]
	if len(a.Files) != 2 || len(a.Hazards) != 1 || a.Hazards[0].Rel != "sessions/ws-a/link" {
		t.Errorf("ws-a: %+v", a)
	}
	if h := byPart["home"]; len(h.Files) != 1 || h.Files[0].Rel != "history.jsonl" || !h.Files[0].Append {
		t.Errorf("home partition: %+v", h.Files)
	}
	for _, u := range units {
		for _, file := range u.Files {
			if strings.Contains(file.Rel, "cache/") || file.Rel == "config.json" {
				t.Errorf("sealed %s", file.Rel)
			}
			if file.Base != "generic:demo_home" {
				t.Errorf("base %s", file.Base)
			}
		}
	}
	noSalt := f.e
	noSalt.Salt = nil
	if _, err := f.a.Scan(ctx, noSalt, dormant); err == nil {
		t.Fatal("Scan without salt succeeded")
	}
	// Relocation through the inventory's env var (DEMO_HOME).
	moved := filepath.Join(f.h.Dir, "relocated-demo")
	os.MkdirAll(filepath.Join(moved, "sessions", "w"), 0o700)
	os.WriteFile(filepath.Join(moved, "sessions", "w", "x"), []byte("x"), 0o600)
	re := f.e
	re.Host = f.h.Env.With("DEMO_HOME", moved)
	homes, err := f.a.Homes(ctx, re)
	if err != nil || len(homes) != 1 || homes[0].Bases["generic:demo_home"] != moved || homes[0].Default {
		t.Fatalf("relocated home: %+v %v", homes, err)
	}
}

func keys(m map[string]harness.Unit) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SPEC §7.3: a dormant seal is refused (live) while a matching process
// runs, a lock is held, the open-file check fails or a -wal/-shm exists.
func TestProbeDormantConditions(t *testing.T) {
	t.Parallel()
	f := newFx(t)
	f.write("sessions/ws/s/wire.jsonl", "x")
	db := f.write("data.db", "x")
	units, err := f.a.Scan(context.Background(), f.e, dormant)
	if err != nil || len(units) != 2 {
		t.Fatalf("scan: %d %v", len(units), err)
	}
	u := units[0]
	probe := func() map[live.Reason]int {
		evs, err := f.a.Probe(context.Background(), f.e, u)
		if err != nil {
			t.Fatal(err)
		}
		out := map[live.Reason]int{}
		for _, e := range evs {
			out[e.Reason]++
		}
		return out
	}
	if ev := probe(); len(ev) != 0 {
		t.Fatalf("dormant: %v", ev)
	}
	demo := platform.ProcInfo{ID: platform.ProcID{PID: 900, StartUS: 1}, PPID: 1, Exe: "/usr/local/bin/demo"}
	f.h.Procs.Add(demo)
	if ev := probe(); ev[live.ReasonProcess] != 1 {
		t.Fatalf("matching process: %v", ev)
	}
	f.h.Procs.Exit(900, false)
	// json-pid lock of a live process; of a dead one; unreadable.
	other := platform.ProcInfo{ID: platform.ProcID{PID: 901, StartUS: 1}, PPID: 1, Exe: "/bin/sh"}
	f.h.Procs.Add(other)
	lock := f.write("locks/s.lock", `{"pid":901,"hostname":"h"}`)
	if ev := probe(); ev[live.ReasonWriterLock] != 1 {
		t.Fatalf("json-pid lock held: %v", ev)
	}
	f.h.Procs.Exit(901, false)
	if ev := probe(); ev[live.ReasonWriterLock] != 0 {
		t.Fatalf("stale json-pid lock: %v", ev)
	}
	os.WriteFile(lock, []byte("{torn"), 0o600)
	if ev := probe(); ev[live.ReasonWriterLock] != 1 {
		t.Fatalf("unreadable lock record must be held: %v", ev)
	}
	os.Remove(lock)
	// flock lock: held when some process has it open (never flocked by us).
	wl := f.write("writer.lock", "")
	f.h.Procs.Add(other)
	f.h.Procs.SetOpenFiles(901, wl)
	if ev := probe(); ev[live.ReasonWriterLock] != 1 || ev[live.ReasonOpenFD] != 1 {
		t.Fatalf("flock lock held: %v", ev)
	}
	f.h.Procs.SetOpenFiles(901)
	// The open-file check fails.
	f.h.Procs.SetErr(fakeplatform.OpOpenFilesUnder, errors.New("no lsof"))
	if ev := probe(); ev[live.ReasonOpenFD] == 0 {
		t.Fatalf("failed open-file check must be live: %v", ev)
	}
	f.h.Procs.SetErr(fakeplatform.OpOpenFilesUnder, nil)
	// A -wal next to a content database.
	dbUnit := units[0]
	for _, x := range units {
		for _, file := range x.Files {
			if file.Rel == "data.db" {
				dbUnit = x
			}
		}
	}
	u = dbUnit
	for _, suf := range []string{"-wal", "-shm", "-journal"} {
		os.WriteFile(db+suf, []byte("x"), 0o600)
		if ev := probe(); ev[live.ReasonUnknown] != 1 {
			t.Fatalf("%s present: %v", suf, ev)
		}
		os.Remove(db + suf)
	}
	if ev := probe(); len(ev) != 0 {
		t.Fatalf("dormant again: %v", ev)
	}
	f.h.Procs.SetErr(fakeplatform.OpList, errors.New("denied"))
	if ev := probe(); ev[live.ReasonUnknown] != 1 {
		t.Fatalf("process table unreadable: %v", ev)
	}
	if evs, _ := f.a.Probe(context.Background(), harness.Env{}, u); len(evs) == 0 {
		t.Fatal("no process table must be live")
	}
}

func TestTargetsNeedARegisteredHome(t *testing.T) {
	t.Parallel()
	f := newFx(t)
	f.write("sessions/ws/s/wire.jsonl", "x")
	units, _ := f.a.Scan(context.Background(), f.e, dormant)
	u := units[0]
	if _, err := f.a.Targets(context.Background(), f.e, u.Ref(), u.UnitID); !errors.Is(err, harness.ErrUnregistered) {
		t.Fatalf("unregistered home: %v", err)
	}
	f.e.Cfg.Harness = map[string]config.Harness{"demo": {Enabled: true, Experimental: true, Homes: []config.Home{{Dir: f.home}}}}
	rules, err := f.a.Targets(context.Background(), f.e, u.Ref(), u.UnitID)
	if err != nil {
		t.Fatal(err)
	}
	base := capsule.BaseID("generic:demo_home")
	for rel, want := range map[string]bool{
		"sessions/ws/s/wire.jsonl": true,
		"sessions/ws/other":        true,
		"sessions/ws2/x":           false, // another partition
		"sessions/cache/x":         false, // excluded
		"config.json":              false,
		"../x":                     false,
		"sessions/ws/../../etc/x":  false,
	} {
		if got := rules.Allow(base, rel); got != want {
			t.Errorf("Allow(%s) = %v, want %v", rel, got, want)
		}
	}
	if rules.Allow(capsule.BaseClaudeConfig, "sessions/ws/x") {
		t.Error("foreign base allowed")
	}
	wrong := u.Ref()
	wrong.Harness = "other"
	if _, err := f.a.Targets(context.Background(), f.e, wrong, u.UnitID); err == nil {
		t.Error("foreign harness accepted")
	}
}

func TestPlanLaunchGeneric(t *testing.T) {
	t.Parallel()
	f := newFx(t)
	bin := filepath.Join(f.h.Dir, "bin", "demo")
	os.MkdirAll(filepath.Dir(bin), 0o700)
	os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700)
	f.e.Host = paths.FromMap(map[string]string{"HOME": f.h.HomeDir, "PATH": filepath.Dir(bin)})
	plan, err := f.a.PlanLaunch(context.Background(), f.e, f.h.Root, []string{"demo", "run", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Argv[0] != bin || plan.Mode != harness.LaunchDirect || len(plan.Roots) != 1 ||
		len(plan.Sync)+len(plan.Background) != 0 || len(plan.Env) != 0 || plan.HookCheck.Event != "" {
		t.Fatalf("plan %+v (no restore, no relocation, no hooks)", plan)
	}
	// CC-24: no hooks, so no SessionEnd budget: the minimum grace.
	if plan.KillGrace != 8*time.Second || len(plan.QuitKeys) != 0 {
		t.Errorf("termination %v %q", plan.KillGrace, plan.QuitKeys)
	}
	if plan, _ := f.a.PlanLaunch(context.Background(), f.e, f.h.Root, []string{"demo", "--version"}); plan.Mode != harness.LaunchPassthrough {
		t.Fatalf("passthrough: %+v", plan)
	}
	if _, err := f.a.PlanLaunch(context.Background(), f.e, f.h.Root, []string{"missing-binary"}); err == nil {
		t.Fatal("missing binary accepted")
	}
	if md, err := f.a.MarkdownPaths(context.Background(), f.e, harness.Unit{}); md != nil || err != nil {
		t.Fatal("experimental harnesses report no Markdown")
	}
}
