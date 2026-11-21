//go:build crossgroup

package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/agent/agenttest"
	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/testkit"
)

// realApp wires the production system over a testkit home: the real
// engine (sweep, harness adapters, live, ledger), the real vault store and
// the real ipc client (Insecure: the agent runs in this test process).
func realApp(t *testing.T, h *testkit.Home) (*app, *env) {
	t.Helper()
	e := newEnv(t)
	e.h = h
	sys := productionSystem()
	sys.newLayout = func(paths.Env) (paths.Layout, error) { return h.Layout, nil }
	sys.getwd = func() (string, error) { return h.Root, nil }
	sys.openTTY = e.app().sys.openTTY
	sys.interactive = func() bool { return false }
	sys.stdoutTTY = func() bool { return false }
	sys.harden = func() error { return nil } // never harden the go test binary
	sys.dial = func(ctx context.Context, o ipc.DialOptions) (daemonClient, error) {
		o.Insecure, o.Autostart = true, false
		c, err := ipc.Dial(ctx, o)
		if err != nil {
			return nil, err
		}
		return ipcClient{c}, nil
	}
	sys.procs = func() platform.ProcTable { return h.Procs }
	sys.clock = func() platform.Clock { return h.Clock }
	// The D63 quiet-window wait advances the fake clock the engine reads
	// (sweep.Env.Sleep, CC-29), so a sweep decides at once.
	sys.sweepSleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		h.Clock.Advance(d)
		return nil
	}
	a := newApp(stdio{in: e.in, out: &e.out, err: &e.err}, h.Env, sys)
	return a, e
}

// The KeySource and Grants adapters and lock/status over a real daemon
// (agenttest): every vault starts locked, key release for an unlogged
// capsule is denied (I14), lock answers (I15).
func TestCrossgroupAdaptersOverAgent(t *testing.T) {
	h := testkit.NewHome(t)
	ag := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	defer ag.Stop()
	a, e := realApp(t, h)
	ctx := context.Background()

	open, err := a.grants()(ctx)
	if err != nil {
		t.Fatalf("grants: %v", err)
	}
	if len(open) != 0 {
		t.Fatalf("a fresh daemon has unlocked vaults: %v", open)
	}
	ks := a.keys()
	defer ks.close()
	if _, err := ks.FileKeys(ctx, []string{"claude-code/0123456789abcdef0123456789abcdef/g000001.pcap"}, ipc.PurposeRestore); !errors.Is(err, sweep.ErrKeyDenied) {
		t.Fatalf("unlogged capsule: %v", err)
	}
	if code := a.run([]string{"lock"}); code != exitOK {
		t.Fatalf("lock: exit %d (%s)", code, e.stderr())
	}
	e.out.Reset()
	if code := a.run([]string{"status", "--json"}); code != exitOK {
		t.Fatalf("status: exit %d (%s)", code, e.stderr())
	}
	var s statusV1
	if err := json.Unmarshal(e.out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if !s.Agent.Running || len(s.Folders) != 1 || s.Folders[0].State != "locked" {
		t.Fatalf("status %+v", s)
	}
}

// The production engine builds over a testkit home and derives unit keys
// exactly as harness.UnitKeyFor (SPEC §6.2).
func TestCrossgroupEngineWiring(t *testing.T) {
	h := testkit.NewHome(t)
	a, _ := realApp(t, h)
	ctx := context.Background()
	eng, err := a.engine(ctx, false)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if _, err := eng.PlaintextSummary(ctx); err != nil {
		t.Fatalf("PlaintextSummary: %v", err)
	}
	k1, err := eng.UnitKey(capsule.KindMarkdown, "", "", "root-acme", "docs/notes.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != 32 {
		t.Fatalf("unit key %q", k1)
	}
	if id, ok := eng.HarnessFor("/usr/local/bin/claude"); !ok || id != harness.ClaudeCode {
		t.Fatalf("HarnessFor(claude) = %v %v", id, ok)
	}
	if _, ok := eng.HarnessFor("/bin/ls"); ok {
		t.Fatal("ls is a harness")
	}
	if code := a.run([]string{"sweep", "--quiet"}); code != exitOK {
		t.Fatalf("sweep on an empty home: exit %d", code)
	}
}
