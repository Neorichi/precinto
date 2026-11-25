package agent

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
)

// TestSameExecutableGate: every operation that needs a precinto peer
// refuses another executable before doing anything (SPEC §13.2).
func TestSameExecutableGate(t *testing.T) {
	x := startTD(t)
	ctx := context.Background()
	other := platform.Peer{UID: os.Getuid(), PID: 4300, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 4300, StartUS: 9}, TTY: "/dev/ttys009"}}
	x.addProc(4100, 1, 4100, "/opt/homebrew/bin/claude", "claude")
	x.setPeer(&other, false)
	c := x.dial()
	checks := map[string]error{}
	_, checks["unlock"] = c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true}, nil)
	_, _, checks["keys"] = c.Keys(ctx, ipc.KeysReq{Purpose: ipc.PurposeRestore})
	checks["vault_create"] = c.VaultCreate(ctx, ipc.VaultCreateReq{RootID: "root-acme", RootPath: x.h.Root}, nil)
	checks["factor_add"] = c.FactorAdd(ctx, ipc.FactorAddReq{Kind: "passphrase"}, nil)
	_, checks["vault_repair"] = c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", Confirmed: true}, nil, nil)
	_, checks["policy confirm"] = c.Policy(ctx, ipc.PolicyReq{Confirm: true})
	for op, err := range checks {
		if ipcCode(err) != ipc.CodeUnauthorized {
			t.Errorf("%s from another executable = %v", op, err)
		}
	}
	if x.vaults.count("root-acme") != 0 || len(x.vaults.created) != 0 {
		t.Fatal("a refused request reached the vault")
	}
	// Registrations: wrapper=true from another executable is unwrapped.
	if err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sidA, PID: 4100, Cwd: x.h.Root, Wrapper: true, WrapperPID: 4300}); err != nil {
		t.Fatal(err)
	}
	if x.d.snap.Load().snap.Sessions[sidA].Info.Wrapper {
		t.Fatal("wrapper registration accepted from another executable")
	}
	// Listing pending policy and locking need only the uid.
	if _, err := c.Policy(ctx, ipc.PolicyReq{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lock(ctx, ipc.LockReq{}); err != nil {
		t.Fatal(err)
	}
}

// TestLockDefaultsToAllAndCompletes: `precinto lock` with no folder locks
// every folder (D50) and completes even when the seal worker cannot be
// spawned (I15).
func TestLockDefaultsToAllAndCompletes(t *testing.T) {
	x := startTD(t, func(x *td, o *Options) {
		o.Spawn = func([]string, platform.SpawnOptions) (platform.ProcID, error) {
			return platform.ProcID{}, errors.New("no space left on device")
		}
	})
	c := x.dial()
	ctx := context.Background()
	if _, err := c.Unlock(ctx, ipc.UnlockReq{All: true, TTY: true, Confirmed: true}, nil); err != nil {
		t.Fatal(err)
	}
	r, err := c.Lock(ctx, ipc.LockReq{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.Locked, "root-acme") || !slices.Contains(r.Locked, "root-beta") {
		t.Fatalf("locked = %v", r.Locked)
	}
	if x.vaultState("root-acme") != VaultLocked || x.vaultState("root-beta") != VaultLocked || len(x.keys.IDs()) != 0 {
		t.Fatal("lock did not complete with a failing seal worker")
	}
}

// TestForgedPidNeverSignalled is the last part of SEC-19: lock --end
// --force never reaches a process named only by a forged gate pid.
func TestForgedPidNeverSignalled(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	vim := x.addProc(5100, 1, 5100, "/usr/bin/vim", "vim")
	fake := x.addProc(5200, 1, 5200, "/opt/homebrew/bin/claude", "claude") // a claude nobody registered
	_, _ = c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "UserPromptSubmit", SID: sidA, PID: vim.ID.PID, Cwd: x.h.Root})
	_, _ = c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "UserPromptSubmit", SID: sidB, PID: fake.ID.PID, Cwd: x.h.Root})
	time.Sleep(50 * time.Millisecond)
	if _, err := c.Lock(ctx, ipc.LockReq{All: true, End: true, Force: true}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	for _, s := range x.rec.snapshot() {
		if s.ID == vim.ID || s.ID == fake.ID {
			t.Fatalf("signalled %+v on gate evidence only", s)
		}
	}
}

// TestRawProtocolFuzz sends malformed and random requests: the daemon
// survives, answers or drops the connection, and never sends an identity.
func TestRawProtocolFuzz(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	if _, err := c.Unlock(context.Background(), ipc.UnlockReq{All: true, TTY: true, Confirmed: true}, nil); err != nil {
		t.Fatal(err)
	}
	ops := []string{"hello", "status", "gate", "activity", "register", "unregister", "unlock", "ui_reply", "lock", "keys",
		"subscribe", "vault_create", "factor_add", "vault_repair", "policy", "x", ""}
	fields := []string{`"gate":{"event":"PreToolUse","sid":"s","cwd":"/"}`, `"keys":{"capsules":[{"path":"md/x/g000001.pcap"}],"purpose":"cat"}`,
		`"lock":{}`, `"unlock":{"root_ids":["root-acme"],"tty":true}`, `"register":{"harness":"claude-code","pid":1}`,
		`"activity":{"kind":"input","sid":"s"}`, `"policy":{"confirm":true}`, `"secrets":2`, `"v":2`, `"origin":"human"`}
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 120; i++ {
		conn, err := net.Dial("unix", x.h.Layout.Socket)
		if err != nil {
			t.Fatal(err)
		}
		_ = ipc.WriteFrame(conn, ipc.FrameJSON, []byte(`{"v":1,"id":1,"op":"hello","hello":{"client":"fuzz","version":"1"}}`))
		var body []string
		body = append(body, `"v":1`, `"id":2`, `"op":"`+ops[rnd.Intn(len(ops))]+`"`)
		for j := rnd.Intn(3); j > 0; j-- {
			body = append(body, fields[rnd.Intn(len(fields))])
		}
		_ = ipc.WriteFrame(conn, ipc.FrameJSON, []byte("{"+strings.Join(body, ",")+"}"))
		if rnd.Intn(4) == 0 {
			_ = ipc.WriteFrame(conn, ipc.FrameSecret, []byte("AGE-SECRET-KEY-1FUZZ"))
		}
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		for {
			k, p, err := ipc.ReadFrame(conn, nil)
			if err != nil {
				break
			}
			if k == ipc.FrameJSON {
				var resp ipc.Response
				_ = json.Unmarshal(p, &resp)
			}
			if strings.Contains(strings.ToUpper(string(p)), "AGE-SECRET-KEY") || strings.Contains(string(p), "FAKEroot") {
				t.Fatalf("identity on the wire: %q", p)
			}
		}
		conn.Close()
	}
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatalf("daemon broken by the fuzz: %v", err)
	}
}

// TestLoaderEnvRefusedBeforeHardening checks the default Harden seam: a
// DYLD_*/LD_* environment is refused first (the test process itself is
// never hardened: the refusal returns before platform.Harden), and the
// RLIMIT_MEMLOCK raise (CC-17) follows a successful hardening only; its
// failure is logged, never fatal.
func TestLoaderEnvRefusedBeforeHardening(t *testing.T) {
	hardened, raised := 0, 0
	fake := func() error { hardened++; return nil }  // never the real platform.Harden here
	memlock := func() error { raised++; return nil } // never the test process's own limits
	for _, env := range []map[string]string{{"DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"}, {"LD_PRELOAD": "/tmp/x.so"}} {
		if err := hardenWith(paths.FromMap(env), fake, memlock)(); !errors.Is(err, platform.ErrUnsafeEnv) {
			t.Fatalf("Harden with %v = %v (SEC-12)", env, err)
		}
	}
	if hardened != 0 || raised != 0 {
		t.Fatalf("hardened %d / memlock raised %d despite a loader environment", hardened, raised)
	}
	if err := hardenWith(paths.FromMap(map[string]string{"HOME": "/h"}), fake, memlock)(); err != nil || hardened != 1 || raised != 1 {
		t.Fatalf("clean environment: %v, hardened %d, memlock raised %d", err, hardened, raised)
	}
	failing := func() error { return errors.New("hardening failed") }
	if err := hardenWith(paths.FromMap(nil), failing, memlock)(); err == nil || raised != 1 {
		t.Fatalf("failed hardening = %v, memlock raised %d (must stop before it)", err, raised)
	}
	if err := hardenWith(paths.FromMap(nil), fake, func() error { return errors.New("EPERM") })(); err != nil {
		t.Fatalf("a memlock limit that cannot be raised is fatal: %v", err)
	}
}
