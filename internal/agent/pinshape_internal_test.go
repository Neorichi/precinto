package agent

import (
	"bytes"
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ipc"
)

// weakened is config.toml after a one-shot writer weakened it: idle_soft
// 10 h, no lock at screen lock, and (drop) root-beta removed.
func (x *td) weakened(drop bool) config.Config {
	cfg := x.h.Cfg
	cfg.Policy.IdleSoft = config.Duration(10 * time.Hour)
	cfg.Policy.LockOnScreenLock = false
	if drop {
		cfg.Roots = slices.DeleteFunc(slices.Clone(cfg.Roots), func(r config.Root) bool { return r.ID == "root-beta" })
	}
	if err := config.Save(x.h.Layout.ConfigFile, cfg); err != nil {
		x.t.Fatal(err)
	}
	return cfg
}

func (x *td) plant(p config.Pinned) []byte {
	x.t.Helper()
	p.Version = config.PinnedVersion
	if err := config.SavePinned(x.h.Layout.PolicyPinned, p); err != nil {
		x.t.Fatal(err)
	}
	b, err := os.ReadFile(x.h.Layout.PolicyPinned)
	if err != nil {
		x.t.Fatal(err)
	}
	return b
}

func (x *td) pinBytes() []byte {
	x.t.Helper()
	b, err := os.ReadFile(x.h.Layout.PolicyPinned)
	if err != nil {
		x.t.Fatal(err)
	}
	return b
}

// TestForgedPinShapes is SEC-23 for pins that decode but have a shape
// precinto never writes (D91, SEC-F1): no MAC, a MAC for a root the
// pinned settings do not hold, a MAC for a vault that does not exist.
// Each raises policy-tampered right after the restart, the defaults join
// the strictest merge, and a plain TTY unlock leaves the pin alone.
func TestForgedPinShapes(t *testing.T) {
	mac := strings.Repeat("0", 64)
	for _, tc := range []struct {
		name string
		pin  func(cfg config.Config) config.Pinned
	}{
		{"no MAC", func(cfg config.Config) config.Pinned { return config.Pinned{Config: cfg, MACs: map[string]string{}} }},
		{"MAC of a root outside the pinned settings", func(cfg config.Config) config.Pinned {
			return config.Pinned{Config: cfg, MACs: map[string]string{"root-beta": mac}}
		}},
		{"MAC of a vault that does not exist", func(cfg config.Config) config.Pinned {
			c := cfg
			c.Roots = append(slices.Clone(cfg.Roots), config.Root{ID: "root-zeta", Path: cfg.Roots[0].Path + "-zeta"})
			return config.Pinned{Config: c, MACs: map[string]string{"root-zeta": mac}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := startTD(t)
			c := x.dial()
			if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Lock(context.Background(), ipc.LockReq{All: true}); err != nil {
				t.Fatal(err)
			}
			planted := x.plant(tc.pin(x.weakened(true)))
			x.restart()
			c = x.dial()
			if _, ok := x.attention(c)[ipc.AttnPolicyTampered]; !ok {
				t.Fatal("a forged pin is not policy-tampered after the restart")
			}
			eff := x.d.effective()
			if eff.Policy.IdleSoft.D() != 15*time.Minute || !eff.Policy.LockOnScreenLock {
				t.Fatalf("effective policy %+v: the defaults did not join the merge", eff.Policy)
			}
			if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(x.pinBytes(), planted) {
				t.Fatal("a plain TTY unlock re-pinned a forged pin")
			}
		})
	}
}

// D91: a well-formed MAC for a folder that stays in the settings but is
// locked is not checked until that folder unlocks: unlocking another
// folder never re-pins the unauthenticated pin (it lists the settings to
// confirm instead), and unlocking the named folder raises policy-tampered.
func TestUnverifiedPinIsNeverLaundered(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lock(context.Background(), ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	cfg := x.weakened(false)
	planted := x.plant(config.Pinned{Config: cfg, MACs: map[string]string{"root-beta": strings.Repeat("0", 64)}})
	x.restart()
	c = x.dial()
	if _, ok := x.attention(c)[ipc.AttnPolicyTampered]; ok {
		t.Fatal("a well-formed pin reported as tampered before any unlock")
	}
	resp, err := x.unlockTTY(c, nil, "root-acme")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x.pinBytes(), planted) {
		t.Fatal("an unauthenticated pin was re-pinned by an unlock of another folder")
	}
	if len(resp.Pending) == 0 {
		t.Fatal("the unlock did not list the settings to confirm")
	}
	if _, err := x.unlockTTY(c, nil, "root-beta"); err != nil {
		t.Fatal(err)
	}
	x.eventually("policy-tampered", func() bool { _, ok := x.attention(c)[ipc.AttnPolicyTampered]; return ok })
}

// D91: the genuine two-folder flow (per-folder unlocks): the pin written
// after unlocking root-acme survives a restart and unlocks of root-beta
// and then root-acme without policy-tampered, and ends with a MAC per
// folder.
func TestGenuinePinCollectsAMACPerFolder(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	x.restart()
	c = x.dial()
	for _, id := range []string{"root-beta", "root-acme"} {
		if _, err := x.unlockTTY(c, nil, id); err != nil {
			t.Fatal(err)
		}
		if _, ok := x.attention(c)[ipc.AttnPolicyTampered]; ok {
			t.Fatalf("a genuine pin reported as tampered after unlocking %s", id)
		}
	}
	p, ok, err := config.LoadPinned(x.h.Layout.PolicyPinned)
	if err != nil || !ok || p.MACs["root-acme"] == "" || p.MACs["root-beta"] == "" {
		t.Fatalf("final pin MACs %v (%v %v)", p.MACs, ok, err)
	}
	// Both entries are kept across another restart and a single unlock.
	x.restart()
	c = x.dial()
	if _, err := x.unlockTTY(c, nil, "root-beta"); err != nil {
		t.Fatal(err)
	}
	p, _, _ = config.LoadPinned(x.h.Layout.PolicyPinned)
	if p.MACs["root-acme"] == "" || p.MACs["root-beta"] == "" {
		t.Fatalf("pin MACs after a restart %v", p.MACs)
	}
}

// D91: `policy confirm` after a lock emptied the key holder writes no
// pin without a MAC.
func TestConfirmAfterLockWritesNoMACLessPin(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	before := x.pinBytes()
	x.weakened(false)
	x.eventually("pending", func() bool { _, ok := x.attention(c)[ipc.AttnPendingPolicy]; return ok })
	if _, err := c.Lock(context.Background(), ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Policy(context.Background(), ipc.PolicyReq{Confirm: true})
	p, ok, err := config.LoadPinned(x.h.Layout.PolicyPinned)
	if err != nil || !ok || len(p.MACs) == 0 {
		t.Fatalf("pin after confirm %+v %v %v", p, ok, err)
	}
	if !bytes.Equal(x.pinBytes(), before) {
		t.Fatal("the pin changed without a vault to sign it")
	}
}
