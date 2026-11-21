package main

import (
	"os"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/testkit"
)

// TestFloorPolicy (D76, D55, D68): the floor every seal and restore keeps
// free is policy.min_free of config.Strictest(config.toml, the pin); the
// defaults stand in for a missing or unreadable pin. A weakening edit of
// config.toml waits for the pin (a TTY confirmation), a strengthening one
// applies at once.
func TestFloorPolicy(t *testing.T) {
	const gib, mib = int64(1) << 30, int64(1) << 20
	for _, c := range []struct {
		name     string
		cfg, pin config.Size // pin 0: no pin; -1: an unreadable pin
		want     int64
	}{
		{"defaults", config.DefaultMinFree, 0, 2 * gib},
		{"lowered before the first pin", 512 << 20, 0, 2 * gib},
		{"raised before the first pin", 8 << 30, 0, 8 * gib},
		{"lowered and confirmed (pinned)", 512 << 20, 512 << 20, 512 * mib},
		{"lowered, the pin keeps the old floor", 512 << 20, 4 << 30, 4 * gib},
		{"raised above the pin", 8 << 30, 2 << 30, 8 * gib},
		{"unreadable pin: the defaults", 512 << 20, -1, 2 * gib},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := testkit.NewHome(t)
			cfg := h.Cfg
			cfg.Policy.MinFree = c.cfg
			switch {
			case c.pin < 0:
				if err := os.WriteFile(h.Layout.PolicyPinned, []byte("{not json"), 0o600); err != nil {
					t.Fatal(err)
				}
			case c.pin > 0:
				pinned := h.Cfg
				pinned.Policy.MinFree = c.pin
				if err := config.SavePinned(h.Layout.PolicyPinned, config.Pinned{ConfirmedAt: time.Unix(0, 0).UTC(), Config: pinned, MACs: map[string]string{}}); err != nil {
					t.Fatal(err)
				}
			}
			f := floorPolicy(cfg, h.Layout).Floor()
			if f.MinBytes != c.want || f.MinFraction != 0 {
				t.Errorf("floor = %+v, want a fixed %d bytes", f, c.want)
			}
		})
	}
}
