package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/config"
)

// D91: the forged shapes of a decodable pin.
func TestPinnedCheckShape(t *testing.T) {
	cfg := config.Default()
	cfg.Roots = []config.Root{{ID: "0123456789abcdef0123456789abcdef", Path: "/x/a"}}
	root := cfg.Roots[0].ID
	mac := strings.Repeat("ab", 32)
	exists := func(id string) bool { return id == root || id == config.PinnedGlobalVault }
	for _, tc := range []struct {
		name string
		macs map[string]string
		ok   bool
	}{
		{"root MAC", map[string]string{root: mac}, true},
		{"global MAC", map[string]string{config.PinnedGlobalVault: mac}, true},
		{"no MAC", nil, false},
		{"malformed", map[string]string{root: "zz"}, false},
		{"outside the settings", map[string]string{"fedcba9876543210fedcba9876543210": mac}, false},
	} {
		err := config.Pinned{Config: cfg, MACs: tc.macs}.CheckShape(exists)
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, config.ErrForgedPin)) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	missing := func(id string) bool { return false }
	if err := (config.Pinned{Config: cfg, MACs: map[string]string{root: mac}}).CheckShape(missing); !errors.Is(err, config.ErrForgedPin) {
		t.Errorf("a MAC for a vault that does not exist: %v", err)
	}
}
