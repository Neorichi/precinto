package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/config"
)

// D91: the forged shapes of a decodable pin; D145: settings that name
// folders carry a MAC of one of them; D130: the pinned policy keeps unlock
// prompts on.
func TestPinnedCheckShape(t *testing.T) {
	cfg := config.Default()
	cfg.Roots = []config.Root{{ID: "0123456789abcdef0123456789abcdef", Path: "/x/a"}}
	root := cfg.Roots[0].ID
	mac := strings.Repeat("ab", 32)
	exists := func(id string) bool { return id == root || id == config.PinnedGlobalVault }
	noRoots := config.Default()
	promptsOff := cfg
	promptsOff.Policy.PromptRatePerMinute = 0
	for _, tc := range []struct {
		name string
		cfg  config.Config
		macs map[string]string
		ok   bool
	}{
		{"root MAC", cfg, map[string]string{root: mac}, true},
		{"root and global MACs", cfg, map[string]string{root: mac, config.PinnedGlobalVault: mac}, true},
		{"global MAC of settings that name no folder", noRoots, map[string]string{config.PinnedGlobalVault: mac}, true},
		{"global MAC alone for settings that name a folder", cfg, map[string]string{config.PinnedGlobalVault: mac}, false},
		{"no MAC", cfg, nil, false},
		{"malformed", cfg, map[string]string{root: "zz"}, false},
		{"outside the settings", cfg, map[string]string{"fedcba9876543210fedcba9876543210": mac}, false},
		{"unlock prompts off", promptsOff, map[string]string{root: mac}, false},
	} {
		err := config.Pinned{Config: tc.cfg, MACs: tc.macs}.CheckShape(exists)
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, config.ErrForgedPin)) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	missing := func(id string) bool { return false }
	if err := (config.Pinned{Config: cfg, MACs: map[string]string{root: mac}}).CheckShape(missing); !errors.Is(err, config.ErrForgedPin) {
		t.Errorf("a MAC for a vault that does not exist: %v", err)
	}
}
