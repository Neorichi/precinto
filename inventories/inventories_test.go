package inventories_test

import (
	"bytes"
	"io/fs"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/inventories"
)

// Every embedded inventory decodes strictly into harness.Inventory (no key
// the schema does not know) and passes the loader's validation.
func TestEveryInventoryDecodesStrictly(t *testing.T) {
	t.Parallel()
	names, err := fs.Glob(inventories.FS, "*.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 2 {
		t.Fatalf("embedded inventories = %v, want at least claude-code and codex", names)
	}
	for _, n := range names {
		data, err := fs.ReadFile(inventories.FS, n)
		if err != nil {
			t.Fatal(err)
		}
		var inv harness.Inventory
		md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&inv)
		if err != nil {
			t.Errorf("%s: %v", n, err)
			continue
		}
		if und := md.Undecoded(); len(und) > 0 {
			t.Errorf("%s: undecoded keys %v", n, und)
		}
		if _, err := harness.LoadInventory(inventories.FS, n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	all, err := harness.LoadInventories(inventories.FS)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]harness.Inventory{}
	for _, inv := range all {
		seen[inv.ID] = inv
	}
	for _, id := range []string{"claude-code", "codex"} {
		if _, ok := seen[id]; !ok {
			t.Errorf("built-in inventory %s missing", id)
		}
	}
	for id, inv := range seen {
		if id != "claude-code" && id != "codex" && inv.Status != "experimental" {
			t.Errorf("%s: status %q, want experimental (D33)", id, inv.Status)
		}
	}
}

// The Codex deny-list mirrors SPEC §7.2 exactly (fail closed, HA24).
func TestCodexNeverTouchMatchesSpec(t *testing.T) {
	t.Parallel()
	inv, err := harness.LoadInventory(inventories.FS, "codex")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"auth.json", "config.toml", "hooks.json", "plugins/**", "skills/**", "cache/**",
		"packages/**", "models_cache.json", "installation_id", "version.json",
		".tmp/**", "tmp/**", "thread-writer-locks/**", "app-server-control/**", "log/**",
		"rollout-maintenance.lock", "*-shm",
	}
	if len(inv.NeverTouch) != len(want) {
		t.Fatalf("never_touch = %v, want %v", inv.NeverTouch, want)
	}
	for i := range want {
		if inv.NeverTouch[i] != want[i] {
			t.Fatalf("never_touch[%d] = %q, want %q", i, inv.NeverTouch[i], want[i])
		}
	}
}
