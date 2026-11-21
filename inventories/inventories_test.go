package inventories_test

import (
	"bytes"
	"io/fs"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/platform"
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
		"rollout-maintenance.lock", "*-shm", ".precinto-auth",
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

// The Codex inventory matches the native binary and an npm install (node
// running the codex bin script or its shim as argv[1]), the process
// `precinto run codex` registers; never another program that merely names
// a file "codex", nor a zombie.
func TestCodexInventoryMatchesNpmInstalls(t *testing.T) {
	t.Parallel()
	inv, err := harness.LoadInventory(inventories.FS, "codex.toml")
	if err != nil {
		t.Fatal(err)
	}
	proc := func(exe string, argv ...string) platform.ProcInfo {
		return platform.ProcInfo{ID: platform.ProcID{PID: 4242, StartUS: 1}, Exe: exe, Argv: argv}
	}
	for _, c := range []struct {
		name string
		p    platform.ProcInfo
		want bool
	}{
		{"native", proc("/opt/homebrew/bin/codex", "codex"), true},
		{"npm bin script", proc("/usr/local/bin/node", "node", "/usr/local/lib/node_modules/@openai/codex/bin/codex.js"), true},
		{"npm shim", proc("/opt/homebrew/bin/node", "node", "/opt/homebrew/bin/codex", "exec"), true},
		{"versioned node", proc("/usr/local/bin/node22", "node22", "/x/@openai/codex/bin/codex.js"), true},
		{"editor on a file named codex", proc("/usr/bin/vim", "vim", "codex"), false},
		{"node running another script", proc("/usr/local/bin/node", "node", "/x/codexify.js"), false},
		{"a shell script", proc("/bin/sh", "/bin/sh", "/usr/local/bin/codex"), false},
	} {
		if got := inv.MatchProcess(c.p); got != c.want {
			t.Errorf("%s: MatchProcess = %v, want %v", c.name, got, c.want)
		}
	}
	z := proc("/usr/local/bin/node", "node", "/x/@openai/codex/bin/codex.js")
	z.State = platform.StateZombie
	if inv.MatchProcess(z) {
		t.Error("a zombie npm codex matched")
	}
}
