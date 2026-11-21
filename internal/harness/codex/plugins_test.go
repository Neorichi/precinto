package codex_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/precinto/precinto/internal/harness/codex"
)

// strictTOML fails unless cfg is valid TOML for a strict parser (duplicate
// tables, redefinitions): what Codex's own reader accepts.
func strictTOML(t *testing.T, name, cfg string) map[string]any {
	t.Helper()
	var v map[string]any
	if _, err := toml.Decode(cfg, &v); err != nil {
		t.Fatalf("%s: not valid TOML: %v\n%s", name, err, cfg)
	}
	return v
}

func readCfg(t *testing.T, home string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// D99 (M2): a folder's home seeded before `precinto integrate codex` picks
// up the plugin at its next launch: the [marketplaces.*] and [plugins.*]
// tables the user's config gained are added to the per-root config (values
// and trust entries it has stay), and a plugins/ directory Codex created
// there while the user had none is replaced by the link (kept next to the
// home), so the plugin loads and /hooks can list it.
func TestPrepareHomePicksUpALaterIntegrate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	user, home := filepath.Join(dir, "codex-user"), filepath.Join(dir, "base", "homes", "codex", "root-acme")
	if err := os.MkdirAll(user, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(user, "config.toml"), []byte("model = \"gpt-codextest\"\n\n[tui]\nanimations = false\n"), 0o600)
	// 1. First `precinto run codex` in the folder; the user has no plugins/.
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
		t.Fatal(err)
	}
	// Codex creates its own plugins/ in the home it runs in, and the user
	// trusts something there.
	os.MkdirAll(filepath.Join(home, "plugins", "cache", "openai-curated", "x"), 0o700)
	os.WriteFile(filepath.Join(home, "plugins", "cache", "openai-curated", "x", "keep"), []byte("curated"), 0o600)
	cfg := readCfg(t, home) + "\n[hooks.state.\"local:hooks.json:stop:0:0\"]\ntrusted_hash = \"sha256:local\"\n"
	os.WriteFile(filepath.Join(home, "config.toml"), []byte(cfg), 0o600)
	if _, _, err := codex.HooksTrusted(home); !errors.Is(err, codex.ErrPluginMissing) {
		t.Fatalf("before integrate: %v, want the plugin missing", err)
	}
	// 2. `precinto integrate codex` writes into the user's home only.
	ucfg := readCfg(t, user) + installPlugin(t, user)
	os.WriteFile(filepath.Join(user, "config.toml"), []byte(ucfg), 0o600)
	// 3. The next launch.
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
		t.Fatal(err)
	}
	got := readCfg(t, home)
	v := strictTOML(t, "per-root config", got)
	plugins, _ := v["plugins"].(map[string]any)
	entry, _ := plugins["precinto@precinto"].(map[string]any)
	if entry["enabled"] != true {
		t.Fatalf("the plugin table was not added:\n%s", got)
	}
	if m, _ := v["marketplaces"].(map[string]any); m["precinto"] == nil {
		t.Fatalf("the marketplace table was not added:\n%s", got)
	}
	if !strings.HasPrefix(got, cfg) {
		t.Fatalf("the per-root config was rewritten, not extended:\n%s", got)
	}
	if target, err := os.Readlink(filepath.Join(home, "plugins")); err != nil || target != filepath.Join(user, "plugins") {
		t.Fatalf("plugins/ = %q %v, want the link to the user's", target, err)
	}
	kept, _ := filepath.Glob(filepath.Join(home+".displaced", "plugins-*", "cache", "openai-curated", "x", "keep"))
	if len(kept) != 1 {
		t.Fatalf("Codex's own plugins directory was not kept: %v", kept)
	}
	if _, err := os.Stat(filepath.Join(home, "plugins", "cache", "precinto", "precinto", "0.2.0")); err != nil {
		t.Fatalf("the home cannot reach the plugin: %v", err)
	}
	if _, known, err := codex.HooksTrusted(home); !known || err != nil {
		t.Fatalf("after the next launch the plugin loads (hooks not trusted yet): known %v err %v", known, err)
	}
	// Idempotent: a further launch changes nothing.
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
		t.Fatal(err)
	}
	if again := readCfg(t, home); again != got {
		t.Fatalf("a second launch changed the config:\n%s", again)
	}
	// sync-config (ForceConfig) re-copies the user's config and keeps the
	// per-root trust entries.
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home, ForceConfig: true}); err != nil {
		t.Fatal(err)
	}
	if forced := readCfg(t, home); !strings.Contains(forced, "sha256:local") || strings.Count(forced, `[plugins."precinto@precinto"]`) != 1 {
		t.Fatalf("sync-config:\n%s", forced)
	}
}

// D99: the merge only adds what the per-root config lacks, in the form
// Codex writes, and never breaks or changes the per-root config.
func TestPluginTablesMerge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	userCfg := "model = \"m\"\n\n[marketplaces.precinto]\nsource_type = \"local\"\nsource = \"/u/src/precinto\"\n\n" +
		"[plugins.\"precinto@precinto\"]\nenabled = true\n\n[plugins.\"other@market\"]\nenabled = true\n"
	for _, c := range []struct {
		name, perRoot string
		check         func(t *testing.T, got string)
	}{
		{"the folder turned the plugin off", "model = \"m\"\n\n[plugins.\"precinto@precinto\"]\nenabled = false\n",
			func(t *testing.T, got string) {
				v := strictTOML(t, "merged", got)
				p := v["plugins"].(map[string]any)
				if p["precinto@precinto"].(map[string]any)["enabled"] != false || p["other@market"] == nil {
					t.Errorf("per-root value changed or other plugin missing:\n%s", got)
				}
			}},
		{"dotted keys below the root", "model = \"m\"\nplugins.\"precinto@precinto\".enabled = false\n",
			func(t *testing.T, got string) {
				v := strictTOML(t, "merged", got)
				if v["plugins"].(map[string]any)["precinto@precinto"].(map[string]any)["enabled"] != false {
					t.Errorf("dotted per-root value changed:\n%s", got)
				}
			}},
		{"an inline plugins table", "model = \"m\"\nplugins = { \"precinto@precinto\" = { enabled = false } }\n",
			func(t *testing.T, got string) {
				v := strictTOML(t, "merged", got)
				if _, ok := v["plugins"].(map[string]any)["other@market"]; ok {
					t.Errorf("a table was added to an inline plugins table:\n%s", got)
				}
				if v["marketplaces"] == nil {
					t.Errorf("the marketplaces family was not merged:\n%s", got)
				}
			}},
		{"no trailing newline, CRLF", "model = \"m\"\r\n[tui]\r\nanimations = false",
			func(t *testing.T, got string) {
				v := strictTOML(t, "merged", got)
				if v["tui"].(map[string]any)["animations"] != false || v["plugins"] == nil {
					t.Errorf("merge after a CRLF file:\n%s", got)
				}
			}},
	} {
		dir := t.TempDir()
		user, home := filepath.Join(dir, "u"), filepath.Join(dir, "h")
		os.MkdirAll(user, 0o700)
		os.MkdirAll(home, 0o700)
		os.WriteFile(filepath.Join(user, "config.toml"), []byte(userCfg), 0o600)
		os.WriteFile(filepath.Join(home, "config.toml"), []byte(c.perRoot), 0o600)
		if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		t.Run(c.name, func(t *testing.T) { c.check(t, readCfg(t, home)) })
	}
	// A user entity defined only by dotted keys is not copied; a user
	// config that does not parse adds nothing and fails nothing.
	dir := t.TempDir()
	user, home := filepath.Join(dir, "u"), filepath.Join(dir, "h")
	os.MkdirAll(user, 0o700)
	os.MkdirAll(home, 0o700)
	os.WriteFile(filepath.Join(home, "config.toml"), []byte("model = \"m\"\n"), 0o600)
	os.WriteFile(filepath.Join(user, "config.toml"), []byte("model = \"m\"\n[plugins]\n\"precinto@precinto\".enabled = true\n"), 0o600)
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
		t.Fatal(err)
	}
	if got := readCfg(t, home); got != "model = \"m\"\n" {
		t.Errorf("a dotted-key plugin entry was copied:\n%s", got)
	}
	os.WriteFile(filepath.Join(user, "config.toml"), []byte("model = = broken\n[plugins.\"precinto@precinto\"]\nenabled = true\n"), 0o600)
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
		t.Fatalf("an unparseable user config failed the launch of a seeded home: %v", err)
	}
	if got := readCfg(t, home); got != "model = \"m\"\n" {
		t.Errorf("an unparseable user config changed the per-root one:\n%s", got)
	}
}

// D98: sync-config (ForceConfig) keeps the folder's own trust entries,
// except that a stale entry of a precinto hook (Codex skips that hook)
// yields to the user's entry for the current declaration; a current
// folder entry is kept over a stale one of the user's.
func TestForceConfigPrefersCurrentTrust(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	golden := codex.GoldenTrust(t)
	stale := func(string) string { return "sha256:" + strings.Repeat("0", 64) }
	current := func(k string) string { return golden[k] }
	dir := t.TempDir()
	user, home := filepath.Join(dir, "u"), filepath.Join(dir, "h")
	os.MkdirAll(user, 0o700)
	plugin := installPlugin(t, user)
	for _, c := range []struct {
		name           string
		userT, rootT   func(string) string
		trusted        bool
		modifiedResult bool
	}{
		{"stale folder trust, current user trust", current, stale, true, false},
		{"current folder trust, stale user trust", stale, current, true, false},
		{"both stale", stale, stale, false, true},
	} {
		os.RemoveAll(home)
		os.MkdirAll(home, 0o700)
		os.WriteFile(filepath.Join(user, "config.toml"), []byte("model = \"m\"\n"+plugin+trustTables("precinto@precinto", c.userT, golden)), 0o600)
		os.WriteFile(filepath.Join(home, "config.toml"), []byte("model = \"m\"\n"+trustTables("precinto@precinto", c.rootT, golden)+
			"\n[hooks.state.\"local:hooks.json:stop:0:0\"]\ntrusted_hash = \"sha256:local\"\n"), 0o600)
		if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home, ForceConfig: true}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := readCfg(t, home)
		strictTOML(t, c.name, got)
		trusted, _, err := codex.HooksTrusted(home)
		if trusted != c.trusted || errors.Is(err, codex.ErrHooksModified) != c.modifiedResult {
			t.Errorf("%s: trusted %v err %v\n%s", c.name, trusted, err, got)
		}
		if !strings.Contains(got, "sha256:local") {
			t.Errorf("%s: the folder's own trust of another hook was dropped", c.name)
		}
		if n := strings.Count(got, "hooks/codex.json:stop:0:0"); n != 1 {
			t.Errorf("%s: %d entries for one hook", c.name, n)
		}
	}
}

// sync-config keeps the trusted_content_hash a Codex newer than 0.154
// writes next to a trust entry (the plugin contents it approved): dropping
// it would have that Codex ask for the hook's trust again.
func TestForceConfigKeepsNewerCodexTrust(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	user, home := filepath.Join(dir, "u"), filepath.Join(dir, "h")
	os.MkdirAll(user, 0o700)
	os.MkdirAll(home, 0o700)
	os.WriteFile(filepath.Join(user, "config.toml"), []byte("model = \"m\"\n"), 0o600)
	entry := "[hooks.state.\"local:hooks.json:stop:0:0\"]\ntrusted_hash = \"sha256:local\"\ntrusted_content_hash = \"sha256:" + strings.Repeat("c", 64) + "\"\n"
	os.WriteFile(filepath.Join(home, "config.toml"), []byte("model = \"old\"\n\n"+entry), 0o600)
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home, ForceConfig: true}); err != nil {
		t.Fatal(err)
	}
	got := readCfg(t, home)
	strictTOML(t, "newer Codex trust", got)
	if !strings.Contains(got, entry) || !strings.HasPrefix(got, "model = \"m\"\n") {
		t.Errorf("sync-config lost a trusted_content_hash:\n%s", got)
	}
}
