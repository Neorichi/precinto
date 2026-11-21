package codex_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/harness/codex/codextest"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/inventories"
)

var salt = []byte("precinto-test-salt-0123456789abc")

func TestClassifyDenyListAndSQLiteGroups(t *testing.T) {
	t.Parallel()
	cases := map[string]codex.Class{
		"auth.json":                           codex.ClassNeverTouch,
		"config.toml":                         codex.ClassNeverTouch,
		"hooks.json":                          codex.ClassNeverTouch,
		"plugins":                             codex.ClassNeverTouch,
		"plugins/cache/x/plugin.json":         codex.ClassNeverTouch,
		"skills/a/SKILL.md":                   codex.ClassNeverTouch,
		"cache/codex_apps/x":                  codex.ClassNeverTouch,
		"packages/p":                          codex.ClassNeverTouch,
		"models_cache.json":                   codex.ClassNeverTouch,
		"installation_id":                     codex.ClassNeverTouch,
		"version.json":                        codex.ClassNeverTouch,
		".tmp/arg0":                           codex.ClassNeverTouch,
		"tmp/arg0/x":                          codex.ClassNeverTouch,
		"thread-writer-locks/x.lock":          codex.ClassNeverTouch,
		"thread-writer-locks":                 codex.ClassNeverTouch,
		"app-server-control/sock":             codex.ClassNeverTouch,
		"log/codex-tui.log":                   codex.ClassNeverTouch,
		"rollout-maintenance.lock":            codex.ClassNeverTouch,
		"state_5.sqlite-shm":                  codex.ClassSHM,
		"sub/x.sqlite-shm":                    codex.ClassSHM,
		"state_5.sqlite":                      codex.ClassSQLiteMain,
		"logs_2.sqlite":                       codex.ClassSQLiteMain,
		"state_5.sqlite-wal":                  codex.ClassSQLiteSide,
		"state_5.sqlite-journal":              codex.ClassSQLiteSide,
		"sessions/2026/11/21/rollout-x.jsonl": codex.ClassContent,
		"history.jsonl":                       codex.ClassContent,
		"session_index.jsonl":                 codex.ClassContent,
		"shell_snapshots/x.sh":                codex.ClassContent,
		"precinto-tmp/hook_outputs/x":         codex.ClassContent,
		"memories/m.md":                       codex.ClassContent,
		"a-new-file-of-a-newer-codex":         codex.ClassContent, // fail closed (HA24)
		"auth.json.bak":                       codex.ClassContent,
		"../auth.json":                        codex.ClassNeverTouch,
		"/abs/path":                           codex.ClassNeverTouch,
		"sessions/../auth.json":               codex.ClassNeverTouch,
		"":                                    codex.ClassNeverTouch,
	}
	if runtime.GOOS == "darwin" {
		cases["Auth.JSON"] = codex.ClassNeverTouch // one file on APFS
		cases["Plugins/x"] = codex.ClassNeverTouch
	}
	for rel, want := range cases {
		if got := codex.Classify(rel); got != want {
			t.Errorf("Classify(%q) = %s, want %s", rel, got, want)
		}
	}
	groups := map[string]string{
		"state_5.sqlite": "state_5.sqlite", "state_5.sqlite-wal": "state_5.sqlite",
		"state_5.sqlite-journal": "state_5.sqlite", "state_5.sqlite-shm": "state_5.sqlite",
		"sub/x.sqlite-wal": "sub/x.sqlite", "history.jsonl": "", "x.sqlite.bak": "", "../x.sqlite": "",
	}
	for rel, want := range groups {
		if got := codex.GroupOf(rel); got != want {
			t.Errorf("GroupOf(%q) = %q, want %q", rel, got, want)
		}
	}
	// The deny-list mirrors the embedded inventory.
	inv, err := harness.LoadInventory(inventories.FS, "codex")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range inv.NeverTouch {
		probe := strings.ReplaceAll(strings.ReplaceAll(g, "/**", "/x"), "*", "state_5.sqlite")
		if c := codex.Classify(probe); c != codex.ClassNeverTouch && c != codex.ClassSHM {
			t.Errorf("inventory never_touch %q (probe %q) classified %s", g, probe, c)
		}
	}
}

func TestApplyPatchPaths(t *testing.T) {
	t.Parallel()
	patch := "*** Begin Patch\r\n" +
		"*** Add File: docs/new.md\r\n+# x\r\n" +
		"*** Update File: /abs/src/main.go\n@@\n-a\n+b\n" +
		"*** Update File: docs/old.md\n*** Move to: notes/moved.md\n" +
		"*** Add File: docs/new.md\n" + // duplicate
		"*** Delete File: docs/gone.md\n" +
		"*** Add File:    \n" +
		"*** End Patch\n"
	got := codex.ApplyPatchPaths([]byte(patch), "/u/work/acme")
	want := []string{"/u/work/acme/docs/new.md", "/abs/src/main.go", "/u/work/acme/docs/old.md", "/u/work/acme/notes/moved.md"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ApplyPatchPaths = %v, want %v", got, want)
	}
	if got := codex.ApplyPatchPaths([]byte(patch), "relative"); !reflect.DeepEqual(got, []string{"/abs/src/main.go"}) {
		t.Fatalf("relative cwd: %v", got)
	}
	if got := codex.ApplyPatchPaths(nil, "/u"); got != nil {
		t.Fatalf("empty patch: %v", got)
	}
}

func TestLaunchEnvAndUserHome(t *testing.T) {
	t.Parallel()
	env := codex.LaunchEnv("/u/base/homes/codex/root-acme/")
	want := []string{"CODEX_HOME=/u/base/homes/codex/root-acme", "CODEX_SQLITE_HOME=/u/base/homes/codex/root-acme",
		"TMPDIR=/u/base/homes/codex/root-acme/precinto-tmp"}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("LaunchEnv = %v", env)
	}
	h, err := codex.UserHome(paths.FromMap(map[string]string{"HOME": "/u", "CODEX_HOME": "/u/my-codex"}))
	if err != nil || h != "/u/my-codex" {
		t.Fatalf("UserHome with CODEX_HOME = %q %v", h, err)
	}
	if h, err := codex.UserHome(paths.FromMap(map[string]string{"HOME": "/u"})); err != nil || h != "/u/.codex" {
		t.Fatalf("UserHome default = %q %v", h, err)
	}
	if _, err := codex.UserHome(paths.FromMap(map[string]string{"HOME": "/u", "CODEX_HOME": "rel"})); err == nil {
		t.Fatal("relative CODEX_HOME accepted")
	}
	if _, err := codex.UserHome(paths.FromMap(nil)); err == nil {
		t.Fatal("no HOME accepted")
	}
}

const userConfig = `# the user's Codex configuration
model = "gpt-codextest"
sqlite_home = "/somewhere/else"   # would move the databases out of the sealed home
"log_dir" = '''
/var/log/codex'''
model_reasoning_effort = "low"

[history]
persistence = "save-all"

[projects."/u/work/acme"]
trust_level = "trusted"

[hooks.state."precinto@precinto:hooks/codex.json:session_start:0:0"]
trusted_hash = "sha256:user-old"
`

func seedFixture(t *testing.T) (user, home string) {
	t.Helper()
	dir := t.TempDir()
	user, home = filepath.Join(dir, "codex-user"), filepath.Join(dir, "base", "homes", "codex", "root-acme")
	codextest.New(t, user, codextest.Options{Rollouts: 1})
	os.WriteFile(filepath.Join(user, "config.toml"), []byte(userConfig), 0o600)
	os.MkdirAll(filepath.Join(user, "plugins", "cache"), 0o755)
	os.MkdirAll(filepath.Join(user, "skills"), 0o755)
	return user, home
}

func TestPrepareHomeSeedsOnce(t *testing.T) {
	t.Parallel()
	user, home := seedFixture(t)
	ctx := context.Background()
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(home)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("home %v %v", fi.Mode(), err)
	}
	if fi, err := os.Lstat(filepath.Join(home, "precinto-tmp")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("precinto-tmp: %v", err)
	}
	cfg, _ := os.ReadFile(filepath.Join(home, "config.toml"))
	c := string(cfg)
	if strings.Contains(c, "sqlite_home") || strings.Contains(c, "log_dir") || strings.Contains(c, "/var/log/codex") {
		t.Fatalf("sqlite_home/log_dir not stripped:\n%s", c)
	}
	for _, keep := range []string{`model = "gpt-codextest"`, `model_reasoning_effort = "low"`, "[history]", `[projects."/u/work/acme"]`, "# the user's Codex configuration", "sha256:user-old"} {
		if !strings.Contains(c, keep) {
			t.Errorf("seeded config lost %q", keep)
		}
	}
	if fi, _ := os.Stat(filepath.Join(home, "config.toml")); fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v", fi.Mode().Perm())
	}
	for _, name := range []string{"plugins", "skills"} {
		target, err := os.Readlink(filepath.Join(home, name))
		if err != nil || target != filepath.Join(user, name) {
			t.Errorf("%s link = %q %v", name, target, err)
		}
	}
	ua, _ := os.ReadFile(filepath.Join(user, "auth.json"))
	ha, err := os.ReadFile(filepath.Join(home, "auth.json"))
	if err != nil || string(ha) != string(ua) {
		t.Fatalf("auth.json not synced in: %v", err)
	}
	// Seeded once: a later user edit is not copied without ForceConfig, and
	// content files are never touched.
	os.WriteFile(filepath.Join(home, "history.jsonl"), []byte("{}\n"), 0o600)
	os.WriteFile(filepath.Join(user, "config.toml"), []byte("model = \"changed\"\n"), 0o600)
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
		t.Fatal(err)
	}
	if cfg2, _ := os.ReadFile(filepath.Join(home, "config.toml")); string(cfg2) != c {
		t.Fatal("config re-seeded without ForceConfig")
	}
	if h, _ := os.ReadFile(filepath.Join(home, "history.jsonl")); string(h) != "{}\n" {
		t.Fatal("PrepareHome touched a content file")
	}
	// A real plugins directory in the home is never replaced.
	other := t.TempDir()
	os.MkdirAll(filepath.Join(other, "plugins", "mine"), 0o700)
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: other}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(other, "plugins", "mine")); err != nil {
		t.Fatal("an existing plugins directory was replaced")
	}
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: "relative"}); err == nil {
		t.Fatal("relative root home accepted")
	}
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: home, RootHome: home}); err == nil {
		t.Fatal("seeding a home from itself accepted")
	}
}

func TestPrepareHomeForceConfigKeepsTrust(t *testing.T) {
	t.Parallel()
	user, home := seedFixture(t)
	ctx := context.Background()
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
		t.Fatal(err)
	}
	// The user trusted precinto's hooks inside the folder's session: the
	// per-root config has newer trust entries than the user's.
	cfg := filepath.Join(home, "config.toml")
	cur, _ := os.ReadFile(cfg)
	trust := strings.Replace(string(cur), "sha256:user-old", "sha256:root-new", 1) +
		"\n[hooks.state.\"precinto@precinto:hooks/codex.json:stop:0:0\"]\ntrusted_hash = \"sha256:root-stop\"\nenabled = false\n"
	os.WriteFile(cfg, []byte(trust), 0o600)
	// A root-level key added by the user (keys after the last table header
	// would belong to that table).
	os.WriteFile(filepath.Join(user, "config.toml"), []byte("model_verbosity = \"high\"\n"+userConfig), 0o600)
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home, ForceConfig: true}); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(cfg)
	s := string(out)
	if !strings.Contains(s, `model_verbosity = "high"`) {
		t.Fatalf("ForceConfig did not re-copy:\n%s", s)
	}
	if strings.Contains(s, "sha256:user-old") || !strings.Contains(s, "sha256:root-new") || !strings.Contains(s, "sha256:root-stop") || !strings.Contains(s, "enabled = false") {
		t.Fatalf("trust entries not kept:\n%s", s)
	}
	if strings.Count(s, "session_start:0:0") != 1 || strings.Contains(s, "sqlite_home") {
		t.Fatalf("duplicate or unstripped entries:\n%s", s)
	}
	// An unparseable user config is never copied (fail closed).
	os.WriteFile(filepath.Join(user, "config.toml"), []byte("model = = broken\n"), 0o600)
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home, ForceConfig: true}); err == nil {
		t.Fatal("an unparseable config was seeded")
	}
	if now, _ := os.ReadFile(cfg); string(now) != s {
		t.Fatal("a failed re-seed changed the per-root config")
	}
}

func TestSyncAuthBack(t *testing.T) {
	t.Parallel()
	user, home := seedFixture(t)
	ctx := context.Background()
	if err := codex.PrepareHome(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
		t.Fatal(err)
	}
	// Unchanged: nothing is copied back.
	ua := filepath.Join(user, "auth.json")
	before, _ := os.Stat(ua)
	if err := codex.SyncAuthBack(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(ua); !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("an unchanged auth.json was copied back")
	}
	// Codex refreshed the token in the sealed home.
	ha := filepath.Join(home, "auth.json")
	os.WriteFile(ha, []byte(`{"tokens":"codextest-refreshed"}`), 0o600)
	future := time.Now().Add(time.Minute)
	os.Chtimes(ha, future, future)
	if err := codex.SyncAuthBack(ctx, codex.Seed{UserHome: user, RootHome: home}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(ua); string(got) != `{"tokens":"codextest-refreshed"}` {
		t.Fatalf("auth.json not synced back: %s", got)
	}
	if fi, _ := os.Stat(ua); fi.Mode().Perm() != 0o600 {
		t.Fatalf("auth.json mode %v", fi.Mode().Perm())
	}
	// An older copy never overwrites a newer one.
	os.WriteFile(ha, []byte(`{"tokens":"codextest-stale"}`), 0o600)
	past := time.Now().Add(-time.Hour)
	os.Chtimes(ha, past, past)
	codex.SyncAuthBack(ctx, codex.Seed{UserHome: user, RootHome: home})
	if got, _ := os.ReadFile(ua); string(got) != `{"tokens":"codextest-refreshed"}` {
		t.Fatal("a stale token overwrote a newer one")
	}
	// No user home: nothing is created.
	missing := filepath.Join(t.TempDir(), "no-codex")
	if err := codex.SyncAuthBack(ctx, codex.Seed{UserHome: missing, RootHome: home}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("SyncAuthBack created the user's home")
	}
}

func TestHooksTrusted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if trusted, known, err := codex.HooksTrusted(dir); trusted || !known || err != nil {
		t.Fatalf("no config: %v %v %v", trusted, known, err)
	}
	events := []string{"session_start", "user_prompt_submit", "pre_tool_use", "permission_request", "post_tool_use",
		"pre_compact", "post_compact", "stop", "interrupt", "session_end"}
	var b strings.Builder
	b.WriteString("model = \"m\"\n\n[hooks]\n")
	// Mix every TOML form Codex or a user could use: a dotted key below
	// [hooks], an inline table and a dotted key below [hooks.state], and
	// [hooks.state."…"] tables (what Codex's own writer produces).
	b.WriteString("state.\"precinto@precinto:hooks/codex.json:session_start:0:0\".trusted_hash = \"sha256:1\"\n")
	b.WriteString("\n[hooks.state]\n\"precinto@precinto:hooks/codex.json:user_prompt_submit:0:0\" = { trusted_hash = \"sha256:2\" }\n")
	b.WriteString("\"precinto@precinto:hooks/codex.json:pre_tool_use:0:0\".trusted_hash = \"sha256:3\"\n")
	for _, ev := range events[3:] {
		b.WriteString("\n[hooks.state.\"precinto@precinto:hooks/codex.json:" + ev + ":0:0\"]\ntrusted_hash = \"sha256:x\"\n")
	}
	full := b.String()
	os.WriteFile(filepath.Join(dir, "config.toml"), []byte(full), 0o600)
	if trusted, known, err := codex.HooksTrusted(dir); !trusted || !known || err != nil {
		t.Fatalf("all trusted: %v %v %v\n%s", trusted, known, err, full)
	}
	// One hook disabled, or missing: not trusted.
	os.WriteFile(filepath.Join(dir, "config.toml"), []byte(full+"enabled = false\n"), 0o600)
	if trusted, known, _ := codex.HooksTrusted(dir); trusted || !known {
		t.Fatal("a disabled hook counted as trusted")
	}
	partial := strings.Replace(full, "session_end", "session_end_renamed", 1)
	os.WriteFile(filepath.Join(dir, "config.toml"), []byte(partial), 0o600)
	if trusted, _, _ := codex.HooksTrusted(dir); trusted {
		t.Fatal("a missing hook counted as trusted")
	}
	// Another plugin's trust entries do not count.
	other := strings.ReplaceAll(full, "precinto@precinto", "other@market")
	os.WriteFile(filepath.Join(dir, "config.toml"), []byte(other), 0o600)
	if trusted, _, _ := codex.HooksTrusted(dir); trusted {
		t.Fatal("another plugin's trust counted")
	}
	// Unparseable: unknown, not an error.
	os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[hooks\n"), 0o600)
	if trusted, known, err := codex.HooksTrusted(dir); trusted || known || err != nil {
		t.Fatalf("unparseable: %v %v %v", trusted, known, err)
	}
	if _, _, err := codex.HooksTrusted("relative"); err == nil {
		t.Fatal("relative home accepted")
	}
}

// fx is a fake HOME whose root has a per-root Codex home.
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
	f := &fx{t: t, h: h, a: codex.New(), home: h.Layout.CodexHome("root-acme")}
	f.e = harness.Env{Cfg: h.Cfg, Layout: h.Layout, Ledger: ledger.Open(h.Layout.SessionsDir),
		Procs: h.Procs, Clock: h.Clock, Salt: salt, Host: h.Env}
	return f
}

func (f *fx) seed(o codextest.Options) *codextest.Home {
	f.t.Helper()
	if err := codex.PrepareHome(context.Background(), codex.Seed{UserHome: f.h.CodexUser, RootHome: f.home}); err != nil {
		f.t.Fatal(err)
	}
	return codextest.New(f.t, f.home, o)
}

func TestScanHomeSnapshot(t *testing.T) {
	t.Parallel()
	f := newFx(t)
	units, err := f.a.Scan(context.Background(), f.e, harness.Scope{})
	if err != nil || len(units) != 0 {
		t.Fatalf("no home yet: %v %v", units, err)
	}
	marker := testkit.Marker(t)
	ch := f.seed(codextest.Options{Rollouts: 2, Marker: marker, WithWAL: true, WithLocks: true, Cwd: f.h.Root})
	os.Symlink("/etc/hosts", filepath.Join(f.home, "stray-link"))
	units, err = f.a.Scan(context.Background(), f.e, harness.Scope{})
	if err != nil || len(units) != 1 {
		t.Fatalf("Scan = %d units, %v", len(units), err)
	}
	u := units[0]
	key, _ := harness.UnitKeyFor(salt, capsule.KindCodexHome, harness.Codex, "", "root-acme", "")
	if u.Kind != capsule.KindCodexHome || u.Key != key || u.UnitID != "root-acme" || u.VaultID != "root-acme" ||
		u.Mode != harness.GenSnapshot || u.Home.RootID != "root-acme" || u.Home.Bases[capsule.BaseCodexHome] != f.home {
		t.Fatalf("unit %+v", u.Ref())
	}
	files := map[string]harness.File{}
	for _, file := range u.Files {
		files[file.Rel] = file
		if c := codex.Classify(file.Rel); c == codex.ClassNeverTouch || c == codex.ClassSHM {
			t.Errorf("sealed %s (%s)", file.Rel, c)
		}
	}
	for _, rel := range ch.Rollouts(t) {
		r, _ := filepath.Rel(f.home, rel)
		if file, ok := files[filepath.ToSlash(r)]; !ok || !file.Append || file.Placement != harness.PlaceExact {
			t.Errorf("rollout %s: %+v", r, file)
		}
	}
	if fl := files["state_5.sqlite"]; fl.Placement != harness.PlaceSQLiteGroup || fl.Group != "state_5.sqlite" {
		t.Errorf("db: %+v", fl)
	}
	if fl := files["state_5.sqlite-wal"]; fl.Group != "state_5.sqlite" {
		t.Errorf("wal: %+v", fl)
	}
	if _, ok := files["state_5.sqlite-shm"]; ok {
		t.Error("-shm sealed")
	}
	if fl := files["history.jsonl"]; fl.Placement != harness.PlaceLineUnion {
		t.Errorf("history: %+v", fl)
	}
	for _, rel := range []string{"auth.json", "config.toml", "thread-writer-locks/.coordination.lock"} {
		if _, ok := files[rel]; ok {
			t.Errorf("sealed never-touch %s", rel)
		}
	}
	if len(u.Hazards) != 1 || u.Hazards[0].Rel != "stray-link" {
		t.Errorf("hazards %+v (plugins/ and skills/ links are never-touch, other links are hazards)", u.Hazards)
	}
	dirs := map[string]bool{}
	for _, d := range u.Dirs {
		dirs[d.Rel] = true
	}
	if !dirs["precinto-tmp"] {
		t.Errorf("empty precinto-tmp not recorded: %v", u.Dirs)
	}
	// CC-19: prune entries are "<base id>:<rel>", deepest first, never the
	// home itself.
	if len(u.Prune) == 0 {
		t.Error("no prune entries")
	}
	depth := -1
	for i, pr := range u.Prune {
		base, rel, ok := strings.Cut(pr, ":")
		if !ok || base != string(capsule.BaseCodexHome) || rel == "" || rel == "." || strings.HasPrefix(rel, "/") {
			t.Errorf("prune entry %q", pr)
		}
		d := strings.Count(rel, "/")
		if i > 0 && d > depth {
			t.Errorf("prune entries not deepest first: %v", u.Prune)
		}
		depth = d
	}
	rules, err := f.a.Targets(context.Background(), f.e, u.Ref(), u.UnitID)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range u.Files {
		if !rules.Allow(file.Base, file.Rel) {
			t.Errorf("sealed %s cannot be restored", file.Rel)
		}
	}
	if units, _ := f.a.Scan(context.Background(), f.e, harness.Scope{SIDs: []string{"x"}}); len(units) != 0 {
		t.Error("a session-scoped scan returned the home")
	}
	if units, _ := f.a.Scan(context.Background(), f.e, harness.Scope{RootIDs: []string{"root-other"}}); len(units) != 0 {
		t.Error("another root's scan returned the home")
	}
}

// CC-21: a Codex session is sealed with its home. A scope naming sessions
// returns the homes that hold one of them (a rollout carries the id in its
// name, or the session's ledger names the home); Scope.Procs and
// Scope.Adopt change nothing for a home.
func TestScanScopesOfAHome(t *testing.T) {
	t.Parallel()
	f := newFx(t)
	ch := f.seed(codextest.Options{Rollouts: 2, Cwd: f.h.Root})
	rollouts := ch.Rollouts(t)
	if len(rollouts) == 0 {
		t.Fatal("no rollouts")
	}
	name := strings.TrimSuffix(filepath.Base(rollouts[0]), ".jsonl")
	sid := name[len(name)-36:]
	scan := func(s harness.Scope) int {
		t.Helper()
		units, err := f.a.Scan(context.Background(), f.e, s)
		if err != nil {
			t.Fatal(err)
		}
		return len(units)
	}
	for label, s := range map[string]harness.Scope{
		"rollout id":            {SIDs: []string{sid}},
		"rollout id, uppercase": {SIDs: []string{strings.ToUpper(sid)}},
		"rollout id in root":    {SIDs: []string{"x", sid}, RootIDs: []string{"root-acme"}},
		"child process":         {RootIDs: []string{"root-acme"}, Procs: []platform.ProcID{{PID: 7, StartUS: 7}}},
		"adopt":                 {Adopt: true},
	} {
		if n := scan(s); n != 1 {
			t.Errorf("%s: %d units, want the home", label, n)
		}
	}
	const other = "00000000-0000-7000-8000-0000000000ff"
	if n := scan(harness.Scope{SIDs: []string{other}}); n != 0 {
		t.Errorf("a session the home does not hold: %d units", n)
	}
	if err := f.e.Ledger.Append(ledger.Event{Type: ledger.TypeStart, Harness: "codex", SID: other, Source: "startup",
		ConfigDir: f.home, Cwd: f.h.Root}); err != nil {
		t.Fatal(err)
	}
	if n := scan(harness.Scope{SIDs: []string{other}}); n != 1 {
		t.Errorf("a session whose ledger names the home: %d units", n)
	}
	if n := scan(harness.Scope{SIDs: []string{sid}, RootIDs: []string{"root-other"}}); n != 0 {
		t.Errorf("another root's scope: %d units", n)
	}
}

func TestProbeHome(t *testing.T) {
	t.Parallel()
	f := newFx(t)
	f.seed(codextest.Options{Rollouts: 1, WithLocks: true})
	units, _ := f.a.Scan(context.Background(), f.e, harness.Scope{})
	u := units[0]
	probe := func() []live.Evidence {
		evs, err := f.a.Probe(context.Background(), f.e, u)
		if err != nil {
			t.Fatal(err)
		}
		return evs
	}
	if evs := probe(); len(evs) != 0 {
		t.Fatalf("idle home: %v", evs)
	}
	cx := platform.ProcInfo{ID: platform.ProcID{PID: 800, StartUS: 1}, PPID: 1, Exe: "/opt/codex/codex"}
	f.h.Procs.Add(cx)
	f.h.Procs.SetOpenFiles(800, filepath.Join(f.home, "thread-writer-locks", "x.lock"), filepath.Join(f.home, "state_5.sqlite"))
	evs := probe()
	reasons := map[live.Reason]int{}
	for _, e := range evs {
		reasons[e.Reason]++
	}
	if reasons[live.ReasonWriterLock] != 1 || reasons[live.ReasonOpenFD] != 1 {
		t.Fatalf("holders: %v", evs)
	}
	f.h.Procs.SetOpenFiles(800)
	f.h.Procs.SetErr(fakeplatform.OpOpenFilesUnder, errors.New("no lsof"))
	if evs := probe(); len(evs) != 1 || evs[0].Reason != live.ReasonOpenFD {
		t.Fatalf("failed check must be live (HA9): %v", evs)
	}
	if evs, _ := f.a.Probe(context.Background(), harness.Env{}, u); len(evs) == 0 {
		t.Fatal("no process table must be live")
	}
}

func TestTargetsHome(t *testing.T) {
	t.Parallel()
	f := newFx(t)
	ref := harness.UnitRef{Harness: harness.Codex, Kind: capsule.KindCodexHome, RootIDs: []string{"root-acme"}}
	rules, err := f.a.Targets(context.Background(), f.e, ref, "root-acme")
	if err != nil {
		t.Fatal(err)
	}
	if rules.Bases[capsule.BaseCodexHome] != f.home || rules.Mode != harness.GenSnapshot {
		t.Fatalf("rules %+v", rules)
	}
	for rel, want := range map[string]bool{
		"sessions/2026/11/21/rollout-x.jsonl": true, "state_5.sqlite": true, "state_5.sqlite-wal": true,
		"state_5.sqlite-shm": false, "auth.json": false, "config.toml": false, "plugins/x": false,
		"../x": false, "/abs": false, "thread-writer-locks/a.lock": false,
	} {
		if got := rules.Allow(capsule.BaseCodexHome, rel); got != want {
			t.Errorf("Allow(%s) = %v, want %v", rel, got, want)
		}
	}
	if rules.Allow(capsule.BaseClaudeConfig, "sessions/x") {
		t.Error("a foreign base was allowed")
	}
	for rel, want := range map[string]harness.Placement{
		"state_5.sqlite": harness.PlaceSQLiteGroup, "state_5.sqlite-journal": harness.PlaceSQLiteGroup,
		"history.jsonl": harness.PlaceLineUnion, "session_index.jsonl": harness.PlaceLineUnion,
		"sessions/a/rollout-x.jsonl": harness.PlaceExact,
	} {
		if got := rules.Policy(capsule.Entry{Base: capsule.BaseCodexHome, Rel: rel}); got != want {
			t.Errorf("Policy(%s) = %s, want %s", rel, got, want)
		}
	}
	for name, r := range map[string]struct {
		ref harness.UnitRef
		id  string
	}{
		"other unit id": {ref, "root-other"},
		"unknown root":  {harness.UnitRef{Harness: harness.Codex, Kind: capsule.KindCodexHome, RootIDs: []string{"root-gone"}}, ""},
		"no root":       {harness.UnitRef{Harness: harness.Codex, Kind: capsule.KindCodexHome}, ""},
		"claude kind":   {harness.UnitRef{Harness: harness.Codex, Kind: capsule.KindClaudeSession, RootIDs: []string{"root-acme"}}, ""},
		"claude ref":    {harness.UnitRef{Harness: harness.ClaudeCode, Kind: capsule.KindCodexHome, RootIDs: []string{"root-acme"}}, ""},
		"bad blob id":   {harness.UnitRef{Harness: harness.Codex, Kind: capsule.KindCodexBlob, RootIDs: []string{"root-acme"}}, "a/b"},
	} {
		if _, err := f.a.Targets(context.Background(), f.e, r.ref, r.id); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	blob := harness.UnitRef{Harness: harness.Codex, Kind: capsule.KindCodexBlob, RootIDs: []string{"root-acme"}}
	if _, err := f.a.Targets(context.Background(), f.e, blob, "0123456789abcdef"); err != nil {
		t.Errorf("blob: %v", err)
	}
}

func TestPlanLaunchCodex(t *testing.T) {
	t.Parallel()
	f := newFx(t)
	bin := filepath.Join(f.h.Dir, "bin", "codex")
	os.MkdirAll(filepath.Dir(bin), 0o700)
	os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700)
	hc := f.e.Cfg.Harness["codex"]
	hc.Bin = bin
	f.e.Cfg.Harness["codex"] = hc
	codextest.New(t, f.h.CodexUser, codextest.Options{})
	ctx := context.Background()

	plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"codex"})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := harness.UnitKeyFor(salt, capsule.KindCodexHome, harness.Codex, "", "root-acme", "")
	if plan.Mode != harness.LaunchInteractive || plan.Argv[0] != bin || len(plan.Roots) != 1 ||
		!reflect.DeepEqual(plan.Env, codex.LaunchEnv(f.home)) || plan.Lease[0] != key ||
		len(plan.Sync) != 1 || plan.Sync[0].Keys[0] != key || plan.Sync[0].Kind != capsule.KindCodexHome {
		t.Fatalf("plan %+v", plan)
	}
	// D72: the folder lists codex, so its first launch (no home yet) asks
	// nothing; consent is per folder, in config.
	if plan.Confirm != "" {
		t.Errorf("a folder that lists codex was asked %q", plan.Confirm)
	}
	if !reflect.DeepEqual(plan.SealScope, harness.Scope{RootIDs: []string{"root-acme"}, Kinds: []capsule.Kind{capsule.KindCodexHome}}) {
		t.Errorf("seal scope %+v", plan.SealScope)
	}
	// CC-24: Ctrl-C twice (Codex has no SIGTERM handler), 3 s + 6 s.
	if string(plan.QuitKeys) != "\x03\x03" || plan.KillGrace != 9*time.Second {
		t.Errorf("termination %q %v", plan.QuitKeys, plan.KillGrace)
	}
	if plan.HookCheck.Event != "UserPromptSubmit" || !plan.HookCheck.OnInput || plan.HookCheck.Within != 5*time.Second {
		t.Errorf("hook check %+v", plan.HookCheck)
	}
	if err := plan.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.home, "auth.json")); err != nil {
		t.Fatal("Prepare did not seed the home")
	}
	if err := plan.Finish(ctx, 0); err != nil {
		t.Fatal(err)
	}
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"codex", "resume", "--last"})
	if plan.Confirm != "C9.codex" || plan.Resume.Kind != harness.ResumeContinue {
		t.Errorf("hooks untrusted / resume --last: %+v", plan)
	}
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"codex", "exec", "resume", "00000000-0000-7000-8000-00000000000A"})
	if plan.Mode != harness.LaunchDirect || plan.Resume.Kind != harness.ResumeSID || plan.Resume.Value != "00000000-0000-7000-8000-00000000000a" {
		t.Errorf("exec resume: %+v", plan)
	}
	// CC-21: a known resume target scopes the seal after exit (the home
	// that holds it); a fork writes a new session.
	if !reflect.DeepEqual(plan.SealScope.SIDs, []string{"00000000-0000-7000-8000-00000000000a"}) || plan.SealScope.RootIDs[0] != "root-acme" {
		t.Errorf("exec resume seal scope: %+v", plan.SealScope)
	}
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"codex", "fork", "00000000-0000-7000-8000-00000000000a"})
	if !plan.Resume.Fork || len(plan.SealScope.SIDs) != 0 {
		t.Errorf("fork of a session: %+v %+v", plan.Resume, plan.SealScope)
	}
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"codex", "fork"})
	if plan.Resume.Kind != harness.ResumePicker || !plan.Resume.Fork {
		t.Errorf("fork picker: %+v", plan.Resume)
	}
	// D72: a folder whose harness list lacks codex asks C10.consent (with
	// {folder}) before anything else, whether or not its home exists; an
	// empty list is the default (every built-in harness).
	cfg := f.e.Cfg
	f.e.Cfg.Roots = append([]config.Root(nil), cfg.Roots...)
	f.e.Cfg.Roots[0].Harnesses = []string{"claude-code"}
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"codex"})
	if plan.Confirm != "C10.consent" || plan.MsgVars["folder"] != "~/work/acme" || plan.Mode != harness.LaunchInteractive || len(plan.Sync) != 1 {
		t.Errorf("folder without codex: confirm %q vars %v plan %+v", plan.Confirm, plan.MsgVars, plan)
	}
	os.RemoveAll(f.home)
	if plan, _ := f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"codex"}); plan.Confirm != "C10.consent" {
		t.Errorf("folder without codex, no home: confirm %q", plan.Confirm)
	}
	f.e.Cfg.Roots[0].Harnesses = nil
	if plan, _ := f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"codex"}); plan.Confirm != "" {
		t.Errorf("default harness list, no home: confirm %q", plan.Confirm)
	}
	f.e.Cfg = cfg
	// A launch through a symlink into the folder uses the folder's home.
	link := filepath.Join(t.TempDir(), "acme-link")
	if err := os.Symlink(f.h.Root, link); err != nil {
		t.Fatal(err)
	}
	if plan, _ := f.a.PlanLaunch(ctx, f.e, link, []string{"codex"}); plan.Mode != harness.LaunchInteractive || len(plan.Roots) != 1 ||
		!reflect.DeepEqual(plan.Env, codex.LaunchEnv(f.home)) {
		t.Errorf("symlinked cwd: %+v", plan)
	}
	// Passthrough inside a root and anything outside run unmanaged.
	plan, _ = f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"codex", "login"})
	if plan.Mode != harness.LaunchPassthrough || len(plan.Env) != 0 || len(plan.Sync) != 0 {
		t.Errorf("login: %+v", plan)
	}
	plan, _ = f.a.PlanLaunch(ctx, f.e, filepath.Join(f.h.HomeDir, "elsewhere"), []string{"codex"})
	if plan.Mode != harness.LaunchPassthrough || len(plan.Roots) != 0 || len(plan.Env) != 0 || plan.Prepare != nil {
		t.Errorf("outside: %+v", plan)
	}
	if _, err := f.a.PlanLaunch(ctx, f.e, "relative", []string{"codex"}); err == nil {
		t.Error("relative cwd accepted")
	}
}

func TestMarkdownPathsAndDescribe(t *testing.T) {
	t.Parallel()
	f := newFx(t)
	f.seed(codextest.Options{Rollouts: 2, Cwd: f.h.Root, RolloutAge: time.Hour})
	units, _ := f.a.Scan(context.Background(), f.e, harness.Scope{})
	md, err := f.a.MarkdownPaths(context.Background(), f.e, units[0])
	want := []string{filepath.Join(f.h.Root, "docs", "notes-0.md"), filepath.Join(f.h.Root, "docs", "notes-1.md")}
	if err != nil || !reflect.DeepEqual(md, want) {
		t.Fatalf("MarkdownPaths = %v %v, want %v", md, err, want)
	}
	title, last, err := f.a.Describe(context.Background(), f.e, units[0])
	if err != nil || title != "" || last.IsZero() || time.Since(last) < 50*time.Minute {
		t.Fatalf("Describe = %q %v %v", title, last, err)
	}
}

func TestCodextestAppenderAndCwd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	h := codextest.New(t, filepath.Join(dir, "home"), codextest.Options{Rollouts: 1, Cwd: "/u/work/acme"})
	r := h.Rollouts(t)[0]
	first, _ := os.ReadFile(r)
	if !strings.Contains(string(first), `"cwd":"/u/work/acme"`) {
		t.Fatal("Options.Cwd not recorded in session_meta")
	}
	a := codextest.StartAppender(t, r, 5*time.Millisecond)
	time.Sleep(40 * time.Millisecond)
	n := a.Stop()
	if n < 2 {
		t.Fatalf("appender wrote %d records", n)
	}
	if a.Stop() != n {
		t.Fatal("Stop is not idempotent")
	}
	data, _ := os.ReadFile(r)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != strings.Count(string(first), "\n")+n {
		t.Fatalf("records: %d lines, %d appended", len(lines), n)
	}
}
