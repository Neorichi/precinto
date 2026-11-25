package harness_test

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/live"
	"github.com/Neorichi/precinto/internal/platform"
)

// stubAdapter is the smallest harness.Adapter: the registry only uses ID.
type stubAdapter struct {
	id  harness.ID
	tag string
}

func (s stubAdapter) ID() harness.ID { return s.id }
func (s stubAdapter) Homes(context.Context, harness.Env) ([]harness.Home, error) {
	return nil, nil
}
func (s stubAdapter) Scan(context.Context, harness.Env, harness.Scope) ([]harness.Unit, error) {
	return nil, nil
}
func (s stubAdapter) Probe(context.Context, harness.Env, harness.Unit) ([]live.Evidence, error) {
	return nil, nil
}
func (s stubAdapter) Targets(context.Context, harness.Env, harness.UnitRef, string) (harness.TargetRules, error) {
	return harness.TargetRules{}, nil
}
func (s stubAdapter) PlanLaunch(context.Context, harness.Env, string, []string) (harness.LaunchPlan, error) {
	return harness.LaunchPlan{}, nil
}
func (s stubAdapter) MarkdownPaths(context.Context, harness.Env, harness.Unit) ([]string, error) {
	return nil, nil
}
func (s stubAdapter) Describe(context.Context, harness.Env, harness.Unit) (string, time.Time, error) {
	return "", time.Time{}, nil
}

// The registry is process-wide; this is the only test that registers.
func TestRegistryOrderLookupAndReplace(t *testing.T) {
	a := stubAdapter{id: "test-a", tag: "first"}
	b := stubAdapter{id: "test-b"}
	harness.Register(a)
	harness.Register(nil) // ignored
	harness.Register(b)
	if got, ok := harness.Get("test-a"); !ok || got.(stubAdapter).tag != "first" {
		t.Fatalf("Get(test-a) = %v, %v", got, ok)
	}
	if _, ok := harness.Get("test-missing"); ok {
		t.Fatal("Get found an unregistered harness")
	}
	harness.Register(stubAdapter{id: "test-a", tag: "second"}) // replaces in place
	var ids []harness.ID
	for _, ad := range harness.All() {
		if strings.HasPrefix(string(ad.ID()), "test-") {
			ids = append(ids, ad.ID())
		}
	}
	if !reflect.DeepEqual(ids, []harness.ID{"test-a", "test-b"}) {
		t.Fatalf("All order = %v", ids)
	}
	if got, _ := harness.Get("test-a"); got.(stubAdapter).tag != "second" {
		t.Fatalf("re-registration did not replace the adapter")
	}
	// All returns a copy.
	all := harness.All()
	all[0] = nil
	if harness.All()[0] == nil {
		t.Fatal("All exposes the registry slice")
	}
}

func TestUnitRefCopiesIdentity(t *testing.T) {
	t.Parallel()
	u := harness.Unit{
		Harness: harness.ClaudeCode, Kind: capsule.KindClaudeSession, Key: "k", VaultID: "root-acme",
		RootIDs: []string{"root-acme", "root-b"}, Home: harness.Home{ID: "0123456789abcdef"},
	}
	r := u.Ref()
	want := harness.UnitRef{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeSession, Key: "k",
		VaultID: "root-acme", RootIDs: []string{"root-acme", "root-b"}, HomeID: "0123456789abcdef"}
	if !reflect.DeepEqual(r, want) {
		t.Fatalf("Ref = %+v, want %+v", r, want)
	}
	r.RootIDs[0] = "changed"
	if u.RootIDs[0] != "root-acme" {
		t.Fatal("Ref aliases the unit's RootIDs")
	}
}

const validInventory = `schema = 1
id = "demo"
name = "Demo CLI"
status = "experimental"
verified_versions = ""
mode = "home"
open_fd_check = true
partition = "home"
content = ["demo_home:sessions/**", "demo_home:db.sqlite"]
exclude = ["demo_home:sessions/cache/**"]
passthrough = [["--version"], ["auth", "login"]]
direct = [["run"], ["--print"]]
stop_cmd = ["demo", "stop"]

[[bases]]
name = "demo_home"
default = "~/.demo"
env = "DEMO_HOME"

[process]
exe_basenames = ["demo"]
exe_paths = ["~/.demo/bin/*"]
argv_regex = ["(^|/)demo(\\.js)?$"]

[[locks]]
glob = "demo_home:locks/*.lock"
kind = "json-pid"

[resume]
flags = ["--resume"]
`

func TestLoadInventoryValid(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{"demo.toml": {Data: []byte(validInventory)}}
	for _, name := range []string{"demo", "demo.toml"} {
		inv, err := harness.LoadInventory(fsys, name)
		if err != nil {
			t.Fatalf("LoadInventory(%q): %v", name, err)
		}
		if inv.ID != "demo" || inv.Mode != "home" || !inv.OpenFDCheck || len(inv.Content) != 2 ||
			inv.Locks[0].Kind != "json-pid" || inv.Bases[0].Env != "DEMO_HOME" {
			t.Fatalf("decoded %+v", inv)
		}
	}
}

func TestLoadInventoryErrors(t *testing.T) {
	t.Parallel()
	mutate := func(old, new string) string {
		if !strings.Contains(validInventory, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(validInventory, old, new, 1)
	}
	cases := map[string]string{
		"unknown top-level key": validInventory + "\nsurprise = true\n",
		"unknown table key":     mutate(`exe_basenames = ["demo"]`, `exe_basenames = ["demo"]`+"\nexe_name = \"demo\""),
		"bad schema":            mutate("schema = 1", "schema = 2"),
		"not experimental":      mutate(`status = "experimental"`, `status = "verified"`),
		"unknown status":        mutate(`status = "experimental"`, `status = "beta"`),
		"capsule mode":          mutate(`mode = "home"`, `mode = "capsule"`),
		"unknown base in glob":  mutate(`"demo_home:db.sqlite"`, `"other:db.sqlite"`),
		"escaping glob":         mutate(`"demo_home:db.sqlite"`, `"demo_home:../db.sqlite"`),
		"absolute glob":         mutate(`"demo_home:db.sqlite"`, `"demo_home:/etc/passwd"`),
		"bare content glob":     mutate(`"demo_home:db.sqlite"`, `"db.sqlite"`),
		"bad lock kind":         mutate(`kind = "json-pid"`, `kind = "fcntl"`),
		"bad regex":             mutate(`argv_regex = ["(^|/)demo(\\.js)?$"]`, `argv_regex = ["(unclosed"]`),
		"no matcher":            mutate("exe_basenames = [\"demo\"]\nexe_paths = [\"~/.demo/bin/*\"]\nargv_regex = [\"(^|/)demo(\\\\.js)?$\"]", ""),
		"relative default":      mutate(`default = "~/.demo"`, `default = "demo"`),
		"unknown placeholder":   mutate(`default = "~/.demo"`, `default = "~/.demo-{user}"`),
		"bad env":               mutate(`env = "DEMO_HOME"`, `env = "demo-home"`),
		"no content":            mutate(`content = ["demo_home:sessions/**", "demo_home:db.sqlite"]`, `content = []`),
		"no partition":          mutate(`partition = "home"`, `partition = ""`),
		"slug without glob":     mutate(`partition = "home"`, `partition = "project-slug"`),
		"unknown partition":     mutate(`partition = "home"`, `partition = "per-file"`),
		"empty passthrough":     mutate(`passthrough = [["--version"], ["auth", "login"]]`, `passthrough = [[]]`),
		"id mismatch":           mutate(`id = "demo"`, `id = "other"`),
		"not toml":              "schema = = 1",
	}
	for name, data := range cases {
		fsys := fstest.MapFS{"demo.toml": {Data: []byte(data)}}
		if _, err := harness.LoadInventory(fsys, "demo"); err == nil {
			t.Errorf("%s: LoadInventory accepted it", name)
		}
	}
	if _, err := harness.LoadInventory(fstest.MapFS{}, "demo"); !errors.Is(err, harness.ErrUnknownHarness) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing inventory: err = %v", err)
	}
	for _, name := range []string{"", "../demo", "sub/demo", "Demo", "demo toml"} {
		if _, err := harness.LoadInventory(fstest.MapFS{}, name); err == nil {
			t.Errorf("LoadInventory(%q) accepted a bad name", name)
		}
	}
	if _, err := harness.LoadInventory(nil, "demo"); err == nil {
		t.Error("LoadInventory(nil) succeeded")
	}
	big := fstest.MapFS{"demo.toml": {Data: []byte(validInventory + "\n#" + strings.Repeat("x", 1<<20))}}
	if _, err := harness.LoadInventory(big, "demo"); err == nil {
		t.Error("LoadInventory accepted an oversize file")
	}
}

func TestLoadInventoriesSortedAndDuplicates(t *testing.T) {
	t.Parallel()
	other := strings.NewReplacer(`id = "demo"`, `id = "alpha"`).Replace(validInventory)
	fsys := fstest.MapFS{
		"demo.toml":  {Data: []byte(validInventory)},
		"alpha.toml": {Data: []byte(other)},
		"notes.txt":  {Data: []byte("ignored")},
	}
	invs, err := harness.LoadInventories(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(invs) != 2 || invs[0].ID != "alpha" || invs[1].ID != "demo" {
		t.Fatalf("LoadInventories = %v", invs)
	}
	fsys["broken.toml"] = &fstest.MapFile{Data: []byte("schema = 1\n")}
	if _, err := harness.LoadInventories(fsys); err == nil {
		t.Fatal("LoadInventories accepted an invalid file")
	}
}

func inventory(t *testing.T) harness.Inventory {
	t.Helper()
	inv, err := harness.LoadInventory(fstest.MapFS{"demo.toml": {Data: []byte(validInventory)}}, "demo")
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestMatchProcess(t *testing.T) {
	t.Parallel()
	inv := inventory(t)
	id := platform.ProcID{PID: 42, StartUS: 1}
	cases := []struct {
		name string
		p    platform.ProcInfo
		want bool
	}{
		{"exe basename", platform.ProcInfo{ID: id, Exe: "/usr/local/bin/demo"}, true},
		{"exe path under any home", platform.ProcInfo{ID: id, Exe: "/Users/someone/.demo/bin/2.0.1"}, true},
		{"exe path needs a home prefix", platform.ProcInfo{ID: id, Exe: "/.demo/bin/2.0.1"}, false},
		{"exe path glob does not cross /", platform.ProcInfo{ID: id, Exe: "/h/.demo/bin/x/y"}, false},
		{"node CLI by argv[1]", platform.ProcInfo{ID: id, Exe: "/usr/bin/node", Argv: []string{"node", "/opt/lib/demo.js", "--x"}}, true},
		{"argv[1] of a non-interpreter", platform.ProcInfo{ID: id, Exe: "/usr/bin/vim", Argv: []string{"vim", "/tmp/demo"}}, false},
		{"argv[0]", platform.ProcInfo{ID: id, Argv: []string{"/opt/demo"}}, true},
		{"kernel name is never used", platform.ProcInfo{ID: id, Exe: "/usr/bin/other", Comm: "demo"}, false},
		{"zombie", platform.ProcInfo{ID: id, Exe: "/usr/local/bin/demo", State: platform.StateZombie}, false},
		{"no pid", platform.ProcInfo{Exe: "/usr/local/bin/demo"}, false},
		{"unknown exe", platform.ProcInfo{ID: id}, false},
	}
	for _, c := range cases {
		if got := inv.MatchProcess(c.p); got != c.want {
			t.Errorf("%s: MatchProcess = %v, want %v", c.name, got, c.want)
		}
	}
	abs := harness.Inventory{Process: harness.ProcessMatch{ExePaths: []string{"/opt/demo/*/demo"}}}
	if !abs.MatchProcess(platform.ProcInfo{ID: id, Exe: "/opt/demo/1.2/demo"}) || abs.MatchProcess(platform.ProcInfo{ID: id, Exe: "/x/opt/demo/1.2/demo"}) {
		t.Error("absolute exe_paths must match the whole path")
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()
	inv := inventory(t)
	cases := []struct {
		args          []string
		stdin, stdout bool
		want          harness.LaunchMode
	}{
		{[]string{"--version"}, true, true, harness.LaunchPassthrough},
		{[]string{"auth", "login"}, true, true, harness.LaunchPassthrough},
		{[]string{"auth"}, true, true, harness.LaunchInteractive},
		{[]string{"chat", "--version"}, true, true, harness.LaunchInteractive}, // passthrough is a prefix only
		{[]string{"run", "x"}, true, true, harness.LaunchDirect},
		{[]string{"--model", "m", "--print", "hi"}, true, true, harness.LaunchDirect},
		{[]string{"--print=json"}, true, true, harness.LaunchDirect},
		{[]string{"--", "--print"}, true, true, harness.LaunchInteractive},
		{nil, true, true, harness.LaunchInteractive},
		{nil, false, true, harness.LaunchDirect},
		{nil, true, false, harness.LaunchDirect},
		{[]string{"--version"}, false, false, harness.LaunchPassthrough},
	}
	for _, c := range cases {
		if got := inv.Classify(c.args, c.stdin, c.stdout); got != c.want {
			t.Errorf("Classify(%q, %v, %v) = %s, want %s", c.args, c.stdin, c.stdout, got, c.want)
		}
	}
}
