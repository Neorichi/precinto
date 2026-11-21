package agent

import (
	"context"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
)

// CC-12: the embedded inventories load, and each built-in adapter has one.
func TestEmbeddedInventoriesLoad(t *testing.T) {
	invs, err := loadInventories()
	if err != nil || len(invs) == 0 {
		t.Fatalf("inventories = %d, %v", len(invs), err)
	}
	for _, id := range []string{"claude-code", "codex"} {
		found := false
		for _, inv := range invs {
			found = found || inv.ID == id
		}
		if !found {
			t.Fatalf("no inventory for %s", id)
		}
	}
}

// CC-12: register verifies the executable with the harness's inventory
// (Inventory.MatchProcess): npm and native Claude installs are accepted,
// other programs refused; a generic inventory registers only when its
// harness is enabled in config.
func TestRegisterByInventory(t *testing.T) {
	x := startTD(t)
	ctx := context.Background()
	c := x.dial()
	sid := 0
	register := func(h string, p platform.ProcInfo) error {
		sid++
		return c.Register(ctx, ipc.RegisterReq{Harness: h, SID: "00000000-0000-4000-8000-0000000003" + string(rune('a'+sid)) + "0", PID: p.ID.PID, Cwd: x.h.Root})
	}
	npm := x.addProc(5300, 1, 5300, "/usr/local/bin/node", "node", "/usr/local/bin/claude", "--resume")
	native := x.addProc(5310, 1, 5310, x.h.HomeDir+"/.local/share/claude/versions/2.1.329", "claude")
	local := x.addProc(5320, 1, 5320, x.h.HomeDir+"/.claude/local/claude", "claude")
	vim := x.addProc(5330, 1, 5330, "/usr/bin/vim", "vim", "claude")
	codex := x.addProc(5340, 1, 5340, "/opt/homebrew/bin/codex", "codex")
	for name, p := range map[string]platform.ProcInfo{"npm": npm, "native": native, "local": local} {
		if err := register("claude-code", p); err != nil {
			t.Errorf("%s Claude refused: %v", name, err)
		}
	}
	if err := register("claude-code", vim); ipcCode(err) != ipc.CodeUnauthorized {
		t.Fatalf("vim as claude = %v", err)
	}
	if err := register("claude-code", codex); ipcCode(err) != ipc.CodeUnauthorized {
		t.Fatalf("codex as claude = %v", err)
	}
	if err := register("codex", codex); err != nil {
		t.Fatalf("codex = %v", err)
	}
	// npm's codex launcher (node running the bin script) is matched by the
	// codex inventory's argv_regex (CC-12); never another node program.
	npmCodex := x.addProc(5345, 1, 5345, "/usr/local/bin/node", "node", "/usr/local/lib/node_modules/@openai/codex/bin/codex.js")
	if err := register("codex", npmCodex); err != nil {
		t.Fatalf("npm codex = %v", err)
	}
	if err := register("claude-code", npmCodex); ipcCode(err) != ipc.CodeUnauthorized {
		t.Fatalf("npm codex as claude = %v", err)
	}
	notCodex := x.addProc(5346, 1, 5346, "/usr/local/bin/node", "node", "/srv/app/server.js")
	if err := register("codex", notCodex); ipcCode(err) != ipc.CodeUnauthorized {
		t.Fatalf("a node server as codex = %v", err)
	}
	if err := register("harness-nobody-ships", codex); ipcCode(err) != ipc.CodeUnauthorized {
		t.Fatalf("unknown harness = %v", err)
	}
	// A generic inventory (gemini runs as a node script).
	gemini := x.addProc(5350, 1, 5350, "/opt/homebrew/bin/node", "node", "/opt/homebrew/bin/gemini")
	if err := register("gemini", gemini); ipcCode(err) != ipc.CodeUnauthorized {
		t.Fatalf("gemini while not enabled = %v", err)
	}
	enableGeneric(t, x, "gemini")
	if err := register("gemini", gemini); err != nil {
		t.Fatalf("gemini once enabled = %v", err)
	}
	if err := register("gemini", vim); ipcCode(err) != ipc.CodeUnauthorized {
		t.Fatalf("vim as gemini = %v", err)
	}
}

// enableGeneric turns on an experimental inventory in config.toml, as
// `precinto integrate` does, and makes the daemon read it.
func enableGeneric(t *testing.T, x *td, id string) {
	t.Helper()
	cfg, err := config.Load(x.h.Layout.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Harness == nil {
		cfg.Harness = map[string]config.Harness{}
	}
	cfg.Harness[id] = config.Harness{Enabled: true, Experimental: true}
	if err := config.Save(x.h.Layout.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	x.d.reloadPolicy(context.Background())
	if !harnessEnabled(x.d.effective(), id) {
		t.Fatalf("%s not enabled after the config edit", id)
	}
}

// D52 with inventories: the scan reports an enabled generic harness running
// in a locked folder (never signalled), and ignores one that is not
// enabled; Attention.Harness names the command (CC-48).
func TestUngatedScanUsesInventories(t *testing.T) {
	x := startTD(t)
	gem := x.addProc(8600, 1, 8600, "/opt/homebrew/bin/node", "node", "/opt/homebrew/bin/gemini")
	x.h.Procs.SetCwd(gem.ID.PID, x.h.Root)
	cx := x.addProc(8610, 1, 8610, "/opt/homebrew/bin/codex", "codex")
	x.h.Procs.SetCwd(cx.ID.PID, x.h.Root)
	c := x.dial()
	reported := func(pid int) (ipc.Attention, bool) {
		st, err := c.Status(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range st.Attention {
			if a.Code == ipc.AttnUngatedSession && a.PID == pid {
				return a, true
			}
		}
		return ipc.Attention{}, false
	}
	x.eventually("codex reported", func() bool { _, ok := reported(cx.ID.PID); return ok })
	if a, _ := reported(cx.ID.PID); a.Harness != "codex" || a.Fix != "precinto run codex" {
		t.Fatalf("codex attention = %+v", a)
	}
	time.Sleep(50 * time.Millisecond)
	if _, ok := reported(gem.ID.PID); ok {
		t.Fatal("a generic harness that is not enabled was reported")
	}
	enableGeneric(t, x, "gemini")
	x.eventually("gemini reported", func() bool { _, ok := reported(gem.ID.PID); return ok })
	if a, _ := reported(gem.ID.PID); a.Harness != "gemini" {
		t.Fatalf("gemini attention = %+v", a)
	}
	for _, s := range x.rec.snapshot() {
		t.Fatalf("a report-only match was signalled: %+v", s)
	}
}

// D28 ancestry is wider than registration: every agent of the list and
// every inventory counts, enabled or not, case-insensitively.
func TestAgentProgram(t *testing.T) {
	for _, tc := range []struct {
		p    platform.ProcInfo
		want string
	}{
		{platform.ProcInfo{Exe: "/opt/homebrew/bin/claude"}, "claude"},
		{platform.ProcInfo{Exe: "/Applications/Claude.app/Contents/MacOS/Claude"}, "claude"},
		{platform.ProcInfo{Exe: "/usr/local/bin/node", Argv: []string{"node", "/usr/local/lib/node_modules/@openai/codex/bin/codex.js"}}, "codex"},
		{platform.ProcInfo{Exe: "/u/.local/share/claude/versions/2.1.329"}, "claude"},
		{platform.ProcInfo{Exe: "/usr/local/bin/droid"}, "droid"},
		{platform.ProcInfo{Exe: "/usr/local/bin/node", Argv: []string{"node", "/usr/local/bin/qwen"}}, "qwen"},
		{platform.ProcInfo{Exe: "/usr/bin/vim", Argv: []string{"vim", "claude"}}, ""},
		{platform.ProcInfo{Exe: "/bin/zsh", Argv: []string{"-zsh"}, Comm: "claude"}, ""},
	} {
		tc.p.ID = platform.ProcID{PID: 4242, StartUS: 1}
		got, ok := agentProgram(tc.p)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("agentProgram(%s %v) = %q %v, want %q", tc.p.Exe, tc.p.Argv, got, ok, tc.want)
		}
	}
}
