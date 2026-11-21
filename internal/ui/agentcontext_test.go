package ui_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
)

// fakeProcs is a minimal platform.ProcTable keyed by pid.
type fakeProcs map[int]platform.ProcInfo

func (f fakeProcs) Lookup(pid int) (platform.ProcInfo, error) {
	p, ok := f[pid]
	if !ok {
		return platform.ProcInfo{}, platform.ErrNoProcess
	}
	return p, nil
}

func (f fakeProcs) Alive(id platform.ProcID) bool {
	p, ok := f[id.PID]
	return ok && p.ID == id && p.State != platform.StateZombie
}

func (f fakeProcs) List() ([]platform.ProcInfo, error) {
	out := make([]platform.ProcInfo, 0, len(f))
	for _, p := range f {
		out = append(out, p)
	}
	return out, nil
}

func (f fakeProcs) Cwd(platform.ProcID) (string, error) { return "", nil }

func (f fakeProcs) OpenFilesUnder(context.Context, []string) ([]platform.Holder, error) {
	return nil, nil
}

var _ platform.ProcTable = fakeProcs(nil)

// chain builds a process table in which every process is the parent of the
// next one: procs[0] is the outermost ancestor (its parent is launchd/init)
// and the last one is the current process, whose pid is returned. Pids
// start at firstPID.
func chain(firstPID int, procs ...platform.ProcInfo) (fakeProcs, int) {
	f := fakeProcs{}
	ppid := 1
	for i, p := range procs {
		pid := firstPID + i
		p.ID = platform.ProcID{PID: pid, StartUS: int64(1_000_000 + i)}
		p.PPID = ppid
		if p.State == "" {
			p.State = platform.StateRunning
		}
		f[pid] = p
		ppid = pid
	}
	return f, ppid
}

func proc(exe string, argv ...string) platform.ProcInfo {
	return platform.ProcInfo{Exe: exe, Argv: argv}
}

var (
	launchd = proc("/sbin/launchd")
	termApp = proc("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal")
	login   = proc("/usr/bin/login", "login", "-pf", "user")
	zsh     = proc("/bin/zsh", "-zsh")
	self    = proc("/usr/local/bin/precinto", "precinto", "init")
)

func noMarkers(paths.Env) []string { return nil }
func withTTY() bool                { return true }
func withoutTTY() bool             { return false }

func markers(names ...string) func(paths.Env) []string {
	return func(paths.Env) []string { return names }
}

func TestAgentContextEvidence(t *testing.T) {
	plain, plainSelf := chain(100, termApp, login, zsh, self)
	type tc struct {
		name     string
		procs    platform.ProcTable
		pid      int
		markers  func(paths.Env) []string
		ctty     func() bool
		want     bool
		evidence string // substring of the evidence
	}
	cases := []tc{
		{"terminal session", plain, plainSelf, noMarkers, withTTY, false, ""},
		{"agent marker", plain, plainSelf, markers("CLAUDECODE"), withTTY, true, "environment variable CLAUDECODE"},
		{"several markers", plain, plainSelf, markers("CLAUDECODE", "CLAUDE_PID"), withTTY, true, "environment variables CLAUDECODE, CLAUDE_PID"},
		{"no controlling terminal", plain, plainSelf, noMarkers, withoutTTY, true, "no controlling terminal"},
		{"unknown controlling terminal", plain, plainSelf, noMarkers, nil, true, "no controlling terminal"},
		{"process missing from the table", plain, 4242, noMarkers, withTTY, true, "process ancestry unavailable"},
		{"no process table", nil, plainSelf, noMarkers, withTTY, true, "process ancestry unavailable"},
	}
	harnessExes := map[string]platform.ProcInfo{
		"claude":       proc("/opt/homebrew/bin/claude", "claude"),
		"codex":        proc("/usr/local/bin/codex", "codex"),
		"droid":        proc("/Users/u/.local/bin/droid", "droid"),
		"cursor-agent": proc("/Users/u/.local/bin/cursor-agent", "cursor-agent"),
		"copilot":      proc("/opt/homebrew/bin/copilot", "copilot"),
		"gemini":       proc("/opt/homebrew/bin/gemini", "gemini"),
		"kimi":         proc("/Users/u/.local/bin/kimi", "kimi"),
		"opencode":     proc("/Users/u/.opencode/bin/opencode", "opencode"),
	}
	for name, h := range harnessExes {
		procs, pid := chain(200, termApp, login, zsh, h, zsh, self)
		cases = append(cases, tc{"harness " + name, procs, pid, noMarkers, withTTY, true, "ancestor process " + name + " (pid 203)"})
	}
	shapes := []struct {
		name, harness string
		p             platform.ProcInfo
	}{
		{"node script on PATH", "gemini", proc("/opt/homebrew/bin/node", "node", "/opt/homebrew/bin/gemini", "--yolo")},
		{"node flags before the script", "codex", proc("/usr/local/bin/node", "node", "--no-warnings", "/usr/local/bin/codex")},
		{"node launcher script", "codex", proc("/usr/local/bin/node", "node", "/usr/local/lib/node_modules/@openai/codex/bin/codex.js")},
		{"npm package entry point", "claude", proc("/usr/local/bin/node", "node", "/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js")},
		{"python script", "kimi", proc("/usr/bin/python3.12", "python3.12", "/Users/u/.local/bin/kimi")},
		{"bun binary", "opencode", proc("/Users/u/.bun/bin/bun", "bun", "/Users/u/.bun/bin/opencode")},
		{"native versioned install", "claude", proc("/Users/u/.local/share/claude/versions/2.0.14", "claude")},
		{"versioned install, unknown argv", "claude", proc("/Users/u/.local/share/claude/versions/2.0.14")},
		{"desktop app", "claude", proc("/Applications/Claude.app/Contents/MacOS/Claude")},
		{"argv[0] only", "codex", proc("", "codex", "exec")},
		{"exec -a launcher", "cursor-agent", proc("/Users/u/.local/share/cursor-agent/versions/1.0/node", "/Users/u/.local/bin/cursor-agent")},
	}
	for _, s := range shapes {
		procs, pid := chain(300, launchd, s.p, zsh, self)
		cases = append(cases, tc{s.name, procs, pid, noMarkers, withTTY, true, "ancestor process " + s.harness + " (pid 301)"})
	}
	notHarness := []struct {
		name string
		p    platform.ProcInfo
	}{
		{"comm is never matched", platform.ProcInfo{Exe: "/bin/zsh", Comm: "claude", Argv: []string{"zsh"}}},
		{"similar names", proc("/usr/local/bin/claude-helper", "claude-helper")},
		{"prefix", proc("/usr/local/bin/codexx", "codexx")},
		{"IDE", proc("/Applications/Cursor.app/Contents/MacOS/Cursor")},
		{"node running another tool", proc("/usr/local/bin/node", "node", "/usr/local/bin/eslint", "claude")},
		{"harness name as a later argument", proc("/usr/bin/git", "git", "commit", "-m", "claude")},
		{"versions dir of another program", proc("/Users/u/.local/share/tool/versions/1.0", "tool")},
	}
	for _, n := range notHarness {
		procs, pid := chain(400, termApp, login, n.p, self)
		cases = append(cases, tc{n.name, procs, pid, noMarkers, withTTY, false, ""})
	}
	// Only ancestors count: the current process itself is not inspected.
	selfOnly, selfPID := chain(500, termApp, login, zsh, proc("/opt/homebrew/bin/claude", "claude"))
	cases = append(cases, tc{"current process", selfOnly, selfPID, noMarkers, withTTY, false, ""})
	// Markers are reported before ancestry.
	agentChain, agentSelf := chain(600, termApp, proc("/opt/homebrew/bin/claude", "claude"), zsh, self)
	cases = append(cases, tc{"markers first", agentChain, agentSelf, markers("CLAUDECODE"), withTTY, true, "environment variable CLAUDECODE"})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, evidence := ui.AgentContextWith(paths.FromMap(nil), c.procs, c.markers, c.pid, c.ctty)
			if got != c.want {
				t.Fatalf("AgentContext = %v (%q), want %v", got, evidence, c.want)
			}
			if !c.want && evidence != "" {
				t.Errorf("evidence %q without an agent context", evidence)
			}
			if c.want && !strings.Contains(evidence, c.evidence) {
				t.Errorf("evidence %q, want it to contain %q", evidence, c.evidence)
			}
		})
	}
}

func TestAgentContextAncestryWalk(t *testing.T) {
	// A PPID loop ends the walk.
	loop := fakeProcs{
		10: {ID: platform.ProcID{PID: 10, StartUS: 1}, PPID: 11, Exe: "/bin/zsh"},
		11: {ID: platform.ProcID{PID: 11, StartUS: 2}, PPID: 10, Exe: "/bin/zsh"},
		12: {ID: platform.ProcID{PID: 12, StartUS: 3}, PPID: 10, Exe: "/usr/local/bin/precinto"},
	}
	if got, evidence := ui.AgentContextWith(paths.FromMap(nil), loop, noMarkers, 12, withTTY); got {
		t.Errorf("PPID loop: agent context (%q)", evidence)
	}

	// A chain longer than the walk bound fails closed; one that fits does not.
	deep := func(ancestors int) (fakeProcs, int) {
		ps := make([]platform.ProcInfo, 0, ancestors+1)
		for i := 0; i < ancestors; i++ {
			ps = append(ps, zsh)
		}
		return chain(1000, append(ps, self)...)
	}
	fits, fitsSelf := deep(ui.MaxAncestors)
	if got, evidence := ui.AgentContextWith(paths.FromMap(nil), fits, noMarkers, fitsSelf, withTTY); got {
		t.Errorf("%d ancestors: agent context (%q)", ui.MaxAncestors, evidence)
	}
	tooDeep, deepSelf := deep(ui.MaxAncestors + 1)
	if got, evidence := ui.AgentContextWith(paths.FromMap(nil), tooDeep, noMarkers, deepSelf, withTTY); !got || !strings.Contains(evidence, "too deep") {
		t.Errorf("%d ancestors: AgentContext = %v (%q), want a fail-closed agent context", ui.MaxAncestors+1, got, evidence)
	}

	// A harness above an ancestor that cannot be looked up is out of sight;
	// the walk stops there without failing.
	gap, gapSelf := chain(2000, proc("/opt/homebrew/bin/claude", "claude"), login, zsh, self)
	delete(gap, 2001)
	if got, evidence := ui.AgentContextWith(paths.FromMap(nil), gap, noMarkers, gapSelf, withTTY); got {
		t.Errorf("walk past a lookup error: agent context (%q)", evidence)
	}
}

// callAgentContext calls the exported AgentContext, skipping the test while
// paths.AgentMarkers (another package of this tree) is still a stub.
func callAgentContext(t *testing.T, e paths.Env, procs platform.ProcTable) (ok bool, evidence string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			if s, isString := r.(string); isString && strings.Contains(s, "unimplemented: paths.AgentMarkers") {
				t.Skip("paths.AgentMarkers is not implemented in this tree yet")
			}
			panic(r)
		}
	}()
	return ui.AgentContext(e, procs)
}

func TestAgentContextUsesPathsMarkersAndRealPID(t *testing.T) {
	pid := os.Getpid()
	procs := fakeProcs{pid: {ID: platform.ProcID{PID: pid, StartUS: 1}, PPID: 1, Exe: "/usr/local/bin/precinto"}}
	got, evidence := callAgentContext(t, paths.FromMap(map[string]string{"CLAUDECODE": "1", "HOME": t.TempDir()}), procs)
	if !got || !strings.Contains(evidence, "CLAUDECODE") {
		t.Errorf("AgentContext with CLAUDECODE=1 = %v (%q)", got, evidence)
	}

	// The real pid is the start of the walk: a harness parent counts.
	parent := pid + 1
	procs = fakeProcs{
		pid:    {ID: platform.ProcID{PID: pid, StartUS: 2}, PPID: parent, Exe: "/usr/local/bin/precinto"},
		parent: {ID: platform.ProcID{PID: parent, StartUS: 1}, PPID: 1, Exe: "/opt/homebrew/bin/codex"},
	}
	got, evidence = callAgentContext(t, paths.FromMap(map[string]string{"HOME": t.TempDir()}), procs)
	if want := fmt.Sprintf("ancestor process codex (pid %d)", parent); !got || evidence != want {
		t.Errorf("AgentContext under codex = %v (%q), want true (%q)", got, evidence, want)
	}
}
