package platform_test

import (
	"context"
	"sort"
	"testing"

	"github.com/Neorichi/precinto/internal/platform"
)

// table is a minimal fake process table for the scaffold-implemented walks
// (fakeplatform is still a stub for G2 to implement).
type table map[int]platform.ProcInfo

func (t table) Lookup(pid int) (platform.ProcInfo, error) {
	p, ok := t[pid]
	if !ok {
		return platform.ProcInfo{}, platform.ErrNoProcess
	}
	return p, nil
}
func (t table) Alive(id platform.ProcID) bool { p, ok := t[id.PID]; return ok && p.ID == id }
func (t table) List() ([]platform.ProcInfo, error) {
	var out []platform.ProcInfo
	for _, p := range t {
		out = append(out, p)
	}
	return out, nil
}
func (t table) Cwd(platform.ProcID) (string, error) { return "", nil }
func (t table) OpenFilesUnder(context.Context, []string) ([]platform.Holder, error) {
	return nil, nil
}

func proc(pid, ppid int, start int64) platform.ProcInfo {
	return platform.ProcInfo{ID: platform.ProcID{PID: pid, StartUS: start}, PPID: ppid}
}

func TestAncestorsAndDescendants(t *testing.T) {
	tb := table{
		1:  proc(1, 0, 1),
		10: proc(10, 1, 100),  // login shell (same Unix session as claude)
		20: proc(20, 10, 200), // unwrapped claude
		30: proc(30, 20, 300), // its MCP server
		31: proc(31, 30, 310), // grandchild
		40: proc(40, 20, 150), // reused pid: started before claude, not its child
		50: proc(50, 10, 500), // sibling job of the shell
	}
	anc, err := platform.Ancestors(tb, 31, 10)
	if err != nil || len(anc) != 3 || anc[0].ID.PID != 30 || anc[2].ID.PID != 10 {
		t.Fatalf("Ancestors = %+v, %v", anc, err)
	}
	if anc, _ := platform.Ancestors(tb, 31, 1); len(anc) != 1 {
		t.Fatalf("max not honoured: %+v", anc)
	}
	ds, err := platform.Descendants(tb, tb[20].ID)
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, d := range ds {
		pids = append(pids, d.ID.PID)
	}
	sort.Ints(pids)
	if len(pids) != 2 || pids[0] != 30 || pids[1] != 31 {
		t.Fatalf("Descendants = %v, want [30 31] (never the shell, its jobs or a reused pid)", pids)
	}
}
