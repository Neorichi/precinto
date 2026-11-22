package claude_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
)

// D136 (H6-3): the project unit of a folder whose name holds an accent is
// live while Claude runs in it whichever Unicode spelling the process's cwd
// and the protected path use (the kernel reports the stored NFD name, a
// folder protected from a typed path is NFC): E7 compares by the D93 rule.
func TestProbeProjectCwdInTheOtherSpelling(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("one folder in two Unicode normalizations needs APFS")
	}
	for _, protected := range []string{"nfc", "nfd"} {
		t.Run(protected, func(t *testing.T) {
			f := newFx(t)
			nfd := filepath.Join(f.h.HomeDir, "work", "Diseño")
			nfc := filepath.Join(f.h.HomeDir, "work", "Diseño")
			if err := os.MkdirAll(nfd, 0o700); err != nil {
				t.Fatal(err)
			}
			a, err := os.Stat(nfc)
			if err != nil {
				t.Skipf("normalization-sensitive file system: %v", err)
			}
			if b, _ := os.Stat(nfd); !os.SameFile(a, b) {
				t.Skip("NFC and NFD name different directories here")
			}
			root, cwd := nfc, nfd
			if protected == "nfd" {
				root, cwd = nfd, nfc
			}
			for i := range f.e.Cfg.Roots {
				if f.e.Cfg.Roots[i].ID == "root-acme" {
					f.e.Cfg.Roots[i].Path = root
				}
			}
			f.h.Root = root
			_, paths := f.session(sid1, root, nil)
			f.taint(sid1, platform.ProcID{})
			pu, ok := find(f.scan(harness.Scope{}), capsule.KindClaudeProject, slugOf(t, paths))
			if !ok {
				t.Fatal("no project unit")
			}
			if ev := evidence(t, f, pu); len(ev[live.ReasonProcess]) != 0 {
				t.Fatalf("no Claude process yet: %v", ev)
			}
			f.h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 700, StartUS: 1}, PPID: 1,
				Exe: "/Users/x/.local/share/claude/versions/2.1.330", Comm: "2.1.330"})
			f.h.Procs.SetCwd(700, filepath.Join(cwd, "src"))
			if ev := evidence(t, f, pu); len(ev[live.ReasonProcess]) != 1 {
				t.Fatalf("Claude runs in the folder (cwd in the other spelling) but the project unit is not live: %v", ev)
			}
		})
	}
}
