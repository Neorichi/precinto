package testkit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Neorichi/precinto/internal/platform"
)

// D154: on Linux a hardened precinto hides its /proc/<pid>/exe (D65), so
// exeOf names it from an absolute argv[0] whose base name is the command
// name, resolved like the kernel resolves it; a known Exe always decides.
func TestExeOfStandsInForAHiddenExecutable(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "precinto")
	if err := os.WriteFile(bin, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}
	long := filepath.Join(dir, "precinto-with-a-long-name")
	for _, c := range []struct {
		name string
		p    platform.ProcInfo
		want string
	}{
		{"a known exe decides", platform.ProcInfo{Exe: "/usr/bin/sleep", Comm: "precinto", Argv: []string{bin}}, "/usr/bin/sleep"},
		{"hidden", platform.ProcInfo{Comm: "precinto", Argv: []string{bin, "sweep", "--quiet"}}, real},
		{"hidden, run through a symlink", platform.ProcInfo{Comm: "link", Argv: []string{link}}, real},
		{"hidden, uncleaned argv[0]", platform.ProcInfo{Comm: "precinto", Argv: []string{dir + "/./precinto"}}, real},
		{"hidden, name cut to 15 bytes", platform.ProcInfo{Comm: "precinto-with-a", Argv: []string{long}}, long},
		{"another command name", platform.ProcInfo{Comm: "dprobe", Argv: []string{bin}}, ""},
		{"a shorter command name", platform.ProcInfo{Comm: "pre", Argv: []string{bin}}, ""},
		{"relative argv[0]", platform.ProcInfo{Comm: "precinto", Argv: []string{"precinto"}}, ""},
		{"no argv", platform.ProcInfo{Comm: "precinto"}, ""},
		{"no command name", platform.ProcInfo{Argv: []string{bin}}, ""},
	} {
		if got := exeOf(c.p); got != c.want {
			t.Errorf("%s: exeOf = %q, want %q", c.name, got, c.want)
		}
	}
	if !runsBinary(platform.ProcInfo{Comm: "precinto", Argv: []string{bin}}, []string{bin}) {
		t.Error("a hidden process whose argv[0] is bin does not run bin")
	}
	if runsBinary(platform.ProcInfo{Exe: "/usr/bin/sleep", Comm: "precinto", Argv: []string{bin}}, []string{bin}) {
		t.Error("a process whose readable exe is another binary was taken for bin")
	}
	other := filepath.Join(t.TempDir(), "precinto")
	if runsBinary(platform.ProcInfo{Comm: "precinto", Argv: []string{other}}, []string{bin}) {
		t.Error("the same base name in another directory was taken for bin")
	}
}
