package harness

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/testkit"
)

func TestIsPE(t *testing.T) {
	for head, want := range map[string]bool{
		"MZ\x90\x00\x03\x00": true,
		"\x7fELF\x02\x01":    false,
		"#!/bin/sh\n":        false,
		"M":                  false,
		"":                   false,
	} {
		if got := isPE([]byte(head)); got != want {
			t.Errorf("isPE(%q) = %v", head, got)
		}
	}
}

func TestShebang(t *testing.T) {
	for _, c := range []struct {
		head, interp, arg string
		ok                bool
	}{
		{"#!/bin/sh\necho", "/bin/sh", "", true},
		{"#!/usr/bin/env node\n", "/usr/bin/env", "node", true},
		{"#! /usr/bin/env -S node --no-warnings\r\nx", "/usr/bin/env", "-S node --no-warnings", true},
		{"#!/usr/bin/env\tbash\n", "/usr/bin/env", "bash", true},
		{"#!\n", "", "", false},
		{"\x7fELF", "", "", false},
		{"#!/mnt/c/tools/node.exe", "/mnt/c/tools/node.exe", "", true},
	} {
		interp, arg, ok := shebang([]byte(c.head))
		if interp != c.interp || arg != c.arg || ok != c.ok {
			t.Errorf("shebang(%q) = %q, %q, %v", c.head, interp, arg, ok)
		}
	}
}

func TestEnvCommand(t *testing.T) {
	for arg, want := range map[string]string{
		"node":                        "node",
		"-S node --no-warnings":       "node",
		"-i PATH=/usr/bin python3":    "python3",
		"-u HOME bash":                "bash",
		"--unset=HOME bash":           "bash",
		"NODE_OPTIONS=--x node":       "node",
		"/mnt/c/tools/node.exe":       "/mnt/c/tools/node.exe",
		"":                            "",
		"-S":                          "",
		"-C /tmp FOO=bar deno run -A": "deno",
	} {
		if got := envCommand(arg); got != want {
			t.Errorf("envCommand(%q) = %q, want %q", arg, got, want)
		}
	}
}

// fakeSystem: files by content, anything below /mnt/c on a Windows drive,
// /broken unknown, PATH lookups from a table.
type fakeSystem struct {
	files map[string]string
	path  map[string]string
	reads []string
}

func (f *fakeSystem) io() programIO {
	return programIO{
		drive: func(p string) error {
			switch {
			case paths.Within("/mnt/c", p):
				return &paths.DriveError{Path: p}
			case paths.Within("/broken", p):
				return &paths.DriveError{Path: p, Unknown: true, Err: fs.ErrPermission}
			}
			return nil
		},
		head: func(p string) ([]byte, error) {
			f.reads = append(f.reads, p)
			if p == "/home/u/bin/unreadable" {
				return nil, fs.ErrPermission
			}
			c, ok := f.files[p]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return []byte(c), nil
		},
		look: func(_ paths.Env, name string) (string, error) {
			if p, ok := f.path[name]; ok {
				return p, nil
			}
			return "", fs.ErrNotExist
		},
	}
}

// D156: a harness executable that would run as a Windows program is
// refused under WSL, and only there.
func TestCheckProgram(t *testing.T) {
	const elf = "\x7fELF\x02\x01\x01"
	sys := &fakeSystem{
		files: map[string]string{
			"/usr/local/bin/claude":         elf,
			"/usr/bin/env":                  elf,
			"/usr/bin/node":                 elf,
			"/usr/bin/sh":                   elf,
			"/home/u/bin/claude.exe":        "MZ\x90\x00",
			"/home/u/bin/npm-claude":        "#!/usr/bin/env node\nrequire('./cli.js')\n",
			"/home/u/bin/flags-claude":      "#!/usr/bin/env -S node --no-warnings\n",
			"/home/u/bin/abs-claude":        "#!/usr/bin/env /mnt/c/tools/node.exe\n",
			"/home/u/bin/sh-claude":         "#!/usr/bin/sh\nexec node cli.js\n",
			"/home/u/bin/winsh":             "#!/mnt/c/tools/sh\n",
			"/home/u/bin/rel":               "#!node\n",
			"/home/u/bin/pe-interp":         "#!/home/u/bin/claude.exe\n",
			"/home/u/bin/missing-cmd":       "#!/usr/bin/env nonode\n",
			"/home/u/bin/unread-interp":     "#!/opt/unreadable/node\n",
			"/home/u/bin/unreadable-interp": "#!/home/u/bin/unreadable\n",
		},
		path: map[string]string{"node": "/mnt/c/Program Files/nodejs/node.exe"},
	}
	wsl := paths.WSL{Version: 2, MountRoot: "/mnt/"}
	env := paths.FromMap(map[string]string{"PATH": "/usr/bin"})

	// Outside WSL nothing is read and everything passes.
	if err := checkProgram(paths.WSL{}, env, "/mnt/c/x/claude.exe", programIO{}); err != nil {
		t.Fatalf("outside WSL: %v", err)
	}
	for _, c := range []struct {
		exe     string
		refused bool
		unknown bool
		why     string
	}{
		{"/usr/local/bin/claude", false, false, ""},
		{"/mnt/c/Users/Public/AppData/Roaming/npm/claude", true, false, "is on a Windows drive"},
		{"/broken/claude", true, true, "could not tell"},
		{"/home/u/bin/claude.exe", true, false, "is a Windows executable"},
		{"/home/u/bin/npm-claude", true, false, "runs /mnt/c/Program Files/nodejs/node.exe, which is on a Windows drive"},
		{"/home/u/bin/flags-claude", true, false, "runs /mnt/c/Program Files/nodejs/node.exe"},
		{"/home/u/bin/abs-claude", true, false, "runs /mnt/c/tools/node.exe"},
		{"/home/u/bin/sh-claude", false, false, ""},
		{"/home/u/bin/winsh", true, false, "runs /mnt/c/tools/sh, which is on a Windows drive"},
		{"/home/u/bin/rel", false, false, ""},
		{"/home/u/bin/pe-interp", true, false, "runs /home/u/bin/claude.exe, which is a Windows executable"},
		{"/home/u/bin/missing-cmd", false, false, ""},
		{"/home/u/bin/unread-interp", false, false, ""}, // a missing interpreter: exec fails
		{"/home/u/bin/nothing-here", false, false, ""},  // a missing executable: exec fails, as before
		{"/home/u/bin/unreadable", true, true, "cannot be read"},
		{"/home/u/bin/unreadable-interp", true, true, "runs /home/u/bin/unreadable, which cannot be read"},
		{"relative/claude", true, true, "not an absolute path"},
	} {
		err := checkProgram(wsl, env, c.exe, sys.io())
		var pe *ProgramError
		if !c.refused {
			if err != nil {
				t.Errorf("%s: %v, want accepted", c.exe, err)
			}
			continue
		}
		if !errors.As(err, &pe) || !errors.Is(err, ErrWindowsProgram) || pe.Exe != c.exe || pe.Unknown != c.unknown || !strings.Contains(pe.Why, c.why) {
			t.Errorf("%s: %v (%+v), want refused (unknown %v, %q)", c.exe, err, pe, c.unknown, c.why)
		}
	}
	// With a Linux node first in PATH the npm install is accepted.
	sys.path["node"] = "/usr/bin/node"
	if err := checkProgram(wsl, env, "/home/u/bin/npm-claude", sys.io()); err != nil {
		t.Fatalf("npm install with a Linux node: %v", err)
	}
}

// readHead reads the first bytes of a regular file, follows links, and
// never blocks on a FIFO.
func TestReadHead(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "claude")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"+strings.Repeat("x", 1000)), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}
	b, err := readHead(link)
	if err != nil || len(b) != headSize || !strings.HasPrefix(string(b), "#!/bin/sh\n") {
		t.Fatalf("readHead = %d bytes, %v", len(b), err)
	}
	if _, err := readHead(dir); err == nil {
		t.Error("a directory was read")
	}
	fifo := filepath.Join(dir, "fifo")
	if testkit.Mkfifo(fifo, 0o600) == nil {
		if _, err := readHead(fifo); err == nil {
			t.Error("a FIFO was read")
		}
	}
	// Outside WSL CheckProgram reads nothing.
	if paths.DetectWSL().Version == 0 {
		if err := CheckProgram(paths.FromMap(nil), ClaudeCode, filepath.Join(dir, "nothing")); err != nil {
			t.Fatalf("CheckProgram outside WSL: %v", err)
		}
	}
}
