package harness

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/testkit"
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

// envCommand reads a "#!/usr/bin/env ARG" line as GNU env reads its one
// argument ARG: only -S and --split-string split it (attached or not);
// NAME=value, -i and -u change the PATH execvp searches; an option it does
// not know, or a split env would process (quotes, escapes, variables,
// comments), is "cannot tell".
func TestEnvCommand(t *testing.T) {
	const path = "/usr/bin:/mnt/c/nodejs"
	for _, c := range []struct {
		arg, cmd, path string
		ok             bool
	}{
		{"node", "node", path, true},
		{"-S node --no-warnings", "node", path, true},
		{"-Snode", "node", path, true},
		{"-S node", "node", path, true},
		{"--split-string=node --no-warnings", "node", path, true},
		{"-S PATH=/mnt/c/nodejs node", "node", "/mnt/c/nodejs", true},
		{"-S -i node", "node", "/bin:/usr/bin", true},
		{"-S -i PATH=/opt/x/bin node", "node", "/opt/x/bin", true},
		{"-S -u PATH node", "node", "/bin:/usr/bin", true},
		{"-S --unset=PATH node", "node", "/bin:/usr/bin", true},
		{"-S -uHOME node", "node", path, true},
		{"-S -C /tmp node", "node", path, true},
		{"-S -- node", "node", path, true},
		{"-S NODE_OPTIONS=--x node", "node", path, true},
		{"-S -0v node", "node", path, true},
		{"/mnt/c/tools/node.exe", "/mnt/c/tools/node.exe", path, true},
		// Without -S the argument is one word: env runs no command, or a
		// command whose name has a space (not found: nothing runs).
		{"NODE_OPTIONS=--x node", "", path, true},
		{"node --no-warnings", "node --no-warnings", path, true},
		{"", "", path, true},
		{"-i", "", "/bin:/usr/bin", true},
		// Cannot tell.
		{"-S", "", "", false},
		{"-S 'node'", "", "", false},
		{"-S node\\ x", "", "", false},
		{"-S ${NODE} x", "", "", false},
		{"-S node #x", "", "", false},
		{"-i PATH=/usr/bin python3", "", "", false}, // "-i" then " ": not an option env knows
		{"-x node", "", "", false},
		{"--split node", "", "", false},
		{"--help", "", "", false},
	} {
		cmd, p, ok := envCommand(c.arg, path)
		if cmd != c.cmd || ok != c.ok || (ok && p != c.path) {
			t.Errorf("envCommand(%q) = %q, %q, %v; want %q, %q, %v", c.arg, cmd, p, ok, c.cmd, c.path, c.ok)
		}
	}
}

// fakeSystem: files by content, anything below /mnt/c on a Windows drive,
// /broken unknown, PATH lookups from a table (or, for a PATH env sets to
// one other folder, that folder), /init WSL's launcher.
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
		look: func(e paths.Env, name string) (string, error) {
			if dir := e.Get("PATH"); dir != "/usr/bin" && filepath.IsAbs(dir) && !strings.Contains(dir, ":") {
				if _, ok := f.files[filepath.Join(dir, name)]; ok {
					return filepath.Join(dir, name), nil
				}
				return "", fs.ErrNotExist
			}
			if p, ok := f.path[name]; ok {
				return p, nil
			}
			return "", fs.ErrNotExist
		},
		launcher: func(p string) bool { return p == "/init" || p == "/usr/local/bin/winrun" },
	}
}

// D156: a harness executable that would run as a Windows program is
// refused under WSL, and only there: itself, or any program it runs
// through "#!" lines and env, as deep as linux follows them. Runs names
// that program; Why never holds a path.
func TestCheckProgram(t *testing.T) {
	const elf = "\x7fELF\x02\x01\x01"
	sys := &fakeSystem{
		files: map[string]string{
			"/usr/local/bin/claude":         elf,
			"/usr/bin/env":                  elf,
			"/usr/bin/node":                 elf,
			"/usr/bin/sh":                   elf,
			"/init":                         elf,
			"/usr/local/bin/winrun":         elf, // a link to /init
			"/mnt/c/nodejs/node.exe":        "MZ\x90\x00",
			"/home/u/bin/claude.exe":        "MZ\x90\x00",
			"/home/u/bin/npm-claude":        "#!/usr/bin/env node\nrequire('./cli.js')\n",
			"/home/u/bin/flags-claude":      "#!/usr/bin/env -S node --no-warnings\n",
			"/home/u/bin/attached-claude":   "#!/usr/bin/env -Snode\n",
			"/home/u/bin/split-claude":      "#!/usr/bin/env --split-string=node\n",
			"/home/u/bin/path-claude":       "#!/usr/bin/env -S PATH=/mnt/c/nodejs node.exe\n",
			"/home/u/bin/odd-env-claude":    "#!/usr/bin/env -S 'node'\n",
			"/home/u/bin/abs-claude":        "#!/usr/bin/env /mnt/c/tools/node.exe\n",
			"/home/u/bin/relcmd-claude":     "#!/usr/bin/env -S -C /mnt/c ./node.exe\n",
			"/home/u/bin/sh-claude":         "#!/usr/bin/sh\nexec node cli.js\n",
			"/home/u/bin/winsh":             "#!/mnt/c/tools/sh\n",
			"/home/u/bin/rel":               "#!node\n",
			"/home/u/bin/pe-interp":         "#!/home/u/bin/claude.exe\n",
			"/home/u/bin/missing-cmd":       "#!/usr/bin/env nonode\n",
			"/home/u/bin/unread-interp":     "#!/opt/unreadable/node\n",
			"/home/u/bin/unreadable-interp": "#!/home/u/bin/unreadable\n",
			"/home/u/bin/init-claude":       "#!/init\n",
			"/home/u/bin/winrun-claude":     "#!/usr/local/bin/winrun\n",
			"/home/u/bin/env-init":          "#!/usr/bin/env /init\n",
			// Two levels: a script whose interpreter is a script whose
			// interpreter is a Windows program.
			"/home/u/bin/two-claude": "#!/home/u/bin/nodew\n",
			"/home/u/bin/nodew":      "#!/mnt/c/nodejs/node.exe\n",
			// Interpreters as deep as linux follows (5), then one more.
			"/home/u/bin/deep0":   "#!/home/u/bin/deep1\n",
			"/home/u/bin/deep1":   "#!/home/u/bin/deep2\n",
			"/home/u/bin/deep2":   "#!/home/u/bin/deep3\n",
			"/home/u/bin/deep3":   "#!/home/u/bin/deep4\n",
			"/home/u/bin/deep4":   "#!/usr/bin/sh\n",
			"/home/u/bin/deeper0": "#!/home/u/bin/deeper1\n",
			"/home/u/bin/deeper1": "#!/home/u/bin/deep0\n",
			// A shebang naming a terminal escape: refused, and the escape
			// only ever travels in Runs.
			"/home/u/bin/esc-claude": "#!/mnt/c/x\x1b]52;c;AAAA\x07y\n",
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
		runs    string
		why     string
	}{
		{"/usr/local/bin/claude", false, false, "", ""},
		{"/mnt/c/Users/Public/AppData/Roaming/npm/claude", true, false, "", "is on a Windows drive"},
		{"/broken/claude", true, true, "", "could not tell"},
		{"/home/u/bin/claude.exe", true, false, "", "is a Windows executable"},
		{"/home/u/bin/npm-claude", true, false, "/mnt/c/Program Files/nodejs/node.exe", "is on a Windows drive"},
		{"/home/u/bin/flags-claude", true, false, "/mnt/c/Program Files/nodejs/node.exe", "is on a Windows drive"},
		{"/home/u/bin/attached-claude", true, false, "/mnt/c/Program Files/nodejs/node.exe", "is on a Windows drive"},
		{"/home/u/bin/split-claude", true, false, "/mnt/c/Program Files/nodejs/node.exe", "is on a Windows drive"},
		{"/home/u/bin/path-claude", true, false, "/mnt/c/nodejs/node.exe", "is on a Windows drive"},
		{"/home/u/bin/odd-env-claude", true, true, "/usr/bin/env", "options precinto can't read"},
		{"/home/u/bin/abs-claude", true, false, "/mnt/c/tools/node.exe", "is on a Windows drive"},
		{"/home/u/bin/relcmd-claude", true, true, "./node.exe", "not an absolute path"},
		{"/home/u/bin/sh-claude", false, false, "", ""},
		{"/home/u/bin/winsh", true, false, "/mnt/c/tools/sh", "is on a Windows drive"},
		{"/home/u/bin/rel", false, false, "", ""},
		{"/home/u/bin/pe-interp", true, false, "/home/u/bin/claude.exe", "is a Windows executable"},
		{"/home/u/bin/missing-cmd", false, false, "", ""},
		{"/home/u/bin/unread-interp", false, false, "", ""}, // a missing interpreter: exec fails
		{"/home/u/bin/nothing-here", false, false, "", ""},  // a missing executable: exec fails, as before
		{"/home/u/bin/unreadable", true, true, "", "can't be read"},
		{"/home/u/bin/unreadable-interp", true, true, "/home/u/bin/unreadable", "can't be read"},
		{"/init", true, false, "", "launcher of Windows programs"},
		{"/home/u/bin/init-claude", true, false, "/init", "launcher of Windows programs"},
		{"/home/u/bin/winrun-claude", true, false, "/usr/local/bin/winrun", "launcher of Windows programs"},
		{"/home/u/bin/env-init", true, false, "/init", "launcher of Windows programs"},
		{"/home/u/bin/two-claude", true, false, "/mnt/c/nodejs/node.exe", "is on a Windows drive"},
		{"/home/u/bin/deep0", false, false, "", ""},
		{"/home/u/bin/deeper0", true, true, "/home/u/bin/deep3", "more interpreters"}, // linux stops there (ELOOP)
		{"/home/u/bin/esc-claude", true, false, "/mnt/c/x\x1b]52;c;AAAA\x07y", "is on a Windows drive"},
		{"relative/claude", true, true, "", "not an absolute path"},
	} {
		err := checkProgram(wsl, env, c.exe, sys.io())
		var pe *ProgramError
		if !c.refused {
			if err != nil {
				t.Errorf("%s: %v, want accepted", c.exe, err)
			}
			continue
		}
		if !errors.As(err, &pe) || !errors.Is(err, ErrWindowsProgram) || pe.Exe != c.exe || pe.Runs != c.runs || pe.Unknown != c.unknown || !strings.Contains(pe.Why, c.why) {
			t.Errorf("%s: %v (%+v), want refused (runs %q, unknown %v, %q)", c.exe, err, pe, c.runs, c.unknown, c.why)
			continue
		}
		if strings.ContainsAny(pe.Why, "/\x1b\x07") {
			t.Errorf("%s: Why %q holds a path or a control character", c.exe, pe.Why)
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
