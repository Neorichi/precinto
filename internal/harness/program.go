package harness

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Neorichi/precinto/internal/paths"
)

// ErrWindowsProgram marks a harness executable precinto refuses under WSL
// because it would run as a Windows program (D156): WSL appends the
// Windows PATH to the Linux one by default, so `claude` or `codex` can
// resolve to a Windows install, whose processes and files precinto can
// neither see nor seal.
var ErrWindowsProgram = errors.New("harness: a Windows program")

// ProgramError is CheckProgram's refusal of an executable.
type ProgramError struct {
	Harness ID     // the harness the executable was to run
	Exe     string // the executable, absolute, as resolved for the launch
	// Runs is the program Exe runs that is, or may be, the Windows one:
	// a "#!" interpreter or the command of an env line, at any depth; ""
	// when Exe itself is. A path: display it as one (it comes from files
	// the user's programs can write).
	Runs    string
	Why     string // short and content-free: what makes Runs (or Exe) a Windows program, or why precinto could not tell
	Unknown bool   // precinto could not tell (refused all the same)
}

func (e *ProgramError) Error() string {
	if e.Runs != "" {
		return fmt.Sprintf("harness: %s runs %s, which %s", e.Exe, e.Runs, e.Why)
	}
	return fmt.Sprintf("harness: %s %s", e.Exe, e.Why)
}

// Is makes errors.Is(err, ErrWindowsProgram) hold for every ProgramError.
func (e *ProgramError) Is(target error) bool { return target == ErrWindowsProgram }

// CheckProgram refuses, under WSL, the executable exe (absolute) of
// harness h when it would run as a Windows program (D156): exe or the
// file it links to lies on a Windows drive, it is a Windows executable (it
// starts with the PE header "MZ"), it is WSL's launcher of Windows
// programs (/init, the interpreter of the WSLInterop binfmt entry), or
// the interpreter of its "#!" line is or does any of that, in turn, as
// deep as linux follows interpreters; a "#!/usr/bin/env ARG" line is read
// as env reads it (-S and --split-string split ARG; NAME=value, -i and -u
// change the PATH that names the command) and its command checked the
// same way (an npm install runs `#!/usr/bin/env node`, and Windows's
// node.exe can be first in the PATH of e). It returns nil outside WSL
// without reading anything, and a *ProgramError (errors.Is
// ErrWindowsProgram) otherwise; an executable that exists but cannot be
// read, an env line precinto cannot read and a chain deeper than linux
// follows are refused too (Unknown), a missing one is left to fail at
// exec as it always did. A script whose body starts a Windows program is
// not seen here.
func CheckProgram(e paths.Env, h ID, exe string) error {
	err := checkProgram(paths.DetectWSL(), e, exe, programIO{drive: paths.CheckDrive, head: readHead, look: paths.LookPath, launcher: isInteropLauncher})
	var pe *ProgramError
	if errors.As(err, &pe) {
		pe.Harness = h
	}
	return err
}

// programIO is how checkProgram reads the system; tests fake it.
type programIO struct {
	drive    func(p string) error                           // paths.CheckDrive
	head     func(p string) ([]byte, error)                 // the first bytes of a regular file
	look     func(e paths.Env, name string) (string, error) // paths.LookPath
	launcher func(p string) bool                            // p is WSL's /init (isInteropLauncher)
}

// maxInterpreters is how many "#!" interpreters checkProgram follows in a
// row, as linux does (fs/exec.c: exec_binprm gives up deeper, with
// ELOOP); env's command counts as one more.
const maxInterpreters = 5

// checkProgram implements CheckProgram over an explicit WSL and I/O.
func checkProgram(w paths.WSL, e paths.Env, exe string, sys programIO) error {
	if w.Version == 0 {
		return nil
	}
	if !filepath.IsAbs(exe) {
		return &ProgramError{Exe: exe, Why: "is not an absolute path", Unknown: true}
	}
	pe := checkFile(e, exe, 0, sys)
	if pe == nil {
		return nil
	}
	pe.Exe = exe
	if pe.Runs == exe {
		pe.Runs = ""
	}
	return pe
}

// checkFile checks p, a program the launch runs (the executable, an
// interpreter, env's command), and what it runs in turn, depth programs
// down: nil, or a ProgramError naming as Runs the program that is, or may
// be, a Windows one.
func checkFile(e paths.Env, p string, depth int, sys programIO) *ProgramError {
	if sys.launcher != nil && sys.launcher(p) {
		return &ProgramError{Runs: p, Why: "is WSL's launcher of Windows programs"}
	}
	head, pe := checkBinary(p, sys)
	if pe != nil || head == nil {
		return pe // a missing program fails at exec, as it always did
	}
	interp, arg, ok := shebang(head)
	if !ok || !filepath.IsAbs(interp) {
		return nil // no script, or one the kernel cannot run (no relative interpreter)
	}
	if depth >= maxInterpreters {
		return &ProgramError{Runs: p, Why: "runs through more interpreters than linux follows", Unknown: true}
	}
	if pe := checkFile(e, interp, depth+1, sys); pe != nil {
		return pe
	}
	if filepath.Base(interp) != "env" {
		return nil
	}
	cmd, pathList, ok := envCommand(arg, e.Get("PATH"))
	switch {
	case !ok:
		return &ProgramError{Runs: interp, Why: "is given options precinto can't read", Unknown: true}
	case cmd == "":
		return nil // env runs no command
	case !strings.Contains(cmd, "/"):
		found, err := sys.look(paths.FromMap(map[string]string{"PATH": pathList}), cmd)
		if err != nil {
			return nil // not found: the script cannot start at all
		}
		cmd = found
	case !filepath.IsAbs(cmd):
		return &ProgramError{Runs: cmd, Why: "is not an absolute path", Unknown: true}
	}
	return checkFile(e, cmd, depth+1, sys)
}

// checkBinary refuses p on a Windows drive or with a PE header, and
// returns its first bytes (nil when p does not exist: nothing runs).
func checkBinary(p string, sys programIO) ([]byte, *ProgramError) {
	if err := sys.drive(p); err != nil {
		var de *paths.DriveError
		if errors.As(err, &de) && de.Unknown {
			return nil, &ProgramError{Runs: p, Why: "may be on a Windows drive (precinto could not tell)", Unknown: true}
		}
		return nil, &ProgramError{Runs: p, Why: "is on a Windows drive"}
	}
	head, err := sys.head(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, &ProgramError{Runs: p, Why: "can't be read to check that it is not a Windows program", Unknown: true}
	}
	if isPE(head) {
		return nil, &ProgramError{Runs: p, Why: "is a Windows executable"}
	}
	if head == nil {
		head = []byte{} // an empty file exists: never nil
	}
	return head, nil
}

// interopLauncher is WSL's /init, the interpreter its WSLInterop binfmt
// entry names: run as a program it starts the Windows program its
// arguments name (microsoft/WSL: WslEntryPoint falls through to
// CreateNtProcess).
const interopLauncher = "/init"

// isInteropLauncher reports whether p is /init, by file identity (a link
// to it, or a hard link, is it too).
func isInteropLauncher(p string) bool {
	if p == interopLauncher {
		return true
	}
	a, err := os.Stat(p)
	if err != nil {
		return false
	}
	b, err := os.Stat(interopLauncher)
	return err == nil && os.SameFile(a, b)
}

// headSize is how much of an executable checkProgram reads: the PE magic
// and a "#!" line (the kernel reads at most 256 bytes of it).
const headSize = 256

// readHead reads the first bytes of a regular file, following symlinks
// (O_NONBLOCK: a FIFO named like a harness never blocks the check).
func readHead(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("harness: %s is not a regular file", filepath.Base(p))
	}
	return io.ReadAll(io.LimitReader(f, headSize))
}

// isPE reports a Windows executable: the DOS header of a PE file starts
// with "MZ" (WSL registers its interop binfmt_misc entry on that magic).
func isPE(head []byte) bool { return bytes.HasPrefix(head, []byte("MZ")) }

// shebang returns the interpreter of a "#!" line and its single optional
// argument, as linux passes them (the rest of the line after the
// interpreter, one argument, spaces trimmed).
func shebang(head []byte) (interp, arg string, ok bool) {
	rest, found := bytes.CutPrefix(head, []byte("#!"))
	if !found {
		return "", "", false
	}
	line, _, _ := bytes.Cut(rest, []byte("\n"))
	s := strings.TrimSpace(strings.TrimSuffix(string(line), "\r"))
	if s == "" {
		return "", "", false
	}
	interp, arg, _ = strings.Cut(strings.ReplaceAll(s, "\t", " "), " ")
	return interp, strings.TrimSpace(arg), true
}

// envCommand returns the command a "#!<env> ARG" line runs, read as GNU
// env reads its arguments (the kernel passes the rest of the line as one
// argument, ARG), and the PATH execvp will search for it: path as
// changed by NAME=value (PATH), -i (no environment: the C library's
// default, /bin:/usr/bin) and -u PATH. -S and --split-string split their
// value (attached or not) into more arguments; one that quotes, escapes,
// expands a variable or comments is not split here. cmd is "" when env
// runs no command; ok is false when precinto cannot tell (an option it
// does not know, a split it does not do).
func envCommand(arg, path string) (cmd, pathList string, ok bool) {
	const defaultPath = "/bin:/usr/bin"
	args := []string{arg}
	insert := func(i int, more []string) {
		rest := append([]string(nil), args[i+1:]...)
		args = append(append(args[:i+1], more...), rest...)
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if i+1 < len(args) {
				return args[i+1], path, true
			}
			return "", path, true
		case a == "-":
			path = defaultPath // -i
		case strings.HasPrefix(a, "--"):
			name, val, hasVal := strings.Cut(a[2:], "=")
			if (name == "split-string" || name == "unset" || name == "chdir" || name == "argv0") && !hasVal {
				if i+1 >= len(args) {
					return "", "", false
				}
				i++
				val = args[i]
			}
			switch name {
			case "split-string":
				more, ok := splitEnvString(val)
				if !ok {
					return "", "", false
				}
				insert(i, more)
			case "unset":
				if val == "PATH" {
					path = defaultPath
				}
			case "ignore-environment":
				path = defaultPath
			case "chdir", "argv0", "null", "debug", "block-signal", "default-signal", "ignore-signal":
			default:
				return "", "", false
			}
		case strings.HasPrefix(a, "-"):
			for j := 1; j < len(a); j++ {
				switch c := a[j]; c {
				case 'i':
					path = defaultPath
				case '0', 'v':
				case 'u', 'C', 'a', 'S':
					val := a[j+1:]
					if val == "" {
						if i+1 >= len(args) {
							return "", "", false
						}
						i++
						val = args[i]
					}
					switch c {
					case 'u':
						if val == "PATH" {
							path = defaultPath
						}
					case 'S':
						more, ok := splitEnvString(val)
						if !ok {
							return "", "", false
						}
						insert(i, more)
					}
					j = len(a)
				default:
					return "", "", false
				}
			}
		case strings.Contains(a, "="):
			if name, val, _ := strings.Cut(a, "="); name == "PATH" {
				path = val
			}
		default:
			return a, path, true
		}
	}
	return "", path, true
}

// splitEnvString splits the value of env -S on spaces and tabs; a value
// with a quote, an escape, a variable or a comment, which env would
// process, is not split here (ok false).
func splitEnvString(s string) ([]string, bool) {
	if strings.ContainsAny(s, "'\"\\$#") {
		return nil, false
	}
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' }), true
}
