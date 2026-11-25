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

	"github.com/precinto/precinto/internal/paths"
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
	Why     string // short and content-free: what makes it a Windows program
	Unknown bool   // precinto could not tell (refused all the same)
}

func (e *ProgramError) Error() string {
	return fmt.Sprintf("harness: %s %s", e.Exe, e.Why)
}

// Is makes errors.Is(err, ErrWindowsProgram) hold for every ProgramError.
func (e *ProgramError) Is(target error) bool { return target == ErrWindowsProgram }

// CheckProgram refuses, under WSL, the executable exe (absolute) of
// harness h when it would run as a Windows program (D156): exe or the
// file it links to lies on a Windows drive, it is a Windows executable (it
// starts with the PE header "MZ"), or the interpreter of its "#!" line
// does or is, a "#!/usr/bin/env CMD" line naming CMD as found in the PATH
// of e (an npm install runs `#!/usr/bin/env node`, and Windows's node.exe
// can be first in that PATH). It returns nil outside WSL without reading
// anything, and a *ProgramError (errors.Is ErrWindowsProgram) otherwise;
// an executable that exists but cannot be read is refused too, a missing
// one is left to fail at exec as it always did.
func CheckProgram(e paths.Env, h ID, exe string) error {
	err := checkProgram(paths.DetectWSL(), e, exe, programIO{drive: paths.CheckDrive, head: readHead, look: paths.LookPath})
	var pe *ProgramError
	if errors.As(err, &pe) {
		pe.Harness = h
	}
	return err
}

// programIO is how checkProgram reads the system; tests fake it.
type programIO struct {
	drive func(p string) error                           // paths.CheckDrive
	head  func(p string) ([]byte, error)                 // the first bytes of a regular file
	look  func(e paths.Env, name string) (string, error) // paths.LookPath
}

// checkProgram implements CheckProgram over an explicit WSL and I/O.
func checkProgram(w paths.WSL, e paths.Env, exe string, sys programIO) error {
	if w.Version == 0 {
		return nil
	}
	if !filepath.IsAbs(exe) {
		return &ProgramError{Exe: exe, Why: "is not an absolute path", Unknown: true}
	}
	head, err := checkBinary(exe, sys)
	if err != nil || head == nil {
		return err // a missing executable fails at exec, as it always did
	}
	interp, arg, ok := shebang(head)
	if !ok || !filepath.IsAbs(interp) {
		return nil // no script, or one the kernel cannot run (no relative interpreter)
	}
	if err := checkRuns(exe, interp, sys); err != nil || filepath.Base(interp) != "env" {
		return err
	}
	cmd := envCommand(arg)
	if cmd == "" {
		return nil
	}
	if !strings.Contains(cmd, "/") {
		p, err := sys.look(e, cmd)
		if err != nil {
			return nil // not found: the script cannot start at all
		}
		cmd = p
	}
	if !filepath.IsAbs(cmd) {
		return nil
	}
	return checkRuns(exe, cmd, sys)
}

// checkRuns refuses exe when the program it runs (its interpreter, or the
// command its env line names) is a Windows program.
func checkRuns(exe, runs string, sys programIO) error {
	_, err := checkBinary(runs, sys)
	var pe *ProgramError
	if errors.As(err, &pe) {
		pe.Exe, pe.Why = exe, "runs "+runs+", which "+pe.Why
	}
	return err
}

// checkBinary refuses p on a Windows drive or with a PE header, and
// returns its first bytes (nil when p does not exist: nothing runs).
func checkBinary(p string, sys programIO) ([]byte, error) {
	if err := sys.drive(p); err != nil {
		var de *paths.DriveError
		if errors.As(err, &de) && de.Unknown {
			return nil, &ProgramError{Exe: p, Why: "may be on a Windows drive (precinto could not tell)", Unknown: true}
		}
		return nil, &ProgramError{Exe: p, Why: "is on a Windows drive"}
	}
	head, err := sys.head(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, &ProgramError{Exe: p, Why: "cannot be read to check that it is not a Windows program", Unknown: true}
	}
	if isPE(head) {
		return nil, &ProgramError{Exe: p, Why: "is a Windows executable"}
	}
	if head == nil {
		head = []byte{} // an empty file exists: never nil
	}
	return head, nil
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

// envCommand returns the command a "#!/usr/bin/env ARG" line runs:
// options (-S splits the argument; -i, -u NAME) and NAME=value
// assignments are skipped, the first remaining word is the command.
func envCommand(arg string) string {
	words := strings.Fields(arg)
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch {
		case w == "-u" || w == "--unset" || w == "-C" || w == "--chdir":
			i++ // the option's value
		case strings.HasPrefix(w, "-"):
		case strings.Contains(w, "="):
		default:
			return w
		}
	}
	return ""
}
