package doctor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
)

// Agent, background-sweep and permission checks (SPEC §6.1, §10.1, §13;
// D6, UX23, R15): the agent's answer, the heartbeat and a stuck sweep lock
// under service-running; the run directory and socket under agent-socket;
// the privacy of precinto's own paths under permissions (EnsureDirs and
// fsx refuse a directory that is a symlink, foreign or not private).

const (
	// sweepInterval is how often the LaunchAgent sweeps (SPEC §13.1);
	// staleSweep is when the heartbeat counts as missed.
	sweepInterval = 10 * time.Minute
	staleSweep    = 3 * sweepInterval
	// stuckLock is how long a sweep may hold the sweep lock before doctor
	// calls it stuck.
	stuckLock = time.Hour
)

func checkServiceRunning(e *env) []Finding {
	var out []Finding
	out = append(out, e.agentFindings()...)
	out = append(out, e.sweepFindings()...)
	out = append(out, e.lockFindings()...)
	if len(out) == 0 {
		out = append(out, ok(CheckServiceRunning, "precinto's agent and background sealing look healthy"))
	}
	return out
}

// checkAgentSocket checks the run directory and the socket (D6).
func checkAgentSocket(e *env) []Finding {
	out := e.part(CheckAgentSocket, e.socketFindings)
	if len(out) == 0 {
		out = append(out, ok(CheckAgentSocket, "precinto's socket folder and socket are private"))
	}
	return out
}

// checkPermissions checks that precinto's own directories and Claude's
// temp folder are private (S7, D6).
func checkPermissions(e *env) []Finding {
	var out []Finding
	out = append(out, e.part(CheckPermissions, e.permissionFindings)...)
	out = append(out, e.part(CheckPermissions, e.claudeTmpPermissions)...)
	if len(out) == 0 {
		out = append(out, ok(CheckPermissions, "precinto's folders and Claude's temp folder are private"))
	}
	return out
}

// agentFindings reports how the agent answered the status query.
func (e *env) agentFindings() []Finding {
	st := e.daemon()
	err := e.statusErr
	switch {
	case st != nil:
		return nil
	case errors.Is(err, ipc.ErrUntrustedServer):
		return []Finding{fail(CheckServiceRunning, "the process answering on precinto's socket is not this precinto binary, so unlocks and gates refuse to talk to it",
			"precinto agent --restart")}
	case errors.Is(err, ipc.ErrNoDaemon), err == nil:
		return nil // not running: it starts when needed (SPEC §13.1)
	case errors.Is(err, context.DeadlineExceeded):
		return []Finding{warn(CheckServiceRunning, "the precinto agent did not answer within "+daemonTimeout.String(), "precinto agent --restart")}
	}
	return []Finding{warn(CheckServiceRunning, "the precinto agent could not be asked for its status ("+errClass(err)+")", "precinto agent --restart")}
}

// socketFindings checks the run directory and the socket (D6): a symlink, a
// foreign owner or open permissions make clients refuse the agent, or let
// another user's process pose as it.
func (e *env) socketFindings() []Finding {
	l := e.o.Layout
	var out []Finding
	if len(l.Socket) >= paths.MaxSocketPath {
		out = append(out, fail(CheckAgentSocket, fmt.Sprintf("precinto's socket path is %d bytes long; the limit is %d", len(l.Socket), paths.MaxSocketPath-1), ""))
	}
	if p := dirProblem(l.RunDir, e.d.EUID); p.text != "" {
		out = append(out, fail(CheckAgentSocket, "precinto's socket folder "+e.show(l.RunDir)+" "+p.text+": the agent and its clients refuse it", p.fix(e, l.RunDir, true)))
	}
	st, err := fsx.Lstat(l.Socket)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		out = append(out, warn(CheckAgentSocket, "could not check precinto's socket "+e.show(l.Socket)+" ("+errClass(err)+")", ""))
	case st.Mode&0o170000 != 0o140000:
		out = append(out, fail(CheckAgentSocket, e.show(l.Socket)+" is not a socket: the agent cannot start", "precinto agent --restart"))
	case int64(st.UID) != int64(e.d.EUID):
		out = append(out, fail(CheckAgentSocket, fmt.Sprintf("precinto's socket %s belongs to another user (uid %d)", e.show(l.Socket), st.UID), "precinto agent --restart"))
	case st.Mode&0o077 != 0:
		out = append(out, fail(CheckAgentSocket, fmt.Sprintf("precinto's socket %s can be used by other users (mode %04o)", e.show(l.Socket), st.Mode&0o7777), "precinto agent --restart"))
	case e.daemon() == nil && errors.Is(e.statusErr, ipc.ErrNoDaemon):
		out = append(out, info(CheckAgentSocket, "a stale agent socket is left at "+e.show(l.Socket)+"; the next agent start replaces it", ""))
	}
	return out
}

// problem is a permission problem of one path.
type problem struct {
	text   string
	severe bool // writable by others, a symlink or a foreign owner
	mode   bool // fixable with chmod
}

func (p problem) fix(e *env, path string, dir bool) string {
	switch {
	case p.mode && dir:
		return "chmod 700 " + e.arg(path)
	case p.mode:
		return "chmod 600 " + e.arg(path)
	}
	return "move " + e.arg(path) + " aside; precinto creates a private one"
}

// dirProblem and fileProblem apply the private-path rule of
// fsx.CheckPrivateDir to an existing path ("" when fine or missing).
func dirProblem(path string, euid int) problem  { return pathProblem(path, true, euid) }
func fileProblem(path string, euid int) problem { return pathProblem(path, false, euid) }

func pathProblem(path string, wantDir bool, euid int) problem {
	st, err := fsx.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return problem{}
		}
		return problem{text: "cannot be checked (" + errClass(err) + ")"}
	}
	const typeMask, symlink, dir = 0o170000, 0o120000, 0o040000
	switch typ := st.Mode & typeMask; {
	case typ == symlink:
		return problem{text: "is a symbolic link", severe: true}
	case wantDir && typ != dir:
		return problem{text: "is not a directory", severe: true}
	case !wantDir && !st.IsRegular():
		return problem{text: "is not a regular file", severe: true}
	case int64(st.UID) != int64(euid):
		return problem{text: fmt.Sprintf("belongs to another user (uid %d)", st.UID), severe: true}
	case st.Mode&0o022 != 0:
		return problem{text: fmt.Sprintf("can be changed by other users (mode %04o)", st.Mode&0o7777), severe: true, mode: true}
	case st.Mode&0o077 != 0:
		return problem{text: fmt.Sprintf("can be read by other users (mode %04o)", st.Mode&0o7777), mode: true}
	}
	return problem{}
}

// precintoDirs are the Layout directories EnsureDirs manages (paths
// layout.go), parents first, and the marketplace integrate writes (a
// missing one is no finding); the run directory is agent-socket's.
func precintoDirs(l paths.Layout) []string {
	return []string{l.Base, filepath.Dir(l.BinLink), l.VaultsDir, l.FactorsDir, l.CapsulesDir, l.HomesDir,
		l.StagingDir, l.QuarantineDir, l.StateDir, l.VerifiedDir, l.GensDir, l.ReceiptsDir, l.LeasesDir,
		l.SessionsDir, l.ProjectsDir, l.JournalDir, l.QueueDir, l.LocksDir, l.HookDedupeDir, l.LogsDir, l.Marketplace}
}

// precintoFiles are precinto's own metadata files at fixed Layout paths
// (state/notes.json holds note paths, CC-34).
func precintoFiles(l paths.Layout) []string {
	return []string{l.ConfigFile, l.RootsList, l.NameSalt, l.CapsuleLog, l.PolicyPinned, l.NotesIndex,
		l.LogFile, l.SweepLast, l.SweepRequested}
}

// permissionFinding renders the permission problem p of one of precinto's
// paths (no finding when there is none).
func (e *env) permissionFinding(path string, dir bool, p problem) []Finding {
	if p.text == "" {
		return nil
	}
	what := "file"
	if dir {
		what = "folder"
	}
	msg := "precinto's " + what + " " + e.show(path) + " " + p.text
	if p.severe {
		return []Finding{fail(CheckPermissions, msg+": precinto refuses to use it, or another user could change it", p.fix(e, path, dir))}
	}
	return []Finding{warn(CheckPermissions, msg, p.fix(e, path, dir))}
}

// permissionFindings checks precinto's own directories and metadata files,
// the vault directories with their files (SPEC §6.1: directories 0700,
// files 0600) and the per-volume restore staging directories (fsx refuses
// one that is not private, and others could read what is staged there).
func (e *env) permissionFindings() []Finding {
	l := e.o.Layout
	var out []Finding
	report := func(path string, dir bool, p problem) { out = append(out, e.permissionFinding(path, dir, p)...) }
	for _, d := range precintoDirs(l) {
		report(d, true, dirProblem(d, e.d.EUID))
	}
	for _, f := range precintoFiles(l) {
		report(f, false, fileProblem(f, e.d.EUID))
	}
	for _, d := range e.volumeStagingDirs() {
		report(d, true, dirProblem(d, e.d.EUID))
	}
	vaults, _ := listDir(l.VaultsDir)
	for _, v := range vaults {
		vdir := filepath.Join(l.VaultsDir, v.Name())
		if id, ok := vaultLockName(v.Name()); ok && vaultIDName(id) {
			// The lock serializing vault.toml rewrites (vault
			// metaLockPath): a private file, never deleted, never
			// moved aside while a process may hold it (UX-05).
			p := fileProblem(vdir, e.d.EUID)
			if p.text != "" && !p.mode {
				out = append(out, e.lockFinding(vdir, p))
				continue
			}
			report(vdir, false, p)
			continue
		}
		if !vaultIDName(v.Name()) {
			continue // a dot name is never a vault (an interrupted creation's staging folder)
		}
		report(vdir, true, dirProblem(vdir, e.d.EUID))
		files, _ := listDir(vdir)
		for _, f := range files {
			if !f.IsDir() {
				p := filepath.Join(vdir, f.Name())
				report(p, false, fileProblem(p, e.d.EUID))
			}
		}
	}
	verified, _ := listDir(l.VerifiedDir)
	for _, f := range verified {
		p := filepath.Join(l.VerifiedDir, f.Name())
		report(p, false, fileProblem(p, e.d.EUID))
	}
	return out
}

// vaultIDName reports whether name can be a vault folder of vaults/: the
// vault package's id rule (letters, digits, '-', '_', '.', never a leading
// '.' or '-'). Lock files and interrupted creations use dot names.
func vaultIDName(name string) bool {
	if name == "" || len(name) > 128 || name[0] == '.' || name[0] == '-' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// vaultLockName returns the vault id of a vaults/.<id>.lock name.
func vaultLockName(name string) (string, bool) {
	if !strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".lock") || len(name) <= len("..lock") {
		return "", false
	}
	return name[1 : len(name)-len(".lock")], true
}

// lockFinding reports a vault lock file that is not a private regular file
// of the user. Its fix waits for every precinto process: moving or removing
// a lock while one holds it breaks the mutual exclusion it provides.
func (e *env) lockFinding(path string, p problem) Finding {
	return fail(CheckPermissions, "precinto's lock file "+e.show(path)+" "+p.text+": vault settings cannot be updated safely",
		"remove "+e.arg(path)+" while no precinto command or agent runs (precinto creates a new one)")
}

// launchAgentInstalled reports whether precinto's LaunchAgent exists
// (darwin `precinto service install`, SPEC §13.1): exactly
// ~/Library/LaunchAgents/<paths.ServiceLabel>.plist (CC-37).
func (e *env) launchAgentInstalled() bool {
	if e.d.GOOS != "darwin" || e.home == "" {
		return false
	}
	es, err := listDir(filepath.Join(e.home, "Library", "LaunchAgents"))
	if err != nil {
		return false
	}
	for _, en := range es {
		if en.Name() == paths.ServiceLabel+".plist" {
			return true
		}
	}
	return false
}

// modTime returns the mtime of path (zero when missing).
func modTime(path string) time.Time {
	fi, err := os.Lstat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// ago renders a duration for messages ("3 h", "2 days").
func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute", "minutes")
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour", "hours")
	}
	return plural(int(d/(24*time.Hour)), "day", "days")
}

// sweepFindings checks the background re-seal heartbeat (UX23).
func (e *env) sweepFindings() []Finding {
	l := e.o.Layout
	last := modTime(l.SweepLast)
	var out []Finding
	if e.d.GOOS == "darwin" {
		if !e.launchAgentInstalled() {
			out = append(out, info(CheckServiceRunning, "background sealing is not installed: sessions are sealed when they end and when a folder locks, not every 10 minutes", "precinto service install"))
		} else if last.IsZero() {
			out = append(out, warn(CheckServiceRunning, "background sealing is installed but has never completed a sweep", "precinto service status"))
		} else if age := e.now.Sub(last); age > staleSweep {
			out = append(out, warn(CheckServiceRunning, "background sealing last completed a sweep "+ago(age)+" ago (it runs every 10 minutes)", "precinto service status"))
		}
	}
	if req := modTime(l.SweepRequested); !req.IsZero() && req.After(last) && e.now.Sub(req) > staleSweep {
		out = append(out, warn(CheckServiceRunning, "a sweep was requested "+ago(e.now.Sub(req))+" ago and has not run since", "precinto sweep"))
	}
	return out
}

// lockFindings reports a sweep lock held for too long: every background
// seal waits for it (SPEC §10.2). Holders come from the process table's
// open-file view (lsof); the lock itself is never probed. On Linux that
// view leaves out a hardened precinto, whose fd/ is refused (D65), so a
// sweep holding the lock is not seen and nothing is reported.
func (e *env) lockFindings() []Finding {
	if e.o.Procs == nil {
		return nil
	}
	lock := e.o.Layout.LockFile("sweep")
	if !exists(lock) {
		return nil
	}
	ctx, cancel := e.bounded()
	defer cancel()
	hs, err := e.o.Procs.OpenFilesUnder(ctx, []string{e.o.Layout.LocksDir})
	if err != nil {
		return nil
	}
	var out []Finding
	for _, h := range hs {
		if filepath.Clean(h.Path) != lock || h.Proc.ID.StartUS <= 0 {
			continue
		}
		started := platform.StartTime(h.Proc.ID)
		if started.IsZero() {
			continue
		}
		held := e.now.Sub(started)
		if held > stuckLock {
			out = append(out, warn(CheckServiceRunning, fmt.Sprintf("the sweep lock has been held for %s by pid %d: background sealing waits for it", ago(held), h.Proc.ID.PID),
				fmt.Sprintf("check whether process %d (a precinto sweep) is stuck", h.Proc.ID.PID)))
		}
	}
	return out
}

// tccProtected are the home folders macOS privacy settings (TCC) guard
// from a LaunchAgent (R15).
var tccProtected = []string{"Desktop", "Documents", "Downloads", "Library/Mobile Documents"}

func checkServiceTCC(e *env) []Finding {
	if e.d.GOOS != "darwin" || !e.launchAgentInstalled() {
		return nil
	}
	var out []Finding
	for _, r := range e.o.Cfg.Roots {
		where := ""
		for _, d := range tccProtected {
			if e.home != "" && paths.Within(filepath.Join(e.home, d), r.Path) {
				where = d
			}
		}
		if where == "" && paths.Within("/Volumes", r.Path) {
			where = "an external or network volume"
		}
		if where != "" {
			out = append(out, warn(CheckServiceTCC, "background sealing runs as a LaunchAgent, which macOS may not let read "+e.folder(r)+" (in "+where+"): its files can stay unsealed until a sweep runs from a terminal",
				"allow precinto in System Settings > Privacy & Security > Files and Folders (or Full Disk Access), or keep the folder elsewhere"))
		}
	}
	sums, err := e.plaintextSummary()
	if err == nil {
		for _, p := range sums {
			if n := p.ByReason["inaccessible"]; n > 0 {
				out = append(out, warn(CheckServiceTCC, plural(n, "file", "files")+" of "+e.folderOf(p.RootID)+" could not be read by precinto (macOS privacy settings or permissions), so "+verb(n, "it stays", "they stay")+" unsealed",
					"run precinto sweep from a terminal, or allow precinto in System Settings > Privacy & Security > Files and Folders"))
			}
		}
	}
	if len(out) == 0 {
		out = append(out, ok(CheckServiceTCC, "background sealing can read every protected folder"))
	}
	return out
}
