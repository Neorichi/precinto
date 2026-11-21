package platform

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/precinto/precinto/internal/paths"
)

// This file holds the OS-independent part of the implementation. Every
// OS-specific mechanism lives behind the sys* functions of proc_*.go,
// peer_*.go, screen_*.go, harden_*.go, misc_*.go and unsupported_other.go,
// which never declare exported identifiers (apidoc refuses them there).

// formatProcID implements ProcID.String: "PID:START" (no boot id: the
// --wait-pid syntax names a process of the current boot).
func formatProcID(id ProcID) string {
	return strconv.Itoa(id.PID) + ":" + strconv.FormatInt(id.StartUS, 10)
}

// parseProcID implements ParseProcID. Both fields must be positive decimal
// numbers without sign or spaces. A "PID:START" string always names a
// process of the current boot, so the boot id of this boot is filled in
// (linux; empty on darwin): the result then compares equal to a ProcID
// measured now for the same incarnation.
func parseProcID(s string) (ProcID, error) {
	pidS, startS, ok := strings.Cut(s, ":")
	if !ok {
		return ProcID{}, fmt.Errorf("platform: malformed process id: want PID:START")
	}
	pid, ok1 := parsePositive(pidS, math.MaxInt32)
	start, ok2 := parsePositive(startS, math.MaxInt64)
	if !ok1 || !ok2 {
		return ProcID{}, fmt.Errorf("platform: malformed process id: want PID:START with positive decimal numbers")
	}
	return ProcID{PID: int(pid), StartUS: start, BootID: sysBootID()}, nil
}

// parsePositive parses a positive decimal number made of digits only (no
// sign, no spaces, no leading zeros) that is at most max.
func parsePositive(s string, max int64) (int64, bool) {
	if s == "" || len(s) > 19 || s[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 || v > max {
		return 0, false
	}
	return v, true
}

// systemTable is the real process table. It is an empty struct so that
// every System() value compares equal (callers may compare a ProcTable with
// System() to know whether facts come from the kernel).
type systemTable struct{}

var _ ProcTable = systemTable{}

func (systemTable) Lookup(pid int) (ProcInfo, error) {
	if pid <= 0 {
		return ProcInfo{}, fmt.Errorf("platform: pid %d: %w", pid, ErrNoProcess)
	}
	return sysLookup(pid)
}

func (systemTable) Alive(id ProcID) bool { return alive(id) }

func (systemTable) List() ([]ProcInfo, error) { return sysList() }

func (systemTable) Cwd(id ProcID) (string, error) {
	if !alive(id) {
		return "", fmt.Errorf("platform: cwd of pid %d: %w", id.PID, ErrNotSame)
	}
	cwd, err := sysCwd(id)
	if err != nil {
		return "", err
	}
	// The pid could have been reused while the cwd was read: the answer is
	// only valid if the same incarnation is still running afterwards.
	if !alive(id) {
		return "", fmt.Errorf("platform: cwd of pid %d: %w", id.PID, ErrNotSame)
	}
	return cwd, nil
}

func (systemTable) OpenFilesUnder(ctx context.Context, dirs []string) ([]Holder, error) {
	if ctx == nil {
		return nil, fmt.Errorf("platform: open files: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("platform: open files: %w", err)
	}
	clean := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if !filepath.IsAbs(d) {
			return nil, fmt.Errorf("platform: open files: directory is not absolute")
		}
		clean = append(clean, filepath.Clean(d))
	}
	if len(clean) == 0 {
		return []Holder{}, nil
	}
	return sysOpenFilesUnder(ctx, clean)
}

// withinAny reports whether p is one of roots or below one of them
// (paths.Within semantics: component-wise, case-folded on darwin).
func withinAny(roots []string, p string) bool {
	for _, r := range roots {
		if paths.Within(r, p) {
			return true
		}
	}
	return false
}

// resolvedRoots returns dirs plus the realpath of each existing one: the
// kernel reports resolved paths (darwin /var is /private/var), callers pass
// configured ones.
func resolvedRoots(dirs []string) []string {
	out := append([]string(nil), dirs...)
	for _, d := range dirs {
		if r, err := filepath.EvalSymlinks(d); err == nil && r != d {
			out = append(out, r)
		}
	}
	return out
}

// selfID caches the identity of the current process.
var selfID struct {
	sync.Mutex
	id ProcID
}

// self implements Self. The measurement is cached once it succeeds; if it
// fails (it should not for a running process) the pid alone is returned and
// the next call measures again.
func self() ProcID {
	selfID.Lock()
	defer selfID.Unlock()
	if !selfID.id.IsZero() {
		return selfID.id
	}
	id, _, err := sysIdentifyState(os.Getpid())
	if err != nil {
		return ProcID{PID: os.Getpid()}
	}
	selfID.id = id
	return id
}

// identify implements Identify: the ProcID of a live (not zombie) pid.
func identify(pid int) (ProcID, error) {
	if pid <= 0 {
		return ProcID{}, fmt.Errorf("platform: pid %d: %w", pid, ErrNoProcess)
	}
	id, state, err := sysIdentifyState(pid)
	if err != nil {
		return ProcID{}, err
	}
	if state == StateZombie {
		return ProcID{}, fmt.Errorf("platform: pid %d is a zombie: %w", pid, ErrNoProcess)
	}
	return id, nil
}

// alive reports whether id is running with the same start time (and boot)
// and is not a zombie.
func alive(id ProcID) bool {
	if id.PID <= 0 || id.StartUS == 0 {
		return false
	}
	cur, state, err := sysIdentifyState(id.PID)
	return err == nil && cur == id && state != StateZombie
}

// checkLoaderEnv implements CheckLoaderEnv.
func checkLoaderEnv(environ []string) error {
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "DYLD_") || strings.HasPrefix(k, "LD_") {
			return fmt.Errorf("%w: %s", ErrUnsafeEnv, k)
		}
	}
	return nil
}

// monoOrigin carries the monotonic reading SystemClock measures from.
var monoOrigin = time.Now()

// systemClock is the real clock: wall time without its monotonic reading,
// and the Go runtime's monotonic clock (which does not advance while the
// machine sleeps, so sleep shows up as a wall-vs-monotonic jump).
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().Round(0) }

func (systemClock) Mono() time.Duration { return time.Since(monoOrigin) }

// watchJumps implements WatchJumps. Ticks use the real timer; deltas use c,
// so tests drive jumps with a fake clock.
func watchJumps(ctx context.Context, c Clock, every, threshold time.Duration, out chan<- Jump) {
	if every <= 0 {
		every = time.Second
	}
	if threshold < 0 {
		threshold = 0
	}
	t := time.NewTicker(every)
	defer t.Stop()
	lastW, lastM := c.Now(), c.Mono()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		w, m := c.Now(), c.Mono()
		dw, dm := w.Sub(lastW), m-lastM
		lastW, lastM = w, m
		if dw-dm <= threshold {
			continue
		}
		select {
		case out <- Jump{Wall: dw, Mono: dm, At: w}:
		case <-ctx.Done():
			return
		}
	}
}

// detectUIContext implements DetectUIContext.
func detectUIContext(e paths.Env, stdin, stdout *os.File) UIContext {
	u := UIContext{
		TTY:  stdin != nil && stdout != nil && isTerminal(stdin) && isTerminal(stdout),
		Tmux: e.Get("TMUX") != "" || e.Get("STY") != "",
		SSH:  e.Get("SSH_CONNECTION") != "" || e.Get("SSH_TTY") != "" || e.Get("SSH_CLIENT") != "",
	}
	// A dialog of the console session cannot reach a user who is in SSH or
	// in a detached tmux/screen session (D27, C2.nogui).
	u.GUI = !u.SSH && !u.Tmux && sysGUI(e)
	return u
}

// cloudSynced implements CloudSynced for the current user.
func cloudSynced(path string) bool {
	home, err := paths.UserHome(paths.FromOS())
	if err != nil {
		// Without a home the synced locations are unknown: report the
		// path as synced so that doctor warns (fail closed).
		return true
	}
	return cloudSyncedIn(home, path)
}

// cloudSyncedIn reports whether path lies in one of the synced locations
// under home (cloudRoots), comparing the path as given and its realpath.
func cloudSyncedIn(home, path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	candidates := []string{filepath.Clean(path)}
	if r, err := filepath.EvalSymlinks(path); err == nil {
		candidates = append(candidates, r)
	}
	roots := resolvedRoots(cloudRoots(home))
	for _, p := range candidates {
		if withinAny(roots, p) {
			return true
		}
	}
	return false
}

// commonCloudRoots are synced folders that client apps create directly in
// the home directory on every OS.
var commonCloudRoots = []string{
	"Dropbox", "OneDrive", "Google Drive", "My Drive", "Nextcloud", "ownCloud", "pCloudDrive", "Box", "Box Sync", "MEGA",
}

// homeCloudRoots lists commonCloudRoots under home, plus every entry of home
// whose name starts with "OneDrive" or "Dropbox" (business accounts use
// "OneDrive - Org" and "Dropbox (Org)").
func homeCloudRoots(home string) []string {
	var out []string
	for _, n := range commonCloudRoots {
		out = append(out, filepath.Join(home, n))
	}
	if ents, err := os.ReadDir(home); err == nil {
		for _, e := range ents {
			n := e.Name()
			if strings.HasPrefix(n, "OneDrive") || strings.HasPrefix(n, "Dropbox") {
				out = append(out, filepath.Join(home, n))
			}
		}
	}
	return out
}

// parseFdesetup reads `fdesetup status` output.
func parseFdesetup(out string) (on, known bool) {
	switch {
	case strings.Contains(out, "FileVault is On"):
		return true, true
	case strings.Contains(out, "FileVault is Off"):
		return false, true
	}
	return false, false
}

// parseCount reads the single number `mdfind -count` prints.
func parseCount(out string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
