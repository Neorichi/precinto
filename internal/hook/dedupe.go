package hook

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Duplicate suppression for experimental hosts (HA21). Cursor imports
// Claude hooks and Copilot installs Claude plugins, so one event can reach
// precinto through two hooks files. For non-gate events the first
// invocation acts and the others exit 0; gate events are never suppressed
// (each invocation decides, and the host lets a deny win), so a duplicate
// can never turn a block into an allow.
const (
	dedupeTTL  = 10 * time.Minute
	dedupeScan = 256 // markers examined per prune
)

// duplicate reports whether the same non-gate event already ran. The key is
// (host, session, event, prompt or turn id) plus the facts that tell two
// events of one turn apart; the marker name is its SHA-256, so the marker
// holds no path or id in clear. Any failure means "not a duplicate".
func duplicate(d Deps, p Payload) bool {
	if p.Host != HostCursor && p.Host != HostCopilot {
		return false
	}
	if d.Layout.HookDedupeDir == "" || p.SID == "" {
		return false
	}
	key := strings.Join([]string{
		string(p.Host), p.SID, string(p.Event), p.PromptID, p.TurnID,
		p.ToolName, p.Source, p.Reason, p.Notification, p.NewCwd,
		strings.Join(p.Paths, "\x1e"), strings.Join(p.AddedDirs, "\x1e"),
	}, "\x1f")
	sum := sha256.Sum256([]byte(key))
	dir := d.Layout.HookDedupeDir // one empty file per event, named by a hash
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return false
	}
	pruneDedupe(dir)
	f, err := os.OpenFile(filepath.Join(dir, hex.EncodeToString(sum[:16])), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return true
	}
	if err == nil {
		_ = f.Close()
	}
	return false
}

// pruneDedupe removes markers older than dedupeTTL (bounded work).
func pruneDedupe(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	entries, _ := d.ReadDir(dedupeScan)
	cutoff := time.Now().Add(-dedupeTTL)
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
