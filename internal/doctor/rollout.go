package doctor

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// isRolloutName reports whether name is a Codex rollout file. Compressed
// rollouts (.jsonl.zst) are listed too: their cwd cannot be read without
// decompressing, so they count as "could not be checked" (fail closed).
func isRolloutName(name string) bool {
	return strings.HasPrefix(name, "rollout-") && (strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".jsonl.zst"))
}

// rolloutFiles lists the rollouts of a Codex home (sessions/** and
// archived_sessions/**) without following symlinks, sorted, at most
// maxDirEntries of them.
func (e *env) rolloutFiles(home string) ([]string, error) {
	var out []string
	for _, sub := range []string{"sessions", "archived_sessions"} {
		top := filepath.Join(home, sub)
		if fi, err := os.Lstat(top); err != nil || !fi.IsDir() {
			continue
		}
		err := filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p != top && errors.Is(err, fs.ErrNotExist) {
					return nil // removed meanwhile (a seal)
				}
				return err
			}
			if err := e.ctx.Err(); err != nil {
				return err
			}
			if d.Type().IsRegular() && isRolloutName(d.Name()) {
				out = append(out, p)
				if len(out) >= maxDirEntries {
					return fs.SkipAll
				}
			}
			return nil
		})
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
