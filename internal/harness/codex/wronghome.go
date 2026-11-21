package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
)

// maxMetaLine bounds what is read of a rollout: the first line only, at
// most 64 KiB (SPEC §7.2).
const maxMetaLine = 64 << 10

// wrongHomeRollouts counts, per protected root, the rollouts in the user's
// own Codex home whose session_meta cwd lies inside that root: sessions
// started without the wrapper, written outside the sealed per-root home and
// never sealed (codex-wrong-home, C9.codexoutside, D31). It reads only the
// cwd field of each rollout's first line, bounded to 64 KiB, never content.
// Compressed rollouts (.jsonl.zst) cannot be read that way and are counted
// under the empty root id ("unknown folder").
func wrongHomeRollouts(ctx context.Context, userHome string, c config.Config) (map[string]int, error) {
	if !filepath.IsAbs(userHome) {
		return nil, errors.New("codex: user home is not absolute")
	}
	out := map[string]int{}
	for _, sub := range []string{"sessions", "archived_sessions"} {
		root := filepath.Join(filepath.Clean(userHome), sub)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == root && errors.Is(err, fs.ErrNotExist) {
					return fs.SkipDir
				}
				return err
			}
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			name := d.Name()
			if !d.Type().IsRegular() || !strings.HasPrefix(name, "rollout-") {
				return nil
			}
			switch {
			case strings.HasSuffix(name, ".jsonl"):
				cwd, ok := sessionMetaCwd(p)
				if !ok {
					return nil
				}
				if r, inRoot := c.RootFor(cwd); inRoot {
					out[r.ID]++
				}
			case strings.HasSuffix(name, ".jsonl.zst"):
				out[""]++
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.SkipDir) {
			return nil, err
		}
	}
	return out, nil
}

// sessionMetaCwd reads the first line of a rollout (≤ 64 KiB) and returns
// the cwd of its session_meta payload.
func sessionMetaCwd(path string) (string, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", false
	}
	defer f.Close()
	if st, err := fsx.Fstat(f); err != nil || !st.IsRegular() {
		return "", false
	}
	buf := make([]byte, maxMetaLine)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", false
	}
	line := buf[:n]
	i := bytes.IndexByte(line, '\n')
	if i < 0 {
		if n == maxMetaLine {
			return "", false // the first line is longer than the bound
		}
	} else {
		line = line[:i]
	}
	var rec struct {
		Type    string `json:"type"`
		Payload struct {
			Cwd string `json:"cwd"`
		} `json:"payload"`
	}
	if json.Unmarshal(line, &rec) != nil || rec.Type != "session_meta" || !filepath.IsAbs(rec.Payload.Cwd) {
		return "", false
	}
	return filepath.Clean(rec.Payload.Cwd), true
}
