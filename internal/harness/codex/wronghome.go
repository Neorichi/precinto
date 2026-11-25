package codex

import (
	"bufio"
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

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/fsx"
)

// maxMetaLine bounds what is read of a rollout: the first line only, at
// most 64 KiB (SPEC §7.2).
const maxMetaLine = 64 << 10

// WrongHomeRollouts counts the rollouts under userHome/sessions (and
// userHome/archived_sessions) whose first line is a session_meta record
// (its `type` is checked) with payload.cwd inside a protected root of c:
// sessions started without the wrapper, written outside the sealed
// per-root home and never sealed (codex-wrong-home, C9.codexoutside, D31).
// It reads at most 64 KiB of that line and keeps only cwd, decoding token
// by token so no other value is kept; counts are per root id. Compressed
// (.jsonl.zst) or unreadable rollouts (a first line that is not JSON, or
// whose cwd lies beyond the bound) are counted under "" (could not be
// checked); a readable first line of another record type is not a
// session and is not counted. A missing home counts nothing.
func WrongHomeRollouts(ctx context.Context, userHome string, c config.Config) (map[string]int, error) {
	return wrongHomeRollouts(ctx, userHome, c)
}

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
				if p != root && errors.Is(err, fs.ErrNotExist) {
					return nil // removed meanwhile (a seal)
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
				cwd, st := sessionMetaCwd(p)
				switch st {
				case metaOK:
					if r, inRoot := c.RootFor(cwd); inRoot {
						out[r.ID]++
					}
				case metaUnreadable:
					out[""]++
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

// metaStatus is what the first line of a rollout told.
type metaStatus int

const (
	metaOK         metaStatus = iota // a session_meta record with an absolute cwd
	metaOther                        // a readable record of another type
	metaUnreadable                   // unreadable, not JSON, or no cwd within the bound
)

// sessionMetaCwd reads the first line of a rollout (≤ 64 KiB) and returns
// the cwd of its session_meta payload. It decodes token by token, keeping
// only the record type and the payload's cwd: every other value is skipped
// unread into anything (instructions and the like can be content). A line
// longer than the bound still yields the cwd when it comes before the cut,
// as Codex writes it.
func sessionMetaCwd(path string) (string, metaStatus) {
	line, err := readFirstLine(path, maxMetaLine)
	if err != nil || len(line) == 0 {
		return "", metaUnreadable
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", metaUnreadable
	}
	typ, cwd, haveCwd := "", "", false
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return "", metaUnreadable
		}
		key, _ := k.(string)
		switch key {
		case "type":
			if err := dec.Decode(&typ); err != nil {
				return "", metaUnreadable
			}
			if typ != "session_meta" {
				return "", metaOther
			}
		case "payload":
			if t, err := dec.Token(); err != nil || t != json.Delim('{') {
				return "", metaUnreadable
			}
			for dec.More() {
				pk, err := dec.Token()
				if err != nil {
					return "", metaUnreadable
				}
				if name, _ := pk.(string); name == "cwd" && !haveCwd {
					if err := dec.Decode(&cwd); err != nil {
						return "", metaUnreadable
					}
					haveCwd = true
					if typ == "session_meta" {
						return absCwd(cwd) // stop reading here
					}
					continue
				}
				if !skipValue(dec) {
					return "", metaUnreadable
				}
			}
			if _, err := dec.Token(); err != nil { // the payload's '}'
				return "", metaUnreadable
			}
		default:
			if !skipValue(dec) {
				return "", metaUnreadable
			}
		}
		if haveCwd && typ == "session_meta" {
			return absCwd(cwd)
		}
	}
	if typ == "session_meta" || typ == "" {
		return "", metaUnreadable // a session_meta (or untyped) record without a usable cwd
	}
	return "", metaOther
}

// absCwd accepts only an absolute cwd.
func absCwd(p string) (string, metaStatus) {
	if !filepath.IsAbs(p) {
		return "", metaUnreadable
	}
	return filepath.Clean(p), metaOK
}

// skipValue consumes the next JSON value of dec token by token.
func skipValue(dec *json.Decoder) bool {
	depth := 0
	for {
		t, err := dec.Token()
		if err != nil {
			return false
		}
		if d, isDelim := t.(json.Delim); isDelim {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if depth == 0 {
			return true
		}
	}
}

// readFirstLine reads the first line of the regular file path, at most max
// bytes of it (O_NOFOLLOW, never blocking on a FIFO).
func readFirstLine(path string, max int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|fsx.ONoFollow|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return nil, err
	}
	if !st.IsRegular() {
		return nil, fsx.ErrUnsafe
	}
	r := bufio.NewReaderSize(io.LimitReader(f, int64(max)), 4096)
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		switch {
		case err == nil:
			return line[:len(line)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return line, nil
		default:
			return nil, err
		}
	}
}
