package doctor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxMetaLine bounds what is read of a rollout: its first line, at most
// 64 KiB (SPEC §7.2).
const maxMetaLine = 64 << 10

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

// sessionMetaCwd reads the cwd recorded in a rollout's first line, the
// session_meta record {"type":"session_meta","payload":{"cwd":…}} (D31,
// HA1). It reads at most maxMetaLine bytes of the first line and decodes it
// token by token, keeping only the record type and the payload's cwd:
// every other value is skipped unread into anything (instructions and
// the like can be content). A line longer than the bound still yields the
// cwd when it comes before the cut, as Codex writes it.
func sessionMetaCwd(path string) (cwd string, ok bool) {
	line, _, err := readFirstLine(path, maxMetaLine)
	if err != nil || len(line) == 0 {
		return "", false
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", false
	}
	typ, haveCwd := "", false
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return "", false
		}
		key, _ := k.(string)
		switch key {
		case "type":
			if err := dec.Decode(&typ); err != nil {
				return "", false
			}
			if typ != "session_meta" {
				return "", false
			}
		case "payload":
			if t, err := dec.Token(); err != nil || t != json.Delim('{') {
				return "", false
			}
			for dec.More() {
				pk, err := dec.Token()
				if err != nil {
					return "", false
				}
				if name, _ := pk.(string); name == "cwd" && !haveCwd {
					if err := dec.Decode(&cwd); err != nil {
						return "", false
					}
					haveCwd = true
					if typ == "session_meta" {
						return absOrEmpty(cwd) // stop reading here
					}
					continue
				}
				if !skipValue(dec) {
					return "", false
				}
			}
			if _, err := dec.Token(); err != nil { // the payload's '}'
				return "", false
			}
		default:
			if !skipValue(dec) {
				return "", false
			}
		}
		if haveCwd && typ == "session_meta" {
			return absOrEmpty(cwd)
		}
	}
	return "", false
}

// absOrEmpty accepts only an absolute cwd.
func absOrEmpty(p string) (string, bool) {
	if !filepath.IsAbs(p) {
		return "", false
	}
	return p, true
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
