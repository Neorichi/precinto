package claude

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Neorichi/precinto/internal/fsx"
)

// uuidLen is the length of the canonical 8-4-4-4-12 form.
const uuidLen = 36

// isUUID reports canonical UUID syntax (session ids are UUIDs, SPEC §11.2).
func isUUID(s string) bool {
	if len(s) != uuidLen {
		return false
	}
	for i := 0; i < uuidLen; i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// sidOf returns the session id a name carries (SPEC §7.1.1): the name is
// the sid, or starts with "<sid>." or "<sid>-".
func sidOf(name string) (string, bool) {
	if len(name) < uuidLen || !isUUID(name[:uuidLen]) {
		return "", false
	}
	if len(name) == uuidLen || name[uuidLen] == '.' || name[uuidLen] == '-' {
		return strings.ToLower(name[:uuidLen]), true
	}
	return "", false
}

// safeComponent reports whether s is one plain path component.
func safeComponent(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 255 || strings.ContainsAny(s, "/\\") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// sameName compares path components the way the file system does: case
// insensitively on darwin (APFS default), exactly elsewhere.
func sameName(a, b string) bool {
	if runtime.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// cleanRel validates a base-relative path from a manifest: local, clean,
// '/'-separated, without empty components (SPEC §5 rule 4).
func cleanRel(rel string) ([]string, bool) {
	if rel == "" || strings.Contains(rel, "\\") || strings.Contains(rel, "\x00") || !filepath.IsLocal(rel) || filepath.Clean(rel) != rel {
		return nil, false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		if !safeComponent(p) {
			return nil, false
		}
	}
	return parts, true
}

// homeID is the stable short id of a home: the first 16 hex digits of the
// SHA-256 of its realpath (SPEC §6.2).
func homeID(realpath string) string {
	sum := sha256.Sum256([]byte(realpath))
	return hex.EncodeToString(sum[:])[:16]
}

// realpath resolves symlinks of an existing absolute path once; a missing
// path is returned cleaned.
func realpath(p string) string {
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// isDir reports whether p is a directory (not a symlink to one).
func isDir(p string) bool {
	st, err := fsx.Lstat(p)
	return err == nil && st.IsDir()
}

func notExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// mdExt reports whether p has a Markdown extension (SPEC §8.1).
func mdExt(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".md", ".mdx", ".markdown":
		return true
	}
	return false
}

// appendUnique appends v to list unless present.
func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
