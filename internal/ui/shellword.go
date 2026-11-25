package ui

import (
	"strings"

	"github.com/Neorichi/precinto/internal/paths"
)

// ShellWord renders the path p as one shell word for a command a message
// tells the user to run (a fix, C6.none): the ~-shortened form (paths.Tilde
// of home) when it needs no quoting, else the absolute path in single
// quotes. Control characters are dropped (a folder name can carry terminal
// escapes, S17) and newlines and tabs become spaces, so the command stays
// on its line.
func ShellWord(home, p string) string {
	short := paths.Tilde(home, p)
	if shellSafe(short) {
		return short
	}
	clean := strings.NewReplacer("\n", " ", "\t", " ").Replace(string(sanitizeTerminal([]byte(p))))
	return "'" + strings.ReplaceAll(clean, "'", `'\''`) + "'"
}

// shellSafe reports whether s needs no quoting in a POSIX shell: letters,
// digits and /._-+:,@%~ only, a leading ~ only as ~ or ~/ (the home).
func shellSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.ContainsRune("/._-+:,@%~", c):
		default:
			return false
		}
	}
	return !strings.HasPrefix(s, "~") || s == "~" || strings.HasPrefix(s, "~/")
}
