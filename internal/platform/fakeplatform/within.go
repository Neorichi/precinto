package fakeplatform

import (
	"path/filepath"
	"runtime"
	"strings"
)

// within reports whether p equals root or lies below it, with exactly the
// semantics of paths.Within (this package may only import
// internal/platform, docs/API.md): cleaned absolute paths compared component
// by component, never by string prefix, with ASCII case folding on darwin;
// relative paths are never within anything.
func within(root, p string) bool {
	if !filepath.IsAbs(root) || !filepath.IsAbs(p) {
		return false
	}
	rc := components(filepath.Clean(root))
	pc := components(filepath.Clean(p))
	if len(pc) < len(rc) {
		return false
	}
	for i := range rc {
		if !sameComponent(rc[i], pc[i]) {
			return false
		}
	}
	return true
}

// withinAny reports whether p is within any of roots.
func withinAny(roots []string, p string) bool {
	for _, r := range roots {
		if within(r, p) {
			return true
		}
	}
	return false
}

func components(clean string) []string {
	if clean == "/" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(clean, "/"), "/")
}

func sameComponent(a, b string) bool {
	if runtime.GOOS != "darwin" {
		return a == b
	}
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
