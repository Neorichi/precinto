//go:build darwin

package platform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// diskEncryption reads `fdesetup status` (read-only, no privileges).
func diskEncryption(ctx context.Context) (on, known bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	out, _, err := runTool(ctx, 10*time.Second, "/usr/bin/fdesetup", "status")
	if err != nil {
		return false, false, fmt.Errorf("platform: fdesetup status: %w", err)
	}
	on, known = parseFdesetup(string(out))
	return on, known, nil
}

// excludeFromBackup adds a sticky Time Machine exclusion (tmutil
// addexclusion without -p: no root needed, the exclusion follows the item).
func excludeFromBackup(ctx context.Context, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("platform: exclude from backup: path must be absolute")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, _, err := runTool(ctx, 30*time.Second, "/usr/bin/tmutil", "addexclusion", path); err != nil {
		return fmt.Errorf("platform: tmutil addexclusion: %w", err)
	}
	return nil
}

// spotlightIndexed counts Markdown files Spotlight knows below path.
func spotlightIndexed(ctx context.Context, path string) (indexed, known bool, err error) {
	if !filepath.IsAbs(path) {
		return false, false, fmt.Errorf("platform: spotlight: path must be absolute")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	out, _, err := runTool(ctx, 30*time.Second, "/usr/bin/mdfind", "-onlyin", path, "-count", "kMDItemFSName == *.md")
	if err != nil {
		return false, false, fmt.Errorf("platform: mdfind: %w", err)
	}
	n, ok := parseCount(string(out))
	if !ok {
		return false, false, nil
	}
	return n > 0, true, nil
}

// cloudRoots lists the synced locations below home: iCloud Drive, the File
// Provider folders (Dropbox, OneDrive, Google Drive, Box…), the Desktop and
// Documents folders when iCloud "Desktop & Documents" sync shows them in
// iCloud Drive, and the classic folders in home.
func cloudRoots(home string) []string {
	mobile := filepath.Join(home, "Library", "Mobile Documents")
	out := []string{mobile, filepath.Join(home, "Library", "CloudStorage")}
	icloud := filepath.Join(mobile, "com~apple~CloudDocs")
	for _, d := range []string{"Desktop", "Documents"} {
		if st, err := os.Lstat(filepath.Join(icloud, d)); err == nil && (st.IsDir() || st.Mode()&os.ModeSymlink != 0) {
			out = append(out, filepath.Join(home, d))
		}
	}
	return append(out, homeCloudRoots(home)...)
}
