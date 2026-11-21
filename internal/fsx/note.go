package fsx

import (
	"os"

	"github.com/precinto/precinto/internal/fsx/failpoint"
)

// note reports a mutating operation to failpoint observers (power-loss
// recording, internal/fsx/fsxtest). It compiles to nothing useful without
// -tags failpoints: failpoint.NoteFS returns at once.
func note(kind failpoint.FSOpKind, path, target string, done bool) {
	if !failpoint.Enabled() {
		return
	}
	failpoint.NoteFS(failpoint.FSOp{Kind: kind, Path: path, Target: target, Done: done})
}

// noteSync reports that f's data is durable.
func noteSync(f *os.File) {
	if !failpoint.Enabled() || f == nil {
		return
	}
	failpoint.NoteFS(failpoint.FSOp{Kind: failpoint.FSFsync, Path: f.Name(), Done: true, File: f})
}
