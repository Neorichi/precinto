package doctor

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"time"
)

// The one program doctor runs itself: `$SHELL -lc true`, which HOOKS-IO
// §3.1 prescribes to detect login-profile noise (it runs the user's
// profile, as Codex does before every hook). It gets an explicit
// environment (D6), no stdin and a deadline; nothing it prints is kept
// beyond a byte count. Time Machine is queried read-only through
// platform.BackupExcluded.

// countingWriter counts the bytes written to it and keeps none.
type countingWriter struct{ n int }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += len(p)
	return len(p), nil
}

// runLoginShell runs `shell -lc true` in dir with env and returns how many
// bytes it printed on stdout and how long it took.
func runLoginShell(ctx context.Context, shell string, env []string, dir string) (int, time.Duration, error) {
	if !filepath.IsAbs(shell) {
		return 0, 0, errors.New("doctor: SHELL is not an absolute path")
	}
	cmd := exec.CommandContext(ctx, shell, "-lc", "true")
	cmd.Env = env
	cmd.Dir = dir
	cmd.Stdin = nil // /dev/null
	out := &countingWriter{}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	start := time.Now()
	err := cmd.Run()
	return out.n, time.Since(start), err
}
