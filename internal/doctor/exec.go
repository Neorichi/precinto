package doctor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/precinto/precinto/internal/paths"
)

// The two programs doctor runs. Both only read: `$SHELL -lc true` is what
// HOOKS-IO §3.1 prescribes to detect login-profile noise (it runs the
// user's profile, as Codex does before every hook), and `tmutil
// destinationinfo` / `tmutil isexcluded` query Time Machine. Every exec.Cmd
// gets an explicit environment (D6), no stdin and a deadline; nothing they
// print is kept beyond what the check needs (a byte count, a status word).

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

// tmutil is Time Machine's command-line tool (darwin).
const tmutil = "/usr/bin/tmutil"

// timeMachine answers deps.BackupExcluded with tmutil, asking once whether
// a backup destination is configured at all.
type timeMachine struct {
	env    []string
	once   sync.Once
	noDest bool
	err    error
}

func newTimeMachine(e paths.Env) *timeMachine {
	env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	if h, err := paths.UserHome(e); err == nil {
		env = append(env, "HOME="+h)
	}
	return &timeMachine{env: env}
}

// run runs tmutil with a deadline and returns at most 64 KiB of its stdout
// (status lines only: destination names and "[Excluded]"/"[Included]").
func (t *timeMachine) run(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tmutil, args...)
	cmd.Env = t.env
	var out bytes.Buffer
	cmd.Stdout = &limitedBuffer{b: &out, max: 64 << 10}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	return out.String(), err
}

// excluded reports whether Time Machine leaves path out of its backups:
// true when no backup destination is configured.
func (t *timeMachine) excluded(ctx context.Context, path string) (excluded, known bool, err error) {
	t.once.Do(func() {
		out, err := t.run(ctx, "destinationinfo")
		t.noDest = strings.Contains(out, "No destinations configured")
		if !t.noDest {
			t.err = err
		}
	})
	if t.noDest {
		return true, true, nil
	}
	if t.err != nil {
		return false, false, t.err
	}
	out, err := t.run(ctx, "isexcluded", path)
	switch {
	case strings.Contains(out, "[Excluded]"):
		return true, true, nil
	case strings.Contains(out, "[Included]"):
		return false, true, nil
	}
	return false, false, err
}

// limitedBuffer keeps the first max bytes written to it.
type limitedBuffer struct {
	b   *bytes.Buffer
	max int
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	if room := w.max - w.b.Len(); room > 0 {
		w.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
