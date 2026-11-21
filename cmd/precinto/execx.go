package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"time"
)

// maxCapture bounds the stdout an external command may return.
const maxCapture = 1 << 20

// errNoArgv is returned for an empty command line.
var errNoArgv = errors.New("no command")

// runExternal runs one external command (launchctl, a harness CLI, an age
// plugin) with an explicit environment: Env is always set, so the child
// never inherits this process's environment (D6, archtest). argv[0] must
// be absolute. Stdout is captured (bounded) unless the spec names a
// writer; stderr is discarded unless it names one.
func runExternal(ctx context.Context, c execSpec) ([]byte, error) {
	if len(c.Argv) == 0 {
		return nil, errNoArgv
	}
	if !filepath.IsAbs(c.Argv[0]) {
		return nil, errors.New("external command must be an absolute path")
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	cmd.Env = append([]string{}, c.Env...)
	cmd.Dir = c.Dir
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	cmd.Stdin = nil
	var out limitedBuffer
	out.limit = maxCapture
	if c.Stdout != nil {
		cmd.Stdout = c.Stdout
	} else {
		cmd.Stdout = &out
	}
	if c.Stderr != nil {
		cmd.Stderr = c.Stderr
	} else {
		cmd.Stderr = io.Discard
	}
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	return out.Bytes(), err
}

// limitedBuffer keeps at most limit bytes and silently drops the rest.
type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}
