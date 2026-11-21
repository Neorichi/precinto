// Command sleeper is a test helper of internal/harness/claude: a harmless
// process that the crossgroup tests build as an executable named claude, so
// the real process table matches it as a Claude process (D47) without
// copying a platform binary (macOS launch constraints kill copies of
// /bin/sleep at exec).
//
// It prints "ready" once it runs, then sleeps until its stdin reaches EOF
// (the test's lifeline: the test closes it, or the test process dies) and
// never longer than 60 s, so it cannot outlive its test.
package main

import (
	"io"
	"os"
	"time"
)

const maxLife = 60 * time.Second

func main() {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(done)
	}()
	_, _ = os.Stdout.WriteString("ready\n")
	select {
	case <-done:
	case <-time.After(maxLife):
	}
}
