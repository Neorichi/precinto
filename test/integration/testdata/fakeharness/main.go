// Command fakeharness stands in for the `claude` executable in precinto's
// integration tests (docs/TESTPLAN.md §1.7). By default it writes a
// synthetic session transcript the way Claude Code lays it out and exits
// with a chosen code. It never touches a real Claude home: without
// CLAUDE_CONFIG_DIR it refuses to run.
//
// Usage (the test names the binary `claude`):
//
//	claude [--resume SID] [-p PROMPT] [--version]
//
// With FAKE_HARNESS_RUN set it is instead a harness process that runs one
// command as its child, the way an agent's tool call runs precinto (SEC-24,
// SEC-33): `claude ARGS…` runs `$FAKE_HARNESS_RUN ARGS…` with its own
// stdio and environment and exits with the child's code.
//
// Environment:
//
//	CLAUDE_CONFIG_DIR      required by the transcript mode: the throwaway Claude config dir
//	FAKE_HARNESS_MARKER    marker text written into the transcript
//	FAKE_HARNESS_SID       session id when --resume is not given
//	FAKE_HARNESS_EXIT      exit code (default 0)
//	FAKE_HARNESS_RUN       absolute path of the command to run as a child
//	FAKE_HARNESS_STOP_SELF "1": the child gets PRECINTO_TEST_ANCESTRY_STOP set
//	                       to this process (PID:START, D64)
//	FAKE_HARNESS_HANDSHAKE "1": print "fakeharness: procid=PID:START" and
//	                       wait for one line on stdin before starting the child
//
// Lifeline: in run mode the child is ended when this process gets SIGHUP,
// SIGTERM or SIGINT (the test closing the pseudo-terminal), and both exit
// after runLimit whatever happens, so neither outlives its test.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/platform"
)

// runLimit bounds a run-mode child.
const runLimit = 3 * time.Minute

func main() {
	if exe := os.Getenv("FAKE_HARNESS_RUN"); exe != "" {
		os.Exit(runChild(exe, os.Args[1:]))
	}
	os.Exit(run(os.Args[1:]))
}

// runChild runs exe with args as this process's child (run mode).
func runChild(exe string, args []string) int {
	if !filepath.IsAbs(exe) {
		fmt.Fprintln(os.Stderr, "fakeharness: FAKE_HARNESS_RUN must be absolute")
		return 99
	}
	self := platform.Self().String()
	env := os.Environ()
	if os.Getenv("FAKE_HARNESS_STOP_SELF") == "1" {
		env = withVar(env, "PRECINTO_TEST_ANCESTRY_STOP", self)
	}
	env = withoutVar(env, "FAKE_HARNESS_RUN", "FAKE_HARNESS_STOP_SELF", "FAKE_HARNESS_HANDSHAKE")
	if os.Getenv("FAKE_HARNESS_HANDSHAKE") == "1" {
		fmt.Printf("fakeharness: procid=%s\n", self)
		if !readLine(os.Stdin) {
			return 98
		}
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "fakeharness: %v\n", err)
		return 97
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	limit := time.NewTimer(runLimit)
	defer limit.Stop()
	for {
		select {
		case err := <-done:
			if err == nil {
				return 0
			}
			if ee, ok := err.(*exec.ExitError); ok {
				if code := ee.ExitCode(); code >= 0 {
					return code
				}
				return 128 + 9
			}
			return 96
		case s := <-sigs:
			if s == syscall.SIGINT {
				continue // the terminal delivers Ctrl-C to the child as well
			}
			_ = cmd.Process.Kill() // this process's own child
		case <-limit.C:
			_ = cmd.Process.Kill()
			<-done
			return 124
		}
	}
}

// readLine reads stdin one byte at a time up to a newline, so nothing meant
// for the child is consumed.
func readLine(f *os.File) bool {
	b := make([]byte, 1)
	for {
		n, err := f.Read(b)
		if n == 1 && (b[0] == '\n' || b[0] == '\r') {
			return true
		}
		if err != nil {
			return false
		}
	}
}

func withVar(env []string, k, v string) []string {
	return append(withoutVar(env, k), k+"="+v)
}

func withoutVar(env []string, keys ...string) []string {
	out := env[:0:0]
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		drop := false
		for _, k := range keys {
			drop = drop || name == k
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return out
}

func run(args []string) int {
	sid, prompt := os.Getenv("FAKE_HARNESS_SID"), ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--version":
			fmt.Println("2.1.329 (Claude Code)")
			return 0
		case "--resume", "-r":
			if i+1 < len(args) {
				sid = args[i+1]
				i++
			}
		case "-p", "--print":
			if i+1 < len(args) {
				prompt = args[i+1]
				i++
			}
		}
	}
	cfg := os.Getenv("CLAUDE_CONFIG_DIR")
	if !filepath.IsAbs(cfg) {
		fmt.Fprintln(os.Stderr, "fakeharness: CLAUDE_CONFIG_DIR must be set to a throwaway directory")
		return 99
	}
	if sid == "" {
		sid = "00000000-0000-4000-8000-000000000001"
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 98
	}
	// Claude's project directory name: the cwd with '/' and '.' replaced
	// by '-' (precinto itself never computes it, IM12).
	slug := strings.NewReplacer("/", "-", ".", "-").Replace(cwd)
	dir := filepath.Join(cfg, "projects", slug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 97
	}
	path := filepath.Join(dir, sid+".jsonl")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return 96
	}
	enc := json.NewEncoder(f)
	marker := os.Getenv("FAKE_HARNESS_MARKER")
	parent := ""
	for i := 1; i <= 3; i++ {
		uuid := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		rec := map[string]any{
			"uuid": uuid, "parentUuid": parent, "sessionId": sid, "cwd": cwd, "type": "user",
			"message": map[string]any{"role": "user", "content": strings.TrimSpace(prompt + " " + marker)},
		}
		if parent == "" {
			rec["parentUuid"] = nil
		}
		if err := enc.Encode(rec); err != nil {
			return 95
		}
		parent = uuid
	}
	if err := f.Close(); err != nil {
		return 94
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 93
	}
	fmt.Printf("fakeharness: wrote session %s sha256=%x\n", sid, sha256.Sum256(b))
	code, _ := strconv.Atoi(os.Getenv("FAKE_HARNESS_EXIT"))
	return code
}
