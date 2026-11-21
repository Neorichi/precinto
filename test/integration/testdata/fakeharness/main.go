// Command fakeharness stands in for the `claude` executable in precinto's
// integration tests (docs/TESTPLAN.md §1.7): it writes a synthetic session
// transcript the way Claude Code lays it out and exits with a chosen code.
// It never touches a real Claude home: without CLAUDE_CONFIG_DIR it refuses
// to run.
//
// Usage (the test names the binary `claude`):
//
//	claude [--resume SID] [-p PROMPT] [--version]
//
// Environment:
//
//	CLAUDE_CONFIG_DIR      required: the throwaway Claude config dir
//	FAKE_HARNESS_MARKER    marker text written into the transcript
//	FAKE_HARNESS_SID       session id when --resume is not given
//	FAKE_HARNESS_EXIT      exit code (default 0)
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:]))
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
