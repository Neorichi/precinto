package codex

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/precinto/precinto/internal/fsx"
)

// apply_patch headers that name a file the patch writes (HA25).
var patchHeaders = []string{"*** Add File:", "*** Update File:", "*** Move to:"}

// applyPatchPaths implements ApplyPatchPaths: header paths in patch order,
// deduplicated, relative ones resolved against cwd. Without an absolute
// cwd only absolute paths are returned.
func applyPatchPaths(patch []byte, cwd string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range bytes.Split(patch, []byte("\n")) {
		l := strings.TrimRight(string(line), "\r")
		for _, h := range patchHeaders {
			rest, ok := strings.CutPrefix(l, h)
			if !ok {
				continue
			}
			p := strings.TrimSpace(rest)
			if p == "" || strings.ContainsRune(p, 0) {
				break
			}
			if !filepath.IsAbs(p) {
				if !filepath.IsAbs(cwd) {
					break
				}
				p = filepath.Join(cwd, p)
			}
			p = filepath.Clean(p)
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
			break
		}
	}
	return out
}

// maxRolloutLine bounds one rollout record read for Markdown paths.
const maxRolloutLine = 64 << 20

// rolloutLine is the subset of a Codex rollout record read here.
type rolloutLine struct {
	Type    string `json:"type"`
	Payload struct {
		Type      string          `json:"type"`
		Name      string          `json:"name"`
		Input     json.RawMessage `json:"input"`
		Arguments string          `json:"arguments"`
		Cwd       string          `json:"cwd"`
	} `json:"payload"`
}

// rolloutMarkdown returns the Markdown paths apply_patch calls of a
// rollout wrote, resolved against the session cwd recorded in the rollout
// (session_meta, turn_context). Only paths are retained.
func rolloutMarkdown(ctx context.Context, path string) ([]string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := fsx.Fstat(f); err != nil || !st.IsRegular() {
		if err == nil {
			err = fsx.ErrUnsafe
		}
		return nil, err
	}
	r := bufio.NewReaderSize(f, 256<<10)
	cwd := ""
	var out []string
	seen := map[string]bool{}
	for n := 0; ; n++ {
		if n%256 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		line, err := readLine(r)
		if len(line) > 0 {
			var rec rolloutLine
			if json.Unmarshal(line, &rec) == nil {
				switch {
				case rec.Type == "session_meta" || rec.Type == "turn_context":
					if filepath.IsAbs(rec.Payload.Cwd) {
						cwd = rec.Payload.Cwd
					}
				case rec.Type == "response_item":
					for _, p := range patchOf(rec) {
						for _, md := range applyPatchPaths([]byte(p), cwd) {
							if mdExt(md) && !seen[md] {
								seen[md] = true
								out = append(out, md)
							}
						}
					}
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// readLine returns the next line (without '\n'); over-long lines are
// skipped (returned empty).
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	over := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !over {
			if len(buf)+len(chunk) > maxRolloutLine {
				over, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return bytes.TrimSuffix(buf, []byte("\n")), err
	}
}

// patchOf returns the patch texts of an apply_patch call: a custom tool
// call's input, a function call's "input"/"patch" argument, or a shell call
// whose command is ["apply_patch", patch].
func patchOf(rec rolloutLine) []string {
	p := rec.Payload
	switch {
	case p.Type == "custom_tool_call" && p.Name == "apply_patch":
		var s string
		if json.Unmarshal(p.Input, &s) == nil {
			return []string{s}
		}
	case p.Type == "function_call" && p.Name == "apply_patch":
		var args struct {
			Input string `json:"input"`
			Patch string `json:"patch"`
		}
		if json.Unmarshal([]byte(p.Arguments), &args) == nil {
			return []string{args.Input, args.Patch}
		}
	case p.Type == "function_call" && (p.Name == "shell" || p.Name == "local_shell"):
		var args struct {
			Command []string `json:"command"`
		}
		if json.Unmarshal([]byte(p.Arguments), &args) == nil && len(args.Command) >= 2 && filepath.Base(args.Command[0]) == "apply_patch" {
			return args.Command[1:]
		}
	}
	return nil
}

func mdExt(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".md", ".mdx", ".markdown":
		return true
	}
	return false
}
