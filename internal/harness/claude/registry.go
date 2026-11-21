package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/fsx"
)

const (
	// maxRegistryBytes bounds one sessions/<pid>.json (a few hundred bytes).
	maxRegistryBytes = 64 << 10
	// maxJobBytes bounds one jobs/<id>/state.json.
	maxJobBytes = 256 << 10
	// maxWaitingFor bounds the waitingFor text kept (a short status word).
	maxWaitingFor = 64
)

// registryFile is the subset of Claude's live-session registry entry that
// precinto reads. procStart is never parsed (SPEC §9.1).
type registryFile struct {
	PID        *json.Number    `json:"pid"`
	SessionID  *string         `json:"sessionId"`
	Cwd        string          `json:"cwd"`
	StartedAt  json.RawMessage `json:"startedAt"`
	Kind       string          `json:"kind"`
	Entrypoint string          `json:"entrypoint"`
	Status     string          `json:"status"`
	WaitingFor json.RawMessage `json:"waitingFor"`
}

// readBounded reads a regular file without following a final symlink.
func readBounded(path string, max int64) ([]byte, fsx.Stat, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fsx.Stat{}, err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return nil, fsx.Stat{}, err
	}
	if !st.IsRegular() {
		return nil, st, fmt.Errorf("%w: %s is not a regular file", fsx.ErrUnsafe, filepath.Base(path))
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, st, err
	}
	if int64(len(data)) > max {
		return nil, st, fmt.Errorf("claude: %s is larger than %d bytes", filepath.Base(path), max)
	}
	return data, st, nil
}

// registryPID parses "<pid>.json"; the .key and .sock siblings never match.
func registryPID(name string) (int, bool) {
	stem, ok := strings.CutSuffix(name, ".json")
	if !ok || stem == "" || len(stem) > 10 {
		return 0, false
	}
	for _, c := range stem {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	pid, err := strconv.Atoi(stem)
	if err != nil || pid <= 0 || strconv.Itoa(pid) != stem {
		return 0, false
	}
	return pid, true
}

// readRegistry implements ReadRegistry: every sessions/<pid>.json, sorted
// by pid. An entry that cannot be read, does not decode, names another pid
// or lacks a session id is returned with Valid=false (its pid's sessions
// are live, R8, D18). A missing directory has no entries; an unreadable
// one is an error.
func readRegistry(configDir string) ([]RegistryEntry, error) {
	if !filepath.IsAbs(configDir) {
		return nil, fmt.Errorf("claude: config dir %q is not absolute", configDir)
	}
	dir := filepath.Join(filepath.Clean(configDir), "sessions")
	des, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []RegistryEntry
	for _, de := range des {
		pid, ok := registryPID(de.Name())
		if !ok {
			continue
		}
		out = append(out, readRegistryEntry(filepath.Join(dir, de.Name()), pid))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

func readRegistryEntry(path string, pid int) RegistryEntry {
	e := RegistryEntry{Path: path, PID: pid}
	data, st, err := readBounded(path, maxRegistryBytes)
	if st.MtimeNS != 0 {
		e.Mtime = time.Unix(0, st.MtimeNS).UTC()
	}
	if err != nil {
		return e
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return e
	}
	var r registryFile
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if dec.Decode(&r) != nil || dec.More() {
		return e
	}
	if r.PID != nil {
		if n, err := r.PID.Int64(); err != nil || n != int64(pid) {
			return e // names another process: unknown schema
		}
	}
	if r.SessionID == nil || *r.SessionID == "" {
		return e
	}
	e.SessionID = *r.SessionID
	e.Cwd = r.Cwd
	e.Status = r.Status
	e.Kind = r.Kind
	e.Entrypoint = r.Entrypoint
	e.StartedAt = parseStartedAt(r.StartedAt)
	e.WaitingFor = waitingText(r.WaitingFor)
	e.Valid = true
	return e
}

// parseStartedAt accepts Unix milliseconds (Claude's format) or an RFC 3339
// string; anything else is zero (LIVE-5: the liveness rule falls back to
// the file's mtime).
func parseStartedAt(raw json.RawMessage) time.Time {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return time.Time{}
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return time.Time{}
		}
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC()
		}
		return time.Time{}
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || f <= 0 || f > 1e15 {
		return time.Time{}
	}
	return time.UnixMilli(int64(f)).UTC()
}

// waitingText reduces waitingFor to a short content-free word: a JSON
// string is kept (bounded), any other non-empty value becomes "pending".
func waitingText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	switch string(raw) {
	case "", "null", `""`, "[]", "{}", "false":
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if len(s) > maxWaitingFor {
			return "pending"
		}
		return s
	}
	return "pending"
}

func (r RegistryEntry) busy() bool { return r.Status == "busy" && r.WaitingFor == "" }

// jobFile is the subset of jobs/<id>/state.json that precinto reads.
type jobFile struct {
	SessionID *string `json:"sessionId"`
	State     *string `json:"state"`
}

// stoppedStates are job states that verifiably mean "not running" (D25);
// any other state, or an unreadable record, keeps the session live.
var stoppedStates = map[string]bool{
	"stopped": true, "completed": true, "complete": true, "done": true, "finished": true,
	"failed": true, "exited": true, "killed": true, "cancelled": true, "canceled": true, "error": true,
}

func jobStopped(j Job) bool { return j.Valid && stoppedStates[strings.ToLower(j.State)] }

// readJobs implements ReadJobs: one Job per jobs/<id>/ directory, sorted
// by id. A record that is missing, unreadable or of an unknown schema is
// returned with Valid=false.
func readJobs(configDir string) ([]Job, error) {
	if !filepath.IsAbs(configDir) {
		return nil, fmt.Errorf("claude: config dir %q is not absolute", configDir)
	}
	dir := filepath.Join(filepath.Clean(configDir), "jobs")
	des, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Job
	for _, de := range des {
		id := de.Name()
		if !de.IsDir() || !safeComponent(id) {
			if de.Type()&fs.ModeSymlink != 0 && safeComponent(id) {
				out = append(out, Job{ID: id}) // never followed: unknown
			}
			continue
		}
		out = append(out, readJob(filepath.Join(dir, id, "state.json"), id))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func readJob(path, id string) Job {
	j := Job{ID: id}
	data, _, err := readBounded(path, maxJobBytes)
	if err != nil {
		return j
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return j
	}
	var f jobFile
	if json.Unmarshal(trimmed, &f) != nil || f.SessionID == nil || *f.SessionID == "" || f.State == nil || *f.State == "" {
		return j
	}
	j.SessionID, j.State, j.Valid = *f.SessionID, *f.State, true
	return j
}
