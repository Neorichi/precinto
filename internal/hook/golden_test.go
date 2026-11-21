package hook_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/testkit"
)

// Golden hook tests (docs/TESTPLAN.md §6): every file
// testdata/<host>/<version>/<event>/<case>.json holds one invocation (argv,
// environment, payload, fake daemon, ledger and process table) and, under
// "want", its exact stdout, stderr, exit code and the content-free side
// effects (daemon requests, ledger events, seal requests, workers). The
// case file is its own golden: `go test ./internal/hook -run Golden
// -update` rewrites "want" from the current behaviour.

// goldenHosts are the first path components of case files.
var goldenHosts = []string{"claude-code", "codex", "cursor", "copilot", "droid", "unknown"}

type goldenCase struct {
	Comment     string            `json:"comment,omitempty"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env"`
	Stdin       json.RawMessage   `json:"stdin,omitempty"`
	StdinRaw    *string           `json:"stdin_raw,omitempty"`
	Getwd       string            `json:"getwd,omitempty"`
	Roots       []string          `json:"roots,omitempty"`      // "id=path"; default root-acme=/u/work/acme
	RootsList   []string          `json:"roots_list,omitempty"` // extra roots.list folders
	Unlock      bool              `json:"unlock_on_prompt,omitempty"`
	Ledger      []ledger.Event    `json:"ledger,omitempty"`
	LedgerHang  bool              `json:"ledger_hang,omitempty"`
	LedgerError bool              `json:"ledger_error,omitempty"`
	Procs       []procSpec        `json:"procs,omitempty"`
	SelfPID     int               `json:"self_pid,omitempty"`
	DeadlineMS  int               `json:"deadline_ms,omitempty"`
	SweepRecent bool              `json:"sweep_recent,omitempty"`
	Daemon      *daemonSpec       `json:"daemon"`
	Want        goldenWant        `json:"want"`
}

type procSpec struct {
	PID   int      `json:"pid"`
	PPID  int      `json:"ppid"`
	Start int64    `json:"start_us"`
	Exe   string   `json:"exe"`
	Argv  []string `json:"argv,omitempty"`
	TTY   string   `json:"tty,omitempty"`
}

type goldenWant struct {
	Exit   int             `json:"exit"`
	Stdout string          `json:"stdout"`
	Stderr string          `json:"stderr"`
	Calls  []call          `json:"calls,omitempty"`
	Ledger []ledger.Event  `json:"ledger,omitempty"`
	Queue  []queue.Request `json:"queue,omitempty"`
	Spawn  [][]string      `json:"spawn,omitempty"`
}

// goldenFiles lists the case files, relative to testdata.
func goldenFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, h := range goldenHosts {
		root := filepath.Join("testdata", h)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ".json") {
				rel, _ := filepath.Rel("testdata", p)
				files = append(files, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if len(files) == 0 {
		t.Fatal("no golden cases found under testdata/")
	}
	return files
}

func TestGolden(t *testing.T) {
	restore := hook.SetApplyPatchPaths(fakeApplyPatchPaths)
	defer restore()
	for _, rel := range goldenFiles(t) {
		t.Run(strings.TrimSuffix(rel, ".json"), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
			if err != nil {
				t.Fatal(err)
			}
			var c goldenCase
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&c); err != nil {
				t.Fatalf("decode case: %v", err)
			}
			c.Want = runGolden(t, c)
			got, err := json.MarshalIndent(c, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			testkit.Golden(t, rel, append(got, '\n'))
		})
	}
}

// runGolden runs one case through hook.RunWith with fakes.
func runGolden(t *testing.T, c goldenCase) goldenWant {
	t.Helper()
	cfg := config.Default()
	cfg.Policy.UnlockOnPrompt = c.Unlock
	roots := c.Roots
	if len(roots) == 0 {
		roots = []string{"root-acme=/u/work/acme"}
	}
	for _, r := range roots {
		id, p, ok := strings.Cut(r, "=")
		if !ok {
			t.Fatalf("bad root %q", r)
		}
		cfg.Roots = append(cfg.Roots, config.Root{ID: id, Path: p, MD: config.MDLedger, Harnesses: []string{"claude-code", "codex"}})
	}
	for _, p := range c.RootsList {
		cfg.Roots = append(cfg.Roots, config.Root{Path: p, MD: config.MDLedger})
	}

	short := testkit.ShortTempDir(t)
	l, err := paths.LayoutAt(short, filepath.Join(short, "run"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	if c.SweepRecent {
		// A sweep one minute before the (fake) decision time.
		at := testkit.Epoch.Add(-time.Minute)
		if err := os.WriteFile(l.SweepLast, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(l.SweepLast, at, at); err != nil {
			t.Fatal(err)
		}
	}

	procs := fakeplatform.NewProcs()
	for _, p := range c.Procs {
		procs.Add(platform.ProcInfo{
			ID:   platform.ProcID{PID: p.PID, StartUS: p.Start},
			PPID: p.PPID, Exe: p.Exe, Argv: p.Argv, TTY: p.TTY,
		})
	}
	// The ancestry walk starts at the case's own pid (9000 by default) and
	// never reaches the real process table.
	self := c.SelfPID
	if self == 0 {
		self = 9000
	}
	defer hook.SetSelfPID(self, 0)()

	led := newFakeLedger(c.Ledger)
	if c.LedgerHang {
		hang := make(chan struct{})
		t.Cleanup(func() { close(hang) })
		led.hang = hang
	}
	if c.LedgerError {
		led.getErr = errFakeLedger
	}
	rec := &recorder{}
	gates := 0
	deps := hook.Deps{
		Cfg:    cfg,
		Layout: l,
		Env:    paths.FromMap(c.Env),
		Ledger: led,
		Procs:  procs,
		Identify: func(pid int) (platform.ProcID, error) {
			info, err := procs.Lookup(pid)
			return info.ID, err
		},
		Now:        func() time.Time { return testkit.Epoch },
		Dial:       rec.dialer(c.Daemon, &gates),
		DialUnlock: rec.dialer(c.Daemon, &gates),
		Enqueue:    rec.enqueue,
		Spawn:      rec.spawn,
	}
	var stdin []byte
	switch {
	case c.StdinRaw != nil:
		stdin = []byte(*c.StdinRaw)
	default:
		stdin = c.Stdin
	}
	ts := hook.TestSystem{Deps: deps, Deadline: time.Duration(c.DeadlineMS) * time.Millisecond}
	if c.Getwd != "" {
		ts.Getwd = func() (string, error) { return c.Getwd, nil }
	}
	var stdout, stderr bytes.Buffer
	exit := hook.RunWith(c.Args, bytes.NewReader(stdin), &stdout, &stderr, paths.FromMap(c.Env), ts)
	return goldenWant{
		Exit:   exit,
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		Calls:  rec.Calls(),
		Ledger: led.Appended(),
		Queue:  rec.Queue(),
		Spawn:  rec.Spawns(),
	}
}

// TestTestdataHygiene keeps every fixture synthetic (S13).
func TestTestdataHygiene(t *testing.T) {
	testkit.Hygiene(t, "testdata")
}
