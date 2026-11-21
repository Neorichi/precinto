package doctor_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault"
)

// now is the fake wall time of every Run (testkit.Epoch plus a day, so
// files dated relative to it are in the past of the real clock too).
var now = testkit.Epoch.Add(24 * time.Hour)

// fixture is one fake HOME with the options and dependencies of a Run.
type fixture struct {
	t       *testing.T
	h       *testkit.Home
	o       doctor.Options
	d       *doctor.Deps
	secrets []string // strings that must never appear in a finding
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	h := testkit.NewHome(t)
	f := &fixture{t: t, h: h}
	f.o = doctor.Options{Cfg: h.Cfg, Layout: h.Layout, Env: h.Env, Procs: h.Procs}
	f.d = safeDeps(now)
	return f
}

// secret registers a string that no finding may contain (values of
// settings, prompts, markers).
func (f *fixture) secret(s ...string) { f.secrets = append(f.secrets, s...) }

// setEnv adds variables to the environment doctor sees.
func (f *fixture) setEnv(kv ...string) {
	for i := 0; i+1 < len(kv); i += 2 {
		f.o.Env = f.o.Env.With(kv[i], kv[i+1])
	}
}

// run runs doctor and checks the invariants every finding must keep.
func (f *fixture) run() []doctor.Finding {
	f.t.Helper()
	fs, err := doctor.RunWith(context.Background(), f.o, f.d)
	if err != nil {
		f.t.Fatalf("Run: %v", err)
	}
	checkInvariants(f.t, fs, f.secrets)
	return fs
}

var (
	forbiddenWord = regexp.MustCompile(`\b(root|grant|soft|hard)\b`)
	controlChar   = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	// pathToken is a path in a message: its components are names, not
	// words of the text (a folder id such as root-acme).
	pathToken = regexp.MustCompile(`(?:~|/)[^\s,()]*`)
)

// checkInvariants: codes from the vocabulary, known severities, one-line
// content-free texts in the catalog's words, no internal errors.
func checkInvariants(t *testing.T, fs []doctor.Finding, secrets []string) {
	t.Helper()
	codes := doctor.Codes()
	for _, f := range fs {
		if !slices.Contains(codes, f.Code) {
			t.Errorf("finding with unknown code %q: %+v", f.Code, f)
		}
		switch f.Severity {
		case doctor.OK, doctor.Info, doctor.Warn, doctor.Fail:
		default:
			t.Errorf("finding with unknown severity %q: %+v", f.Severity, f)
		}
		if f.Message == "" {
			t.Errorf("finding without a message: %+v", f)
		}
		if f.Message == doctor.InternalErrorText {
			t.Errorf("check %s panicked (a dependency without a fake?)", f.Code)
		}
		for _, s := range []string{f.Message, f.Fix} {
			if controlChar.MatchString(s) {
				t.Errorf("%s: control character or line break in %q", f.Code, s)
			}
			words := pathToken.ReplaceAllString(strings.ReplaceAll(s, "--root", ""), "PATH")
			if w := forbiddenWord.FindString(words); w != "" {
				t.Errorf("%s: forbidden user-facing word %q in %q", f.Code, w, s)
			}
			for _, sec := range secrets {
				if sec != "" && strings.Contains(s, sec) {
					t.Errorf("%s: finding text leaks %q: %q", f.Code, sec, s)
				}
			}
		}
	}
	// "ok" never sits next to a problem of the same code.
	bad := map[string]bool{}
	for _, f := range fs {
		if f.Severity != doctor.OK {
			bad[f.Code] = true
		}
	}
	for _, f := range fs {
		if f.Severity == doctor.OK && bad[f.Code] {
			t.Errorf("%s: ok finding next to a problem", f.Code)
		}
	}
	// Findings come in Codes order.
	rank := map[string]int{}
	for i, c := range codes {
		rank[c] = i
	}
	for i := 1; i < len(fs); i++ {
		if rank[fs[i-1].Code] > rank[fs[i].Code] {
			t.Errorf("findings out of order: %s before %s", fs[i-1].Code, fs[i].Code)
		}
	}
}

// of returns the findings of one code.
func of(fs []doctor.Finding, code string) []doctor.Finding {
	var out []doctor.Finding
	for _, f := range fs {
		if f.Code == code {
			out = append(out, f)
		}
	}
	return out
}

// want requires a finding of code and severity whose message contains
// every part, and returns it.
func want(t *testing.T, fs []doctor.Finding, code string, sev doctor.Severity, parts ...string) doctor.Finding {
	t.Helper()
	for _, f := range of(fs, code) {
		if f.Severity != sev {
			continue
		}
		okAll := true
		for _, p := range parts {
			if !strings.Contains(f.Message, p) {
				okAll = false
				break
			}
		}
		if okAll {
			return f
		}
	}
	t.Fatalf("no %s finding of %s containing %q; got:\n%s", sev, code, parts, dump(of(fs, code)))
	return doctor.Finding{}
}

// none requires that code has no finding of the given severities (any
// severity when none is given).
func none(t *testing.T, fs []doctor.Finding, code string, sevs ...doctor.Severity) {
	t.Helper()
	for _, f := range of(fs, code) {
		if len(sevs) == 0 || slices.Contains(sevs, f.Severity) {
			t.Errorf("unexpected %s finding of %s: %q", f.Severity, code, f.Message)
		}
	}
}

func dump(fs []doctor.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString("  " + string(f.Severity) + " " + f.Code + ": " + f.Message + "\n")
	}
	if b.Len() == 0 {
		return "  (none)\n"
	}
	return b.String()
}

// safeDeps are dependencies that find nothing wrong and touch nothing: no
// I/O beyond the files a test writes, no OS tool, no daemon. Tests replace
// the fields they exercise.
func safeDeps(at time.Time) *doctor.Deps {
	return &doctor.Deps{
		Now:              func() time.Time { return at },
		GOOS:             runtime.GOOS,
		EUID:             os.Geteuid(),
		DiskEncryption:   func(context.Context) (bool, bool, error) { return true, true, nil },
		CloudSynced:      func(string) bool { return false },
		SpotlightIndexed: func(context.Context, string) (bool, bool, error) { return false, true, nil },
		BackupExcluded:   func(context.Context, string) (bool, bool, error) { return true, true, nil },
		Executable:       func() (string, error) { return "", errors.New("no executable in unit tests") },
		RunShell: func(context.Context, string, []string, string) (int, time.Duration, error) {
			return 0, 10 * time.Millisecond, nil
		},
		DaemonStatus:     func(context.Context) (ipc.StatusResp, error) { return ipc.StatusResp{}, ipc.ErrNoDaemon },
		VaultInitialized: func() (bool, error) { return true, nil },
		OpenVault: func(id string) (*vault.Vault, error) {
			return &vault.Vault{Meta: vault.Meta{ID: id, RecoveryVerifiedAt: at.Add(-time.Hour),
				Factors: []vault.Factor{{Name: "se", Kind: vault.FactorSE}}}}, nil
		},
		VaultRecipients:  func(string) (string, error) { return "fpr-good", nil },
		CapsuleHeaderSHA: func(string) (string, error) { return "", errors.New("no capsule reader in unit tests") },
		CapsuleLog:       func() ([]capslog.Entry, error) { return nil, nil },
		JournalPending:   func() ([]*journal.Record, error) { return nil, nil },
		QueueList:        func() ([]queue.Request, error) { return nil, nil },
		Plaintext:        func(context.Context) ([]sweep.Plaintext, error) { return nil, nil },
		Units:            func(context.Context, bool) ([]sweep.UnitInfo, error) { return nil, nil },
		Receipt:          func(string) (sweep.Receipt, bool, error) { return sweep.Receipt{}, false, nil },
		Inventory: func(string) (harness.Inventory, error) {
			return harness.Inventory{}, errors.New("no inventories in unit tests")
		},
		HistoryLine:        fakeHistoryLine,
		ClaudeSettingsJSON: func(config.Policy) string { return claudeSettingsJSON },
		CleanupPeriodDays:  func(string) (int, error) { return 30, nil },
		CodexUserHome:      fakeCodexUserHome,
		CodexHooksTrusted:  func(string) (bool, bool, error) { return true, true, nil },
		CodexClassify:      fakeCodexClassify,
		Sessions:           func(harness.ID) ([]ledger.Session, error) { return nil, nil },
		LeaseHeld:          func(string) (bool, error) { return false, nil },
	}
}

// claudeSettingsJSON is what protect --claude-settings writes (SPEC §7.1.5).
const claudeSettingsJSON = `{"idleCompaction":false,"awaySummaryEnabled":false,"precomputeCompactionEnabled":false}`

// fakeHistoryLine mirrors claude.ParseHistoryLine on the fields doctor uses.
func fakeHistoryLine(b []byte) claude.HistoryLine {
	var l struct {
		Project   string `json:"project"`
		SessionID string `json:"sessionId"`
	}
	if json.Unmarshal(b, &l) != nil {
		return claude.HistoryLine{}
	}
	return claude.HistoryLine{Project: l.Project, SessionID: l.SessionID, Valid: true}
}

// fakeCodexUserHome mirrors codex.UserHome: CODEX_HOME, else ~/.codex.
func fakeCodexUserHome(e paths.Env) (string, error) {
	if h := e.Get("CODEX_HOME"); filepath.IsAbs(h) {
		return filepath.Clean(h), nil
	}
	home, err := paths.UserHome(e)
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".codex"), nil
}

// fakeCodexClassify mirrors the never-touch list of SPEC §7.2.
func fakeCodexClassify(rel string) codex.Class {
	top, _, _ := strings.Cut(rel, "/")
	switch {
	case strings.HasSuffix(rel, "-shm"):
		return codex.ClassSHM
	case strings.HasSuffix(rel, "-wal"), strings.HasSuffix(rel, "-journal"):
		return codex.ClassSQLiteSide
	case strings.HasSuffix(rel, ".sqlite"):
		return codex.ClassSQLiteMain
	}
	switch top {
	case "auth.json", "config.toml", "hooks.json", "plugins", "skills", "cache", "packages", "models_cache.json",
		"installation_id", "version.json", ".tmp", "tmp", "thread-writer-locks", "app-server-control", "log", "rollout-maintenance.lock":
		return codex.ClassNeverTouch
	}
	return codex.ClassContent
}

// writeFile writes data (creating parents 0700) and returns path.
func writeFile(t *testing.T, path string, data string, perm os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeJSON writes v as JSON.
func writeJSON(t *testing.T, path string, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, path, string(b), 0o600)
}

// mkdir creates dir (and parents) with perm.
func mkdir(t *testing.T, dir string, perm os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, perm); err != nil {
		t.Fatal(err)
	}
	return dir
}

// setMtime dates path relative to the fake now.
func setMtime(t *testing.T, path string, age time.Duration) {
	t.Helper()
	at := now.Add(-age)
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

// installClaudePlugin writes what `claude plugin install` leaves for
// precinto's plugin in the fake config dir: the installed-plugins list and
// enabledPlugins in the user settings.
func (f *fixture) installClaudePlugin() {
	f.t.Helper()
	cc := f.h.ClaudeConfig
	writeJSON(f.t, filepath.Join(cc, "plugins", "installed_plugins.json"), map[string]any{
		"version": 2,
		"plugins": map[string]any{"precinto@precinto": []any{map[string]any{"scope": "user", "version": "0.2.0"}}},
	})
	writeJSON(f.t, filepath.Join(cc, "settings.json"), map[string]any{"enabledPlugins": map[string]bool{"precinto@precinto": true}})
}

// tilde renders a path of the fixture's HOME as findings show it.
func (f *fixture) tilde(p string) string { return paths.Tilde(f.h.HomeDir, p) }
