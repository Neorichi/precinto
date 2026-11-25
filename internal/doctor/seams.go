package doctor

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/harness/generic"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/vault"
	"github.com/precinto/precinto/inventories"
)

// deps are doctor's inputs that come from other packages or from the OS.
// Run uses the real implementations (defaultDeps); the tests substitute
// fakes through export_test.go, so every check runs without the daemon,
// without real harness data and without running OS tools. Each one is a
// read: none of them may write, signal or unlock (the package's static
// test enforces that for doctor's own code).
//
// Field names are exported only so that the external tests can fill the
// struct (export_test.go aliases it); the type itself is unexported.
type deps struct {
	Now  func() time.Time
	GOOS string
	EUID int

	// OS facilities (internal/platform).
	DiskEncryption   func(ctx context.Context) (on, known bool, err error)
	CloudSynced      func(path string) bool
	SpotlightIndexed func(ctx context.Context, path string) (indexed, known bool, err error)
	// BackupExcluded reports whether Time Machine leaves path out of its
	// backups (platform.BackupExcluded: known=false with a nil error when
	// no backup destination is configured).
	BackupExcluded func(ctx context.Context, path string) (excluded, known bool, err error)
	// VolumeRoot returns the mount point of the file system holding path,
	// as fsx chooses <volume>/.precinto-staging ("" when unknown).
	VolumeRoot func(path string) string
	// WSL is what precinto knows of the WSL instance it runs in (zero
	// outside WSL), and CheckDrive refuses a location on a Windows drive
	// under WSL (paths.DetectWSL, paths.CheckDrive; D155, D156).
	WSL        func() paths.WSL
	CheckDrive func(p string) error
	// CheckProgram refuses, under WSL, a harness executable that would
	// run as a Windows program (harness.CheckProgram; D156): doctor finds
	// harnesses through PATH, to which WSL appends the Windows PATH.
	CheckProgram func(e paths.Env, h harness.ID, exe string) error
	Executable   func() (string, error)
	// SystemBins are directories searched for harness executables after
	// PATH and the per-user install locations.
	SystemBins []string
	// RunShell runs `shell -lc true` with env and returns how many bytes it
	// printed on stdout (HA6; the bytes themselves are never kept) and how
	// long it took.
	RunShell func(ctx context.Context, shell string, env []string, dir string) (printed int, took time.Duration, err error)

	// The daemon (internal/ipc): its status, never an autostart.
	DaemonStatus func(ctx context.Context) (ipc.StatusResp, error)

	// Vaults (internal/vault, internal/capsule).
	VaultInitialized func() (bool, error)
	OpenVault        func(id string) (*vault.Vault, error)
	// VaultRecipients returns the recipients fingerprint of a vault, or
	// vault.ErrRecipientsChanged when vault.toml differs from its verified
	// copy (the tripwire, D5).
	VaultRecipients func(id string) (fpr string, err error)
	// CapsuleHeaderSHA returns the SHA-256 of the age header of the
	// capsule file at path (the provenance key, D8).
	CapsuleHeaderSHA func(path string) (string, error)

	// Orchestration state (internal/sweep and below).
	CapsuleLog     func() ([]capslog.Entry, error)
	JournalPending func() ([]*journal.Record, error)
	QueueList      func() ([]queue.Request, error)
	Plaintext      func(ctx context.Context) ([]sweep.Plaintext, error)
	Units          func(ctx context.Context, conflicts bool) ([]sweep.UnitInfo, error)
	Receipt        func(unit string) (sweep.Receipt, bool, error)

	// Harness adapters (internal/harness and its adapters, internal/ledger,
	// internal/live).
	Inventory          func(id string) (harness.Inventory, error)
	HistoryLine        func(line []byte) claude.HistoryLine
	ClaudeSettingsJSON func(config.Policy) string
	CleanupPeriodDays  func(configDir string) (int, error)
	CodexUserHome      func(paths.Env) (string, error)
	CodexHooksTrusted  func(home string) (trusted, known bool, err error)
	CodexClassify      func(rel string) codex.Class
	Sessions           func(h harness.ID) ([]ledger.Session, error)
	LeaseHeld          func(key string) (bool, error)
}

// daemonTimeout bounds the status query: the agent answers from memory.
const daemonTimeout = 2 * time.Second

// defaultDeps wires the real implementations for o. Nothing is opened or
// computed here: every input is read when a check first asks for it.
func defaultDeps(o Options) *deps {
	l := o.Layout
	store := func() *vault.Store { return vault.OpenStore(l.VaultsDir, l.VerifiedDir, l.FactorsDir) }
	status := onceStatus(func(ctx context.Context) (ipc.StatusResp, error) { return dialStatus(ctx, l) })
	se := &sweepEnvOnce{o: o, status: status}
	return &deps{
		Now:  time.Now,
		GOOS: runtime.GOOS,
		EUID: os.Geteuid(),

		DiskEncryption:   platform.DiskEncryption,
		CloudSynced:      platform.CloudSynced,
		SpotlightIndexed: platform.SpotlightIndexed,
		BackupExcluded:   platform.BackupExcluded,
		VolumeRoot:       volumeRoot,
		WSL:              paths.DetectWSL,
		CheckDrive:       paths.CheckDrive,
		CheckProgram:     harness.CheckProgram,
		Executable:       os.Executable,
		SystemBins:       []string{"/opt/homebrew/bin", "/usr/local/bin"},
		RunShell:         runLoginShell,

		DaemonStatus: status,

		VaultInitialized: func() (bool, error) { return store().Initialized() },
		OpenVault:        func(id string) (*vault.Vault, error) { return store().Open(id) },
		VaultRecipients: func(id string) (string, error) {
			_, fpr, err := store().Recipients(id)
			return fpr, err
		},
		CapsuleHeaderSHA: capsuleHeaderSHA,

		CapsuleLog:     func() ([]capslog.Entry, error) { return capslog.Open(l.CapsuleLog).All() },
		JournalPending: func() ([]*journal.Record, error) { return journal.Open(l.JournalDir).Pending() },
		QueueList:      func() ([]queue.Request, error) { return queue.List(l.QueueDir) },
		Plaintext: func(ctx context.Context) ([]sweep.Plaintext, error) {
			e, err := se.get()
			if err != nil {
				return nil, err
			}
			return sweep.PlaintextSummary(ctx, e)
		},
		Units: func(ctx context.Context, conflicts bool) ([]sweep.UnitInfo, error) {
			e, err := se.get()
			if err != nil {
				return nil, err
			}
			return sweep.List(ctx, e, sweep.ListOptions{Conflicts: conflicts})
		},
		Receipt: func(unit string) (sweep.Receipt, bool, error) {
			e, err := se.get()
			if err != nil {
				return sweep.Receipt{}, false, err
			}
			return sweep.LoadReceipt(e, unit)
		},

		Inventory:          func(id string) (harness.Inventory, error) { return harness.LoadInventory(inventories.FS, id) },
		HistoryLine:        claude.ParseHistoryLine,
		ClaudeSettingsJSON: claude.SettingsJSON,
		CleanupPeriodDays:  claude.CleanupPeriodDays,
		CodexUserHome:      codex.UserHome,
		CodexHooksTrusted:  codex.HooksTrusted,
		CodexClassify:      codex.Classify,
		Sessions:           func(h harness.ID) ([]ledger.Session, error) { return ledger.Open(l.SessionsDir).List(string(h)) },
		LeaseHeld: func(key string) (bool, error) {
			held, _, err := live.Probe(l.LeasesDir, key)
			return held, err
		},
	}
}

// onceStatus memoizes one status query, so the checks and the sweep
// environment (whose Grants come from it) ask the agent once.
func onceStatus(fetch func(context.Context) (ipc.StatusResp, error)) func(context.Context) (ipc.StatusResp, error) {
	var (
		once sync.Once
		st   ipc.StatusResp
		err  error
	)
	return func(ctx context.Context) (ipc.StatusResp, error) {
		once.Do(func() { st, err = fetch(ctx) })
		return st, err
	}
}

// dialStatus asks a running agent for its status. It never starts one
// (Autostart stays off: doctor changes nothing) and gives up quickly.
func dialStatus(ctx context.Context, l paths.Layout) (ipc.StatusResp, error) {
	ctx, cancel := context.WithTimeout(ctx, daemonTimeout)
	defer cancel()
	c, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l, Client: "cli", Timeout: daemonTimeout})
	if err != nil {
		return ipc.StatusResp{}, err
	}
	defer c.Close()
	return c.Status(ctx)
}

// capsuleHeaderSHA reads the header hash of one capsule file with the
// no-follow directory handle of internal/fsx.
func capsuleHeaderSHA(path string) (string, error) {
	dir, err := fsx.OpenBase(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	defer dir.Close()
	_, sum, err := capsule.ReadHeader(dir, filepath.Base(path))
	return sum, err
}

// sweepEnvOnce builds, once, the sweep.Env that PlaintextSummary, List and
// LoadReceipt need: the same adapters, ledger, liveness engine and stores a
// sweep uses, with Grants from the agent's status (no agent: every folder
// counts as locked, R4). It reads state/name.salt without creating it
// (capsule.ReadSalt). When the salt does not exist yet a random one stands
// in: the adapters refuse an empty salt, and since nothing was ever sealed
// or leased (both create the salt first), no receipt, lease or log entry can
// match any key.
type sweepEnvOnce struct {
	o      Options
	status func(context.Context) (ipc.StatusResp, error)
	once   sync.Once
	e      sweep.Env
	err    error
}

func (s *sweepEnvOnce) get() (sweep.Env, error) {
	s.once.Do(func() { s.e, s.err = buildSweepEnv(s.o, s.status) })
	return s.e, s.err
}

func buildSweepEnv(o Options, status func(context.Context) (ipc.StatusResp, error)) (sweep.Env, error) {
	l := o.Layout
	if o.Procs == nil {
		return sweep.Env{}, errors.New("doctor: no process table")
	}
	salt, ok, err := capsule.ReadSalt(l.NameSalt)
	if err != nil {
		return sweep.Env{}, err
	}
	if !ok {
		salt = make([]byte, saltSize)
		_, _ = rand.Read(salt) // never fails (Go ≥ 1.24)
	}
	clock := platform.SystemClock()
	led := ledger.Open(l.SessionsDir)
	eng := &live.Engine{
		Procs:     o.Procs,
		Clock:     clock,
		LeasesDir: l.LeasesDir,
		Observer:  live.NewObserver(clock),
		Quiet:     o.Cfg.Policy.QuietWindow.D(),
		HoldCap:   o.Cfg.Policy.HoldCap.D(),
	}
	henv := harness.Env{
		Cfg:    o.Cfg,
		Layout: l,
		Ledger: led,
		Index:  func(h string) *ledger.Index { return ledger.OpenIndex(l.ProjectsDir, h) },
		Live:   eng,
		Procs:  o.Procs,
		Clock:  clock,
		Salt:   salt,
		Host:   o.Env,
	}
	adapters := []harness.Adapter{claude.New(), codex.New()}
	extra, err := generic.Adapters(inventories.FS, false)
	if err != nil {
		return sweep.Env{}, err
	}
	adapters = append(adapters, extra...)
	return sweep.Env{
		Cfg:      o.Cfg,
		Harness:  henv,
		Adapters: adapters,
		Vaults:   vault.OpenStore(l.VaultsDir, l.VerifiedDir, l.FactorsDir),
		Log:      capslog.Open(l.CapsuleLog),
		Journal:  journal.Open(l.JournalDir),
		Live:     eng,
		Procs:    o.Procs,
		Clock:    clock,
		Grants:   grantsFrom(status),
		Floor:    o.Cfg.Policy.Floor(), // policy.min_free (D76); doctor never writes
		Sealer:   "precinto doctor",
	}, nil
}

// grantsFrom turns the agent's vault states into sweep.Grants; an error
// (no agent) means every folder is locked.
func grantsFrom(status func(context.Context) (ipc.StatusResp, error)) sweep.Grants {
	return func(ctx context.Context) (map[string]bool, error) {
		st, err := status(ctx)
		if err != nil {
			return nil, err
		}
		return unlockedVaults(st), nil
	}
}

// unlockedVaults lists the vault ids the agent reports unlocked.
func unlockedVaults(st ipc.StatusResp) map[string]bool {
	out := map[string]bool{}
	for _, v := range st.Vaults {
		if v.State == "unlocked" {
			out[v.VaultID] = true
		}
	}
	return out
}
