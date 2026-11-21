package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/vault"
)

// vaultOps is the daemon's view of internal/vault (G1): everything that
// unwraps, verifies or rewrites a vault. Tests substitute it.
type vaultOps interface {
	// unwrap performs exactly one user-presence unwrap of vault id.
	unwrap(ctx context.Context, id, factor string, u vault.UI) (*memguard.LockedBuffer, error)
	// verify checks recipient and MAC and writes the tripwire copy (D5).
	verify(id string, identity *memguard.LockedBuffer) error
	// create makes the vault of a new root and returns its identity.
	create(ctx context.Context, id, rootPath string, u vault.UI) (*memguard.LockedBuffer, error)
	// addFactor wraps identity to a new factor of vault id.
	addFactor(ctx context.Context, id string, identity *memguard.LockedBuffer, spec vault.FactorSpec, u vault.UI) error
	// repair rewrites the recipient set of vault id (D53).
	repair(id string, identity, recovery *memguard.LockedBuffer, now time.Time) (vault.RepairResult, error)
	// repairPlan computes what repair would rewrite and the recipients
	// fingerprint the vault would then have, writing nothing to the vault
	// (the vault_repair dry run, CC-32).
	repairPlan(id string, identity, recovery *memguard.LockedBuffer, now time.Time) (vault.RepairResult, string, error)
	// markAudited moves last_audit of vault id forward to at (CC-07).
	markAudited(id string, at time.Time) error
	// meta returns vault.toml of id.
	meta(id string) (vault.Meta, error)
	// fingerprint returns the recipients fingerprint of id (tripwire-checked).
	fingerprint(id string) (string, error)
}

// keyHolder is the subset of *vault.Keyring the daemon uses.
type keyHolder interface {
	Put(id string, identity *memguard.LockedBuffer) error
	Has(id string) bool
	Drop(id string)
	DropAll()
	IDs() []string
	FileKey(id string, header []byte) (*memguard.LockedBuffer, error)
	MAC(id, info string, data []byte) (string, error)
	// WithIdentityBuffer runs fn with the locked identity of id, destroyed
	// when fn returns (factor enrollment, CC-10).
	WithIdentityBuffer(id string, fn func(identity *memguard.LockedBuffer) error) error
}

// deps are the daemon's seams onto other packages and onto the system.
// newDeps fills the production implementations; tests replace fields.
type deps struct {
	vaults  vaultOps
	keyring keyHolder

	// capsule provenance (D8, D39)
	readHeader func(rel string) (header []byte, headerSHA string, err error)
	lookup     func(rel, headerSHA string) (capslog.Entry, error)
	logged     func() ([]capslog.Entry, error)
	manifest   func(rel string, fileKey []byte) (capsule.Manifest, error)
	// opens reports whether identity unwraps header (vault repair, D53).
	opens func(identity *memguard.LockedBuffer, header []byte) bool

	// harness facts (G3)
	ledgerList func(harness string) ([]ledger.Session, error)
	ledgerGet  func(harness, sid string) (ledger.Session, error)
	registry   func(configDir string) ([]claude.RegistryEntry, error)
	jobs       func(configDir string) ([]claude.Job, error)

	// processes and terminals
	signal   func(id platform.ProcID, sig syscall.Signal) error
	waitExit func(ctx context.Context, id platform.ProcID) error
	scrub    func(tty string, o platform.ScrubOptions) error
	notify   func(tty, text string) error
	peer     func(c *ipc.Conn) (platform.Peer, bool)
}

// newDeps returns the production seams. real is false when the process
// table is a fake (agenttest): then nothing touches real processes or
// terminals — signals and terminal writes are only recorded.
func newDeps(l paths.Layout, procs platform.ProcTable, clock platform.Clock, real bool, rec *recorder) deps {
	d := deps{
		vaults:     &storeOps{l: l},
		keyring:    &lazyKeyring{},
		readHeader: func(rel string) ([]byte, string, error) { return readCapsuleHeader(l.CapsulesDir, rel) },
		lookup: func(rel, sha string) (capslog.Entry, error) {
			if _, err := os.Lstat(l.CapsuleLog); err != nil {
				return capslog.Entry{}, capslog.ErrNotLogged
			}
			return capslog.Open(l.CapsuleLog).Lookup(rel, sha)
		},
		logged: func() ([]capslog.Entry, error) {
			if _, err := os.Lstat(l.CapsuleLog); errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			}
			return capslog.Open(l.CapsuleLog).All()
		},
		manifest: func(rel string, key []byte) (capsule.Manifest, error) {
			return readCapsuleManifest(l.CapsulesDir, rel, key)
		},
		opens: identityOpens,
		ledgerList: func(h string) ([]ledger.Session, error) {
			if !hasEntries(filepath.Join(l.SessionsDir, h), ".jsonl") {
				return nil, nil
			}
			return ledger.Open(l.SessionsDir).List(h)
		},
		ledgerGet: func(h, sid string) (ledger.Session, error) {
			if !validName(sid) {
				return ledger.Session{}, ledger.ErrNotFound
			}
			if _, err := os.Lstat(filepath.Join(l.SessionsDir, h, sid+".jsonl")); err != nil {
				return ledger.Session{}, ledger.ErrNotFound
			}
			return ledger.Open(l.SessionsDir).Get(h, sid)
		},
		registry: func(dir string) ([]claude.RegistryEntry, error) {
			if !hasEntries(filepath.Join(dir, "sessions"), ".json") {
				return nil, nil
			}
			return claude.ReadRegistry(dir)
		},
		jobs: func(dir string) ([]claude.Job, error) {
			if !hasEntries(filepath.Join(dir, "jobs"), "") {
				return nil, nil
			}
			return claude.ReadJobs(dir)
		},
		peer: func(c *ipc.Conn) (platform.Peer, bool) { return c.Peer(), c.PeerSameExecutable() },
	}
	if real {
		d.signal, d.waitExit, d.scrub, d.notify = platform.Signal, platform.WaitExit, platform.ScrubTTY, notifyTTY
	} else {
		d.signal = rec.signal
		d.scrub = rec.scrub
		d.notify = rec.notify
		d.waitExit = func(ctx context.Context, id platform.ProcID) error { return pollGone(ctx, procs, id) }
	}
	return d
}

// recorder keeps what a daemon on a fake process table would have done to
// real processes and terminals.
type recorder struct {
	mu       sync.Mutex
	signals  []signalled
	scrubbed []string
	notified []string
}

type signalled struct {
	ID  platform.ProcID
	Sig syscall.Signal
}

func (r *recorder) signal(id platform.ProcID, sig syscall.Signal) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signals = append(r.signals, signalled{id, sig})
	return nil
}

func (r *recorder) scrub(tty string, _ platform.ScrubOptions) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scrubbed = append(r.scrubbed, tty)
	return nil
}

func (r *recorder) notify(tty, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notified = append(r.notified, tty)
	return nil
}

func (r *recorder) snapshot() []signalled {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]signalled(nil), r.signals...)
}

// pollGone waits until id is no longer alive in procs.
func pollGone(ctx context.Context, procs platform.ProcTable, id platform.ProcID) error {
	for procs.Alive(id) {
		t := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

// hasEntries reports whether dir holds at least one entry with suffix (any
// entry when suffix is ""). It keeps the daemon from calling into readers
// when there is nothing to read.
func hasEntries(dir, suffix string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist) // unreadable: let the reader decide (and fail)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), suffix) {
			return true
		}
	}
	return false
}

// validName accepts a single path component without separators or dots.
func validName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00") && len(s) <= 255
}

// storeOps implements vaultOps over vault.Store, opened on first use.
type storeOps struct {
	l     paths.Layout
	once  sync.Once
	store *vault.Store
}

func (s *storeOps) st() *vault.Store {
	s.once.Do(func() { s.store = vault.OpenStore(s.l.VaultsDir, s.l.VerifiedDir, s.l.FactorsDir) })
	return s.store
}

// open loads a vault; a folder without vault.toml has none (checked first,
// so nothing is opened for a folder that was never protected).
func (s *storeOps) open(id string) (*vault.Vault, error) {
	if !validName(id) {
		return nil, vault.ErrNotFound
	}
	if _, err := os.Lstat(filepath.Join(s.l.VaultDir(id), "vault.toml")); err != nil {
		return nil, vault.ErrNotFound
	}
	return s.st().Open(id)
}

func (s *storeOps) unwrap(ctx context.Context, id, factor string, u vault.UI) (*memguard.LockedBuffer, error) {
	v, err := s.open(id)
	if err != nil {
		return nil, err
	}
	return v.Unwrap(ctx, factor, u)
}

func (s *storeOps) verify(id string, identity *memguard.LockedBuffer) error {
	v, err := s.open(id)
	if err != nil {
		return err
	}
	return s.st().Verify(v, identity)
}

func (s *storeOps) create(ctx context.Context, id, rootPath string, u vault.UI) (*memguard.LockedBuffer, error) {
	return s.st().Create(ctx, id, rootPath, u)
}

func (s *storeOps) addFactor(ctx context.Context, id string, identity *memguard.LockedBuffer, spec vault.FactorSpec, u vault.UI) error {
	v, err := s.open(id)
	if err != nil {
		return err
	}
	return v.AddFactor(ctx, identity, spec, u)
}

func (s *storeOps) repair(id string, identity, recovery *memguard.LockedBuffer, now time.Time) (vault.RepairResult, error) {
	v, err := s.open(id)
	if err != nil {
		return vault.RepairResult{}, err
	}
	return s.st().Repair(v, vault.RepairOptions{Identity: identity, Recovery: recovery, Now: func() time.Time { return now }})
}

// repairPlan runs Store.Repair on a scratch copy of vault id's metadata
// (vault.toml and its verified copy, public data only) in a private
// directory under the run directory, so the dry run shows exactly what the
// confirmed repair will write while the real vault stays untouched; the
// copy is removed before returning.
func (s *storeOps) repairPlan(id string, identity, recovery *memguard.LockedBuffer, now time.Time) (vault.RepairResult, string, error) {
	if !validName(id) {
		return vault.RepairResult{}, "", vault.ErrNotFound
	}
	tmp, err := os.MkdirTemp(s.l.RunDir, repairScratchPrefix)
	if err != nil {
		return vault.RepairResult{}, "", fmt.Errorf("agent: repair scratch: %w", err)
	}
	defer os.RemoveAll(tmp)
	vaults, verified := filepath.Join(tmp, "vaults"), filepath.Join(tmp, "verified")
	if err := os.MkdirAll(filepath.Join(vaults, id), 0o700); err != nil {
		return vault.RepairResult{}, "", err
	}
	if err := os.MkdirAll(verified, 0o700); err != nil {
		return vault.RepairResult{}, "", err
	}
	if err := copyPublic(filepath.Join(s.l.VaultDir(id), "vault.toml"), filepath.Join(vaults, id, "vault.toml")); err != nil {
		return vault.RepairResult{}, "", err
	}
	if err := copyPublic(filepath.Join(s.l.VerifiedDir, id+".recipients"), filepath.Join(verified, id+".recipients")); err != nil &&
		!errors.Is(err, fs.ErrNotExist) {
		return vault.RepairResult{}, "", err
	}
	st := vault.OpenStore(vaults, verified, s.l.FactorsDir)
	v, err := st.Open(id)
	if err != nil {
		return vault.RepairResult{}, "", err
	}
	res, err := st.Repair(v, vault.RepairOptions{Identity: identity, Recovery: recovery, Now: func() time.Time { return now }})
	if err != nil {
		return vault.RepairResult{}, "", err
	}
	_, fpr, err := st.Recipients(id)
	if err != nil {
		return vault.RepairResult{}, "", err
	}
	return res, fpr, nil
}

// repairScratchPrefix names the dry run's scratch directories (left-overs
// of a crash are removed at the next start).
const repairScratchPrefix = ".repair-"

// copyPublic copies a small regular file (no symlink followed, at most
// 1 MiB) with mode 0600.
func copyPublic(src, dst string) error {
	f, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return fmt.Errorf("agent: %s is not a small regular file", filepath.Base(src))
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}

func (s *storeOps) markAudited(id string, at time.Time) error {
	if _, err := s.open(id); err != nil {
		return err
	}
	return s.st().MarkAudited(id, at)
}

func (s *storeOps) meta(id string) (vault.Meta, error) {
	v, err := s.open(id)
	if err != nil {
		return vault.Meta{}, err
	}
	return v.Meta, nil
}

func (s *storeOps) fingerprint(id string) (string, error) {
	if _, err := s.open(id); err != nil {
		return "", err
	}
	_, fpr, err := s.st().Recipients(id)
	return fpr, err
}

// lazyKeyring creates the vault.Keyring at the first Put: until then no
// identity exists, so every query answers "locked" without allocating one.
type lazyKeyring struct {
	mu sync.Mutex
	k  *vault.Keyring
}

func (l *lazyKeyring) get(create bool) *vault.Keyring {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.k == nil && create {
		l.k = vault.NewKeyring()
	}
	return l.k
}

func (l *lazyKeyring) Put(id string, identity *memguard.LockedBuffer) error {
	return l.get(true).Put(id, identity)
}

func (l *lazyKeyring) Has(id string) bool {
	k := l.get(false)
	return k != nil && k.Has(id)
}

func (l *lazyKeyring) Drop(id string) {
	if k := l.get(false); k != nil {
		k.Drop(id)
	}
}

func (l *lazyKeyring) DropAll() {
	if k := l.get(false); k != nil {
		k.DropAll()
	}
}

func (l *lazyKeyring) IDs() []string {
	if k := l.get(false); k != nil {
		return k.IDs()
	}
	return nil
}

func (l *lazyKeyring) FileKey(id string, header []byte) (*memguard.LockedBuffer, error) {
	k := l.get(false)
	if k == nil {
		return nil, vault.ErrLocked
	}
	return k.FileKey(id, header)
}

func (l *lazyKeyring) MAC(id, info string, data []byte) (string, error) {
	k := l.get(false)
	if k == nil {
		return "", vault.ErrLocked
	}
	return k.MAC(id, info, data)
}

func (l *lazyKeyring) WithIdentityBuffer(id string, fn func(identity *memguard.LockedBuffer) error) error {
	k := l.get(false)
	if k == nil {
		return vault.ErrLocked
	}
	return k.WithIdentityBuffer(id, fn)
}

// identityOpens unwraps header with a copy of identity in a throwaway
// keyring (the daemon's own keyring is not touched).
func identityOpens(identity *memguard.LockedBuffer, header []byte) bool {
	k := vault.NewKeyring()
	defer k.DropAll()
	if err := k.Put("repair-check", memguard.NewBufferFromBytes(append([]byte(nil), identity.Bytes()...))); err != nil {
		return false
	}
	key, err := k.FileKey("repair-check", header)
	if err != nil {
		return false
	}
	key.Destroy()
	return true
}

// capsuleRel validates a capsule path relative to CapsulesDir:
// "<harness>/<unit-key>/g<N>.pcap" (or deeper codex blob paths), clean,
// local, with a generation file name.
func capsuleRel(rel string) (dir, name string, err error) {
	if rel == "" || !filepath.IsLocal(rel) || path.Clean(rel) != rel || strings.Contains(rel, "\\") {
		return "", "", fmt.Errorf("agent: capsule path is not a clean relative path")
	}
	dir, name = path.Split(rel)
	if dir == "" || !strings.HasSuffix(name, capsule.FileExt) || strings.Count(rel, "/") > 4 {
		return "", "", fmt.Errorf("agent: not a capsule path")
	}
	return strings.TrimSuffix(dir, "/"), name, nil
}

// readCapsuleHeader opens the capsule below capsulesDir without following
// symlinks and returns its age header and the header's SHA-256.
func readCapsuleHeader(capsulesDir, rel string) ([]byte, string, error) {
	dirRel, name, err := capsuleRel(rel)
	if err != nil {
		return nil, "", err
	}
	// Cheap existence check first; the real open below never follows a
	// symlink (fsx walks with O_NOFOLLOW).
	if st, err := os.Lstat(filepath.Join(capsulesDir, filepath.FromSlash(rel))); err != nil || !st.Mode().IsRegular() {
		return nil, "", fmt.Errorf("agent: no such capsule")
	}
	base, err := fsx.OpenBase(capsulesDir)
	if err != nil {
		return nil, "", err
	}
	defer base.Close()
	dir, err := base.OpenDir(dirRel, false)
	if err != nil {
		return nil, "", err
	}
	defer dir.Close()
	return capsule.ReadHeader(dir, name)
}

// readCapsuleManifest decrypts the manifest head of a capsule with its
// file key (SPEC §13.5 SHOULD).
func readCapsuleManifest(capsulesDir, rel string, key []byte) (capsule.Manifest, error) {
	dirRel, name, err := capsuleRel(rel)
	if err != nil {
		return capsule.Manifest{}, err
	}
	base, err := fsx.OpenBase(capsulesDir)
	if err != nil {
		return capsule.Manifest{}, err
	}
	defer base.Close()
	dir, err := base.OpenDir(dirRel, false)
	if err != nil {
		return capsule.Manifest{}, err
	}
	defer dir.Close()
	f, _, err := dir.Open(name)
	if err != nil {
		return capsule.Manifest{}, err
	}
	defer f.Close()
	return capsule.OpenManifest(f, key)
}

// notifyTTY writes an OSC 9 desktop notification (D60) to a terminal owned
// by the current user, opened write-only without becoming its controlling
// terminal.
func notifyTTY(tty, text string) error {
	if !strings.HasPrefix(tty, "/dev/") || filepath.Clean(tty) != tty {
		return fmt.Errorf("agent: not a terminal path")
	}
	f, err := os.OpenFile(tty, os.O_WRONLY|syscall.O_NOCTTY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || st.Mode()&fs.ModeCharDevice == 0 || int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("agent: terminal is not owned by the current user")
	}
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, text)
	_ = f.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = f.WriteString("\x1b]9;" + clean + "\x1b\\")
	return err
}
