package sweep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/vault"
)

// The ports below are sweep's only view of the packages it orchestrates.
// Production wires them to internal/fsx, internal/capsule, internal/live,
// internal/ledger, internal/vault and the harness helpers (prodPorts);
// in-package tests substitute fakes, so the planner, the executor and
// recovery are tested without the other groups' implementations.

// dirHandle mirrors *fsx.Dir: every operation is relative to an open
// directory, never follows symlinks, and refuses unsafe components.
type dirHandle interface {
	Path() string
	Close() error
	OpenDir(rel string, create bool) (dirHandle, error)
	Open(rel string) (*os.File, fsx.Stat, error)
	Lstat(rel string) (fsx.Stat, error)
	ReadDir(rel string) ([]fsx.Entry, error)
	Walk(rel string, fn func(fsx.WalkEntry) error) error
	CreateTemp(dirRel, pattern string) (*os.File, string, error)
	Rename(oldRel, newRel string, mode fsx.RenameMode) error
	RenameTo(oldRel string, dst dirHandle, newRel string, mode fsx.RenameMode) error
	Link(oldRel, newRel string) error
	UnlinkIfUnchanged(rel string, expect fsx.Stat) error
	Remove(rel string) error
	RemoveEmptyDirs(rel, stopAt string) error
	Chtimes(rel string, mtime time.Time) error
	Chmod(rel string, perm fs.FileMode) error
	Sync() error
	Device() (uint64, error)
}

// stagingHandle mirrors *fsx.Staging.
type stagingHandle interface {
	Dir() dirHandle
	Path() string
	ID() string
	Remove() error
}

// fileSystem is the rest of fsx that sweep uses.
type fileSystem interface {
	OpenBase(path string) (dirHandle, error)
	MkdirPrivate(path string) error
	CheckSpace(path string, need int64, floor fsx.Floor) error
	Space(path string) (avail, total uint64, err error)
	NewStaging(preferred, target, id string) (stagingHandle, error)
	OpenStaging(path string) (stagingHandle, error)
}

// recipientSet is an opaque, verified sealing recipient set (vault +
// recovery) with its fingerprint. apply installs it into a capsule seal
// request, so sweep never names the age types itself.
type recipientSet struct {
	fpr   string
	apply func(*capsule.SealRequest)
}

// vaultPort returns sealing recipients after the tripwire check (D5).
type vaultPort interface {
	recipients(vaultID string) (recipientSet, error)
}

// sealInput mirrors capsule.Input with a dirHandle.
type sealInput struct {
	Base   capsule.BaseID
	Dir    dirHandle
	Rel    string
	Path   string
	Snap   fsx.Stat
	Append bool
	Group  string
	Open   *os.File
}

// sealRequest mirrors capsule.SealRequest.
type sealRequest struct {
	Manifest   capsule.Manifest
	Inputs     []sealInput
	Dirs       []capsule.Entry
	Recipients recipientSet
	Out        dirHandle
	Name       string
	OnPhase    func(capsule.Phase, *capsule.Sealed) error
}

// extractRequest mirrors capsule.ExtractOptions with a stagingHandle.
type extractRequest struct {
	FileKey []byte
	Staging stagingHandle
	Limits  capsule.Limits
	Check   func(capsule.Entry) error
}

// codecPort is the capsule format.
type codecPort interface {
	Seal(ctx context.Context, r sealRequest) (*capsule.Sealed, error)
	ReadHeader(dir dirHandle, name string) (header []byte, headerSHA256 string, err error)
	HashFile(dir dirHandle, name string) (string, int64, error)
	OpenManifest(r io.Reader, fileKey []byte) (capsule.Manifest, error)
	Extract(ctx context.Context, r io.Reader, o extractRequest) (capsule.Manifest, []capsule.Staged, error)
}

// livePort is the liveness engine plus the lease probe.
type livePort interface {
	Decide(ctx context.Context, s live.Subject, extra []live.Evidence) (live.Verdict, error)
	StillQuiet(ctx context.Context, s live.Subject, snaps map[string]fsx.Stat) (bool, error)
}

// ledgerPort is the session ledger.
type ledgerPort interface {
	Snapshot(harness, sid string) (raw []byte, n int64, err error)
	Archive(harness, sid string, n int64) error
	List(harness string) ([]ledger.Session, error)
}

// gitPort answers "is this file git-tracked" for the Markdown policy
// (SPEC §8.2): it returns the repository-relative paths of the index of
// repo; any error means "treat everything in repo as tracked".
type gitPort interface {
	Tracked(ctx context.Context, repo string) (map[string]bool, error)
}

// busyPort reports whether any harness session working inside root is
// mid-turn (D17); an error means "busy" (never seal notes on doubt).
type busyPort interface {
	RootBusy(ctx context.Context, e Env, root string) (bool, error)
}

// ports is the set of seams of one operation.
type ports struct {
	fs     fileSystem
	codec  codecPort
	live   livePort
	ledger ledgerPort
	vaults vaultPort
	git    gitPort
	busy   busyPort

	// Harness helpers (internal/harness/claude and codex).
	scanLinks   func(ctx context.Context, r io.Reader) (claude.Links, error)
	historyLine func(b []byte) claude.HistoryLine
	codexClass  func(rel string) codex.Class

	// sleep waits d or until ctx ends (rescue grace, history tail quiet).
	sleep func(ctx context.Context, d time.Duration) error
	// rescueWait is the grace before kept descriptors are re-checked
	// (SPEC §10.3 step 7: at least 1 s).
	rescueWait time.Duration
	// tailQuiet is how long the history tail loop waits for late appends
	// (SPEC §7.1.4 step 5: 500 ms).
	tailQuiet time.Duration
}

// prodPorts wires the real implementations.
func prodPorts(e Env) ports {
	return ports{
		fs:          fsxFS{},
		codec:       capsuleCodec{},
		live:        engineLive{eng: e.Live},
		ledger:      ledgerAdapter{l: e.Harness.Ledger},
		vaults:      storeVaults{s: e.Vaults},
		git:         execGit{env: e.Harness.Host},
		busy:        registryBusy{},
		scanLinks:   claude.ScanLinks,
		historyLine: claude.ParseHistoryLine,
		codexClass:  codex.Classify,
		sleep:       sleepCtx,
		rescueWait:  time.Second,
		tailQuiet:   500 * time.Millisecond,
	}
}

// sleepCtx waits d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// errMixedHandles means a handle of another fileSystem reached a
// production adapter (a wiring bug, never user input).
var errMixedHandles = errors.New("sweep: file handle from another file system")

// fsxFS is the production fileSystem (internal/fsx).
type fsxFS struct{}

type fsxDir struct{ d *fsx.Dir }

type fsxStaging struct{ s *fsx.Staging }

func (fsxFS) OpenBase(path string) (dirHandle, error) {
	d, err := fsx.OpenBase(path)
	if err != nil {
		return nil, err
	}
	return fsxDir{d}, nil
}
func (fsxFS) MkdirPrivate(path string) error { return fsx.MkdirPrivate(path) }
func (fsxFS) CheckSpace(path string, need int64, floor fsx.Floor) error {
	return fsx.CheckSpace(path, need, floor)
}
func (fsxFS) Space(path string) (uint64, uint64, error) { return fsx.Space(path) }
func (fsxFS) NewStaging(preferred, target, id string) (stagingHandle, error) {
	s, err := fsx.NewStaging(preferred, target, id)
	if err != nil {
		return nil, err
	}
	return fsxStaging{s}, nil
}
func (fsxFS) OpenStaging(path string) (stagingHandle, error) {
	s, err := fsx.OpenStaging(path)
	if err != nil {
		return nil, err
	}
	return fsxStaging{s}, nil
}

func (s fsxStaging) Dir() dirHandle { return fsxDir{s.s.Dir} }
func (s fsxStaging) Path() string   { return s.s.Path }
func (s fsxStaging) ID() string     { return s.s.ID }
func (s fsxStaging) Remove() error  { return s.s.Remove() }

func (x fsxDir) Path() string { return x.d.Path() }
func (x fsxDir) Close() error { return x.d.Close() }
func (x fsxDir) OpenDir(rel string, create bool) (dirHandle, error) {
	d, err := x.d.OpenDir(rel, create)
	if err != nil {
		return nil, err
	}
	return fsxDir{d}, nil
}
func (x fsxDir) Open(rel string) (*os.File, fsx.Stat, error) { return x.d.Open(rel) }
func (x fsxDir) Lstat(rel string) (fsx.Stat, error)          { return x.d.Lstat(rel) }
func (x fsxDir) ReadDir(rel string) ([]fsx.Entry, error)     { return x.d.ReadDir(rel) }
func (x fsxDir) Walk(rel string, fn func(fsx.WalkEntry) error) error {
	return x.d.Walk(rel, fn)
}
func (x fsxDir) CreateTemp(dirRel, pattern string) (*os.File, string, error) {
	return x.d.CreateTemp(dirRel, pattern)
}
func (x fsxDir) Rename(oldRel, newRel string, mode fsx.RenameMode) error {
	return x.d.Rename(oldRel, newRel, mode)
}
func (x fsxDir) RenameTo(oldRel string, dst dirHandle, newRel string, mode fsx.RenameMode) error {
	dd, ok := dst.(fsxDir)
	if !ok {
		return errMixedHandles
	}
	return x.d.RenameTo(oldRel, dd.d, newRel, mode)
}
func (x fsxDir) Link(oldRel, newRel string) error { return x.d.Link(oldRel, newRel) }
func (x fsxDir) UnlinkIfUnchanged(rel string, expect fsx.Stat) error {
	return x.d.UnlinkIfUnchanged(rel, expect)
}
func (x fsxDir) Remove(rel string) error                  { return x.d.Remove(rel) }
func (x fsxDir) RemoveEmptyDirs(rel, stopAt string) error { return x.d.RemoveEmptyDirs(rel, stopAt) }
func (x fsxDir) Chtimes(rel string, mtime time.Time) error {
	return x.d.Chtimes(rel, mtime)
}
func (x fsxDir) Chmod(rel string, perm fs.FileMode) error { return x.d.Chmod(rel, perm) }
func (x fsxDir) Sync() error                              { return x.d.Sync() }
func (x fsxDir) Device() (uint64, error)                  { return x.d.Device() }

// rawDir unwraps a production handle.
func rawDir(h dirHandle) (*fsx.Dir, error) {
	if h == nil {
		return nil, nil
	}
	x, ok := h.(fsxDir)
	if !ok {
		return nil, errMixedHandles
	}
	return x.d, nil
}

// capsuleCodec is the production codecPort (internal/capsule).
type capsuleCodec struct{}

func (capsuleCodec) Seal(ctx context.Context, r sealRequest) (*capsule.Sealed, error) {
	out, err := rawDir(r.Out)
	if err != nil {
		return nil, err
	}
	req := capsule.SealRequest{Manifest: r.Manifest, Dirs: r.Dirs, Out: out, Name: r.Name, OnPhase: r.OnPhase}
	for _, in := range r.Inputs {
		d, err := rawDir(in.Dir)
		if err != nil {
			return nil, err
		}
		req.Inputs = append(req.Inputs, capsule.Input{
			Base: in.Base, Dir: d, Rel: in.Rel, Path: in.Path, Snap: in.Snap,
			Append: in.Append, Group: in.Group, Open: in.Open,
		})
	}
	if r.Recipients.apply == nil {
		return nil, capsule.ErrRecipients
	}
	r.Recipients.apply(&req)
	return capsule.Seal(ctx, req)
}

func (capsuleCodec) ReadHeader(dir dirHandle, name string) ([]byte, string, error) {
	d, err := rawDir(dir)
	if err != nil {
		return nil, "", err
	}
	return capsule.ReadHeader(d, name)
}

func (capsuleCodec) HashFile(dir dirHandle, name string) (string, int64, error) {
	d, err := rawDir(dir)
	if err != nil {
		return "", 0, err
	}
	return capsule.HashFile(d, name)
}

func (capsuleCodec) OpenManifest(r io.Reader, fileKey []byte) (capsule.Manifest, error) {
	return capsule.OpenManifest(r, fileKey)
}

func (capsuleCodec) Extract(ctx context.Context, r io.Reader, o extractRequest) (capsule.Manifest, []capsule.Staged, error) {
	st, ok := o.Staging.(fsxStaging)
	if !ok {
		return capsule.Manifest{}, nil, errMixedHandles
	}
	return capsule.Extract(ctx, r, capsule.ExtractOptions{FileKey: o.FileKey, Staging: st.s, Limits: o.Limits, Check: o.Check})
}

// engineLive is the production livePort. Without an engine every unit is
// live (fail closed).
type engineLive struct{ eng *live.Engine }

func (l engineLive) Decide(ctx context.Context, s live.Subject, extra []live.Evidence) (live.Verdict, error) {
	if l.eng == nil {
		return live.Verdict{Live: true, Evidence: []live.Evidence{{Reason: live.ReasonUnknown, Detail: "no liveness engine"}}}, nil
	}
	return l.eng.Decide(ctx, s, extra)
}

func (l engineLive) StillQuiet(ctx context.Context, s live.Subject, snaps map[string]fsx.Stat) (bool, error) {
	if l.eng == nil {
		return false, nil
	}
	return l.eng.StillQuiet(ctx, s, snaps)
}

// ledgerAdapter is the production ledgerPort; without a ledger there is
// nothing to snapshot or archive.
type ledgerAdapter struct{ l *ledger.Ledger }

func (a ledgerAdapter) Snapshot(h, sid string) ([]byte, int64, error) {
	if a.l == nil {
		return nil, 0, nil
	}
	raw, n, err := a.l.Snapshot(h, sid)
	if errors.Is(err, ledger.ErrNotFound) {
		return nil, 0, nil
	}
	return raw, n, err
}

func (a ledgerAdapter) Archive(h, sid string, n int64) error {
	if a.l == nil || n == 0 {
		return nil
	}
	err := a.l.Archive(h, sid, n)
	if errors.Is(err, ledger.ErrNotFound) {
		return nil
	}
	return err
}

func (a ledgerAdapter) List(h string) ([]ledger.Session, error) {
	if a.l == nil {
		return nil, nil
	}
	return a.l.List(h)
}

// storeVaults is the production vaultPort.
type storeVaults struct{ s *vault.Store }

func (v storeVaults) recipients(id string) (recipientSet, error) {
	if v.s == nil {
		return recipientSet{}, errors.New("sweep: no vault store")
	}
	rs, fpr, err := v.s.Recipients(id)
	if err != nil {
		return recipientSet{}, err
	}
	return recipientSet{fpr: fpr, apply: func(req *capsule.SealRequest) { req.Recipients = rs }}, nil
}

// execGit is the production gitPort: a hardened, read-only `git ls-files`
// run once per repository and sweep (SPEC §8.2, S21, IM22).
type execGit struct{ env paths.Env }

// maxGitIndexBytes bounds the ls-files output read (beyond it: tracked).
const maxGitIndexBytes = 64 << 20

func (g execGit) Tracked(ctx context.Context, repo string) (map[string]bool, error) {
	bin, err := paths.LookPath(g.env, "git")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-C", repo,
		"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
		"ls-files", "-z", "--cached")
	cmd.Env = []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"PATH=" + filepath.Dir(bin),
		"HOME=/nonexistent",
		"LC_ALL=C",
	}
	var out limitedBuffer
	out.max = maxGitIndexBytes
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	cmd.Stdin = nil
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	if out.over {
		return nil, errors.New("sweep: git index listing too large")
	}
	set := map[string]bool{}
	for _, p := range bytes.Split(out.b.Bytes(), []byte{0}) {
		if len(p) > 0 {
			set[string(p)] = true
		}
	}
	return set, nil
}

// limitedBuffer keeps at most max bytes and remembers that it overflowed.
type limitedBuffer struct {
	b    bytes.Buffer
	max  int
	over bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.b.Len()+len(p) > l.max {
		l.over = true
		return 0, errors.New("output too large")
	}
	return l.b.Write(p)
}

// registryBusy is the production busyPort: a Claude registry entry whose
// cwd lies inside root and that is mid-turn makes the root busy; an
// unreadable registry is busy too (D17, fail closed).
type registryBusy struct{}

func (registryBusy) RootBusy(ctx context.Context, e Env, root string) (bool, error) {
	ad := adapterFor(e, harness.ClaudeCode)
	if ad == nil {
		return false, nil
	}
	homes, err := ad.Homes(ctx, e.Harness)
	if err != nil {
		return true, err
	}
	for _, h := range homes {
		dir := h.Bases[capsule.BaseClaudeConfig]
		if dir == "" {
			continue
		}
		entries, err := claude.ReadRegistry(dir)
		if err != nil {
			return true, err
		}
		for _, re := range entries {
			if !re.Valid {
				return true, fmt.Errorf("sweep: unreadable registry entry for pid %d", re.PID)
			}
			if re.Busy() && (re.Cwd == "" || paths.Within(root, re.Cwd)) {
				return true, nil
			}
		}
	}
	return false, nil
}

// adapterFor returns the adapter of harness id among e.Adapters.
func adapterFor(e Env, id harness.ID) harness.Adapter {
	for _, a := range e.Adapters {
		if a != nil && a.ID() == id {
			return a
		}
	}
	return nil
}

// sortedCopy returns a sorted copy of s.
func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}
