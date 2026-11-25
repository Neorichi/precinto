package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault"
)

// fakeVaults is an in-memory vaultOps: each vault's identity is a fixed
// fake secret; unwrap optionally asks the UI for a passphrase.
type fakeVaults struct {
	mu        sync.Mutex
	unwraps   map[string]int
	ask       bool // unwrap asks ui.Secret and requires "correct horse battery"
	unwrapErr map[string]error
	verifyErr map[string]error
	block     chan struct{} // when set, unwrap waits for it
	metas     map[string]vault.Meta
	fpr       map[string]string
	repairs   []string
	repairErr error
	plans     []string
	audited   map[string]time.Time
	auditErr  error
	created   []string
	factors   []string
	specs     []vault.FactorSpec
	uis       []vault.UI
}

func newFakeVaults() *fakeVaults {
	return &fakeVaults{unwraps: map[string]int{}, unwrapErr: map[string]error{}, verifyErr: map[string]error{},
		metas: map[string]vault.Meta{}, fpr: map[string]string{}, audited: map[string]time.Time{}}
}

// set mutates the fake under its lock (the daemon reads it concurrently).
func (f *fakeVaults) set(fn func(f *fakeVaults)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func fakeIdentity(id string) *memguard.LockedBuffer {
	return memguard.NewBufferFromBytes([]byte("AGE-SECRET-KEY-1FAKE" + id))
}

func (f *fakeVaults) unwrap(ctx context.Context, id, factor string, u vault.UI) (*memguard.LockedBuffer, error) {
	f.mu.Lock()
	f.unwraps[id]++
	err := f.unwrapErr[id]
	block := f.block
	ask := f.ask
	f.uis = append(f.uis, u)
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, vault.ErrCancelled
		}
	}
	if err != nil {
		return nil, err
	}
	if ask {
		p, err := u.Secret("passphrase")
		if err != nil {
			return nil, err
		}
		ok := string(p.Bytes()) == "correct horse battery"
		p.Destroy()
		if !ok {
			return nil, vault.ErrWrongIdentity
		}
	}
	return fakeIdentity(id), nil
}

func (f *fakeVaults) count(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unwraps[id]
}

func (f *fakeVaults) verify(id string, identity *memguard.LockedBuffer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verifyErr[id]
}

func (f *fakeVaults) create(ctx context.Context, id, rootPath string, u vault.UI) (*memguard.LockedBuffer, error) {
	f.mu.Lock()
	f.created = append(f.created, id)
	f.mu.Unlock()
	return fakeIdentity(id), nil
}

func (f *fakeVaults) addFactor(ctx context.Context, id string, identity *memguard.LockedBuffer, spec vault.FactorSpec, u vault.UI) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !identity.IsAlive() || string(identity.Bytes()) != string(fakeIdentity(id).Bytes()) {
		return vault.ErrWrongIdentity // the key holder's identity of this very vault
	}
	f.factors = append(f.factors, id+":"+string(spec.Kind))
	rec := spec
	if spec.Passphrase != nil {
		rec.Passphrase = memguard.NewBufferFromBytes(append([]byte(nil), spec.Passphrase.Bytes()...))
		spec.Passphrase.Destroy() // consumed, like vault.AddFactor
	}
	f.specs = append(f.specs, rec)
	return nil
}

func (f *fakeVaults) repairPlan(id string, identity, recovery *memguard.LockedBuffer, now time.Time) (vault.RepairResult, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repairErr != nil {
		return vault.RepairResult{}, "", f.repairErr
	}
	f.plans = append(f.plans, id)
	return vault.RepairResult{RecipientChanged: true, LastAudit: f.metas[id].LastAudit}, "fpr-repaired", nil
}

func (f *fakeVaults) markAudited(id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auditErr != nil {
		return f.auditErr
	}
	f.audited[id] = at
	m := f.metas[id]
	m.ID, m.LastAudit = id, at
	if len(m.Factors) == 0 {
		m.Factors = []vault.Factor{{Name: "se", Kind: vault.FactorSE, GUI: true}}
	}
	f.metas[id] = m
	return nil
}

func (f *fakeVaults) repair(id string, identity, recovery *memguard.LockedBuffer, now time.Time) (vault.RepairResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repairErr != nil {
		return vault.RepairResult{}, f.repairErr
	}
	f.repairs = append(f.repairs, id)
	f.fpr[id] = "fpr-repaired"
	return vault.RepairResult{RecipientChanged: true, LastAudit: f.metas[id].LastAudit}, nil
}

func (f *fakeVaults) meta(id string) (vault.Meta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.metas[id]
	if !ok {
		m = vault.Meta{ID: id, Factors: []vault.Factor{{Name: "se", Kind: vault.FactorSE, GUI: true}}}
	}
	return m, nil
}

func (f *fakeVaults) fingerprint(id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.fpr[id]; ok {
		return v, nil
	}
	return "fpr-" + id, nil
}

// fakeKeyring keeps copies of fake identities; file keys and MACs are
// deterministic functions of them.
type fakeKeyring struct {
	mu      sync.Mutex
	ids     map[string][]byte
	dropped []string
}

func newFakeKeyring() *fakeKeyring { return &fakeKeyring{ids: map[string][]byte{}} }

func (k *fakeKeyring) Put(id string, identity *memguard.LockedBuffer) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ids[id] = append([]byte(nil), identity.Bytes()...)
	identity.Destroy()
	return nil
}

func (k *fakeKeyring) Has(id string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.ids[id]
	return ok
}

func (k *fakeKeyring) Drop(id string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.ids, id)
	k.dropped = append(k.dropped, id)
}

func (k *fakeKeyring) DropAll() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for id := range k.ids {
		k.dropped = append(k.dropped, id)
	}
	k.ids = map[string][]byte{}
}

func (k *fakeKeyring) IDs() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for id := range k.ids {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func (k *fakeKeyring) droppedIDs() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.dropped...)
}

func fileKeyOf(header []byte) []byte {
	s := sha256.Sum256(header)
	return s[:16]
}

func (k *fakeKeyring) FileKey(id string, header []byte) (*memguard.LockedBuffer, error) {
	if !k.Has(id) {
		return nil, vault.ErrLocked
	}
	return memguard.NewBufferFromBytes(fileKeyOf(header)), nil
}

func (k *fakeKeyring) WithIdentityBuffer(id string, fn func(identity *memguard.LockedBuffer) error) error {
	k.mu.Lock()
	ident, ok := k.ids[id]
	k.mu.Unlock()
	if !ok {
		return vault.ErrLocked
	}
	b := memguard.NewBufferFromBytes(append([]byte(nil), ident...))
	defer b.Destroy()
	return fn(b)
}

func (k *fakeKeyring) MAC(id, info string, data []byte) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	ident, ok := k.ids[id]
	if !ok {
		return "", vault.ErrLocked
	}
	m := hmac.New(sha256.New, ident)
	m.Write([]byte(info))
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// fakeCapsules is the provenance side: headers on "disk", log entries and
// manifests.
type fakeCapsules struct {
	mu        sync.Mutex
	headers   map[string][]byte
	entries   map[string]capslog.Entry
	manifests map[string]capsule.Manifest
}

func newFakeCapsules() *fakeCapsules {
	return &fakeCapsules{headers: map[string][]byte{}, entries: map[string]capslog.Entry{}, manifests: map[string]capsule.Manifest{}}
}

func shaHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// add logs a capsule of vault (roots) at rel with a matching manifest.
func (f *fakeCapsules) add(rel, vaultID string, roots ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := []byte("age-encryption.org/v1 header of " + rel)
	f.headers[rel] = h
	f.entries[rel] = capslog.Entry{Path: rel, HeaderSHA256: shaHex(h), Kind: string(capsule.KindMarkdown), Unit: "unit-" + rel,
		VaultID: vaultID, RootIDs: roots, SealedAt: epochT.Add(time.Hour), RecipientsFpr: "fpr-" + vaultID}
	f.manifests[rel] = capsule.Manifest{Kind: capsule.KindMarkdown, UnitKey: "unit-" + rel, VaultID: vaultID, RootIDs: roots}
}

// epochT is where the daemon's fake clock starts (x.h.Clock, testkit.Epoch):
// fixture times (process starts, registry startedAt, capsule sealed_at)
// are derived from it, never from a copy of the date, so they stay
// consistent with the clock whatever its value (TESTPLAN §1.4, D77).
var epochT = testkit.Epoch

func (f *fakeCapsules) readHeader(rel string) ([]byte, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.headers[rel]
	if !ok {
		return nil, "", errors.New("no such capsule")
	}
	return h, shaHex(h), nil
}

func (f *fakeCapsules) lookup(rel, sha string) (capslog.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[rel]
	if !ok || e.HeaderSHA256 != sha {
		return capslog.Entry{}, capslog.ErrNotLogged
	}
	return e, nil
}

func (f *fakeCapsules) logged() ([]capslog.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []capslog.Entry
	for _, e := range f.entries {
		out = append(out, e)
	}
	return out, nil
}

func (f *fakeCapsules) manifest(rel string, key []byte) (capsule.Manifest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.manifests[rel]
	if !ok || string(key) != string(fileKeyOf(f.headers[rel])) {
		return capsule.Manifest{}, errors.New("cannot decrypt")
	}
	return m, nil
}

// td is a daemon under test: real socket, real machine, fake seams.
type td struct {
	t        *testing.T
	h        *testkit.Home
	d        *daemon
	vaults   *fakeVaults
	keys     *fakeKeyring
	caps     *fakeCapsules
	rec      *recorder
	cancel   context.CancelFunc
	done     chan error
	mu       sync.Mutex
	peer     *platform.Peer // nil: the in-process peer itself
	same     bool
	screen   platform.ScreenState
	spawned  [][]string
	registry map[string][]claude.RegistryEntry
	regErr   error
	jobs     []claude.Job
	signal   func(id platform.ProcID, sig syscall.Signal)
	waitExit func(ctx context.Context, id platform.ProcID) error
	// drive stands in for paths.CheckDrive (D156); nil: no drive.
	drive func(p string) error
}

type tdOpt func(*td, *Options)

func startTD(t *testing.T, opts ...tdOpt) *td {
	t.Helper()
	x := &td{t: t, h: testkit.NewHome(t), vaults: newFakeVaults(), keys: newFakeKeyring(), caps: newFakeCapsules(),
		rec: &recorder{}, done: make(chan error, 1), same: true, screen: platform.ScreenState{LockKnown: true},
		registry: map[string][]claude.RegistryEntry{}}
	x.h.Protect(t, "work/beta")
	x.addVault("root-acme")
	x.addVault("root-beta")
	x.addVault(vault.GlobalID)
	o := Options{Layout: x.h.Layout, Env: x.h.Env, Exe: "/opt/precinto/bin/precinto", Version: "test",
		Clock: x.h.Clock, Procs: x.h.Procs, IdleExit: 100 * 365 * 24 * time.Hour, Tick: 10 * time.Millisecond,
		Spawn: x.spawn, Screen: x.readScreen, Harden: func() error { return nil }}
	for _, f := range opts {
		f(x, &o)
	}
	x.start(o)
	return x
}

func (x *td) addVault(id string) {
	dir := x.h.Layout.VaultDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		x.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vault.toml"), []byte("format = 1\n"), 0o600); err != nil {
		x.t.Fatal(err)
	}
}

func (x *td) start(o Options) {
	ln, err := ipc.Listen(x.h.Layout)
	if err != nil {
		x.t.Fatal(err)
	}
	dp := newDeps(x.h.Layout, x.h.Procs, x.h.Clock, false, x.rec)
	dp.vaults, dp.keyring = x.vaults, x.keys
	dp.readHeader, dp.lookup, dp.logged, dp.manifest = x.caps.readHeader, x.caps.lookup, x.caps.logged, x.caps.manifest
	dp.opens = func(identity *memguard.LockedBuffer, header []byte) bool {
		return string(identity.Bytes()) == "AGE-SECRET-KEY-1FAKEroot-acme"
	}
	dp.peer = func(c *ipc.Conn) (platform.Peer, bool) {
		x.mu.Lock()
		defer x.mu.Unlock()
		if x.peer != nil {
			return *x.peer, x.same
		}
		return c.Peer(), c.PeerSameExecutable()
	}
	dp.registry = func(dir string) ([]claude.RegistryEntry, error) {
		x.mu.Lock()
		defer x.mu.Unlock()
		return x.registry[dir], x.regErr
	}
	dp.jobs = func(string) ([]claude.Job, error) {
		x.mu.Lock()
		defer x.mu.Unlock()
		return x.jobs, nil
	}
	dp.signal = func(id platform.ProcID, sig syscall.Signal) error {
		_ = x.rec.signal(id, sig)
		if x.signal != nil {
			x.signal(id, sig)
		}
		return nil
	}
	if x.waitExit != nil {
		dp.waitExit = x.waitExit
	}
	dp.checkDrive = func(p string) error {
		x.mu.Lock()
		f := x.drive
		x.mu.Unlock()
		if f == nil {
			return nil
		}
		return f(p)
	}
	x.d = newDaemon(o, dp, ln)
	x.d.rec = x.rec
	ctx, cancel := context.WithCancel(context.Background())
	x.cancel = cancel
	go func() { x.done <- x.d.serve(ctx) }()
	x.t.Cleanup(x.stop)
}

func (x *td) stop() {
	if x.cancel != nil {
		x.cancel()
		select {
		case <-x.done:
		case <-time.After(10 * time.Second):
			x.t.Error("daemon did not stop")
		}
		x.cancel = nil
	}
}

func (x *td) spawn(argv []string, _ platform.SpawnOptions) (platform.ProcID, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.spawned = append(x.spawned, argv)
	return platform.ProcID{PID: 990000 + len(x.spawned), StartUS: 1}, nil
}

func (x *td) readScreen(ctx context.Context) (platform.ScreenState, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	s := x.screen
	s.At = x.h.Clock.Now()
	return s, nil
}

func (x *td) setScreen(s platform.ScreenState) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.screen = s
}

func (x *td) setPeer(p *platform.Peer, same bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.peer, x.same = p, same
}

func (x *td) dial() *ipc.Client {
	x.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := ipc.Dial(ctx, ipc.DialOptions{Layout: x.h.Layout, Client: "test", Timeout: 5 * time.Second, Insecure: true})
	if err != nil {
		x.t.Fatal(err)
	}
	x.t.Cleanup(func() { c.Close() })
	return c
}

// eventually waits for cond (the daemon's tick runs every 10 ms).
func (x *td) eventually(what string, cond func() bool) {
	x.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			x.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (x *td) vaultState(id string) VaultState {
	return x.d.snap.Load().snap.Vaults[id].State
}

func (x *td) spawnedArgs() [][]string {
	x.mu.Lock()
	defer x.mu.Unlock()
	var out [][]string
	for _, a := range x.spawned {
		out = append(out, a[1:])
	}
	return out
}

// unlockTTY unlocks roots from a terminal client.
func (x *td) unlockTTY(c *ipc.Client, ui ipc.UIHandler, roots ...string) (ipc.UnlockResp, error) {
	return c.Unlock(context.Background(), ipc.UnlockReq{RootIDs: roots, TTY: true, Confirmed: len(roots) > 1}, ui)
}

// scripted is a client UI handler.
type scripted struct {
	mu        sync.Mutex
	secret    string
	prompts   []string
	confirm   bool
	displayed []string
}

func (s *scripted) Display(m string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.displayed = append(s.displayed, m)
	return nil
}

func (s *scripted) Secret(p string) (*memguard.LockedBuffer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prompts = append(s.prompts, p)
	return memguard.NewBufferFromBytes([]byte(s.secret)), nil
}

func (s *scripted) Confirm(p, yes, no string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prompts = append(s.prompts, p)
	return s.confirm, nil
}

func ipcCode(err error) ipc.Code {
	var e *ipc.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Fake processes of the tests (pids are made up; nothing real is ever
// signalled: the daemon runs on a fake table).
func (x *td) addProc(pid, ppid, sid int, exe string, argv ...string) platform.ProcInfo {
	p := platform.ProcInfo{ID: platform.ProcID{PID: pid, StartUS: epochT.Add(-time.Hour).UnixMicro() + int64(pid)},
		PPID: ppid, SID: sid, UID: os.Getuid(), Exe: exe, Argv: argv}
	x.h.Procs.Add(p)
	return p
}
