package agent

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/vault"
)

// Daemon constants.
const (
	defaultIdleExit = 10 * time.Minute
	defaultTick     = 3 * time.Second
	heartbeatEvery  = time.Second
	// jumpThreshold is the wall−monotonic jump that means sleep/wake (D24).
	jumpThreshold = 30 * time.Second
	// hookPresenceWindow is how long a harness process may run without any
	// hook event or registration before the scan calls it ungated (§14.4).
	hookPresenceWindow = 10 * time.Second
	// unlockWait bounds a hook-raised unlock (HOOKS-IO §1) and a TTY one.
	hookUnlockWait = 60 * time.Second
	ttyUnlockWait  = 2 * time.Minute
	// queueDrainEvery spaces `seal --queue` workers spawned by the daemon.
	queueDrainEvery = time.Minute
	subscriberQueue = 64
)

// published is what connection handlers read without taking any lock.
type published struct {
	snap         Snapshot
	screenLocked bool
	screenKnown  bool
	next         time.Time
	hasNext      bool
}

// mreq is one input for the machine goroutine.
type mreq struct {
	in   Input
	done chan []Action // nil: fire and forget
}

// subscriber is one subscribed connection.
type subscriber struct {
	conn    *ipc.Conn
	id      uint64
	roots   []string
	sid     string
	peer    platform.ProcID // the subscribing process, measured at accept (D71 addressing)
	wrapper bool            // subscribed as a wrapper (SubscribeReq.Wrapper)
	q       chan ipc.Event
	once    sync.Once
	done    chan struct{}
}

func (s *subscriber) stop() {
	s.once.Do(func() {
		close(s.done)
		_ = s.conn.Close()
	})
}

// wants reports whether ev concerns the subscription. End events never go
// through it: they are addressed to the wrapper whose session ends (D71,
// daemon.sendEnd).
func (s *subscriber) wants(ev ipc.Event) bool {
	if ev.Kind == ipc.EventEnd {
		return false
	}
	if ev.Kind == ipc.EventHeartbeat || (len(s.roots) == 0 && s.sid == "") {
		return true
	}
	if s.sid != "" && slices.Contains(ev.SIDs, s.sid) {
		return true
	}
	for _, r := range ev.RootIDs {
		if slices.Contains(s.roots, r) {
			return true
		}
	}
	return false
}

// policyState is the effective policy and how it was derived (D48, D55).
type policyState struct {
	cfg       config.Config // config.toml as last loaded successfully
	cfgStamp  string        // size+mtime of config.toml at that load
	pinned    config.Pinned
	hasPinned bool
	tampered  bool // policy-tampered: defaults join the strictest merge
	forged    bool // the pin failed to decode, its shape (D91) or its MAC: never re-pinned without confirmation
	// verified: a MAC of the pin was checked with a vault key in this
	// daemon's lifetime, or the daemon wrote the pin (D91). An unverified
	// pin is never re-pinned without a confirmation.
	verified bool
	eff      config.Config // what the daemon enforces
	pending  []config.Change
	// recorded: the folders the root vaults record, which join eff while
	// the policy is tampered (D145, recordedRoots).
	recorded []config.Root
}

// daemon is one running `precinto agent`.
type daemon struct {
	o       Options
	l       paths.Layout
	clock   platform.Clock
	procs   platform.ProcTable
	real    bool
	deps    deps
	rec     *recorder
	ln      *ipc.Listener
	started time.Time
	logger  *log.Logger

	m    *Machine // owned by the machine goroutine
	mch  chan mreq
	snap atomic.Pointer[published]

	limiter *RateLimiter

	mu          sync.Mutex
	pol         policyState
	attention   map[string]ipc.Attention // by code + folder + pid
	taint       map[string][]string      // sid → managed roots (sticky, HA10)
	subs        map[*subscriber]struct{}
	enterAt     map[string]instant          // session key → last verified Enter (D37)
	sessSeen    map[string]instant          // sid → last hook event (expiry of process-less records)
	humanGate   map[string]instant          // sid → last prompt gate with a human origin
	hookSeen    map[platform.ProcID]instant // harness process → last hook event or registration
	signalable  map[platform.ProcID]bool    // registered or scan-found: may be ended (D57)
	workers     map[platform.ProcID]bool
	ungated     map[platform.ProcID]ungatedMatch
	hid         hidSample
	screenOK    bool
	gui         map[string]bool             // vault id → has a factor that prompts without a terminal
	factors     map[string][]string         // vault id → enrolled factor kinds in unlock order (CC-40)
	versions    map[platform.ProcID]string  // harness process → version from register (CC-49)
	repairs     map[*pendingRepair]struct{} // identities held by vault_repair dry runs (CC-32)
	invs        []harness.Inventory         // embedded inventories (CC-12)
	lastQueue   instant
	queueWorker platform.ProcID
	spawned     [][]string

	ctx      context.Context // the serve context: background work ends with it
	shutdown chan struct{}
	shutOnce sync.Once
	wg       sync.WaitGroup
}

// hidSample is the last console poll (D37).
type hidSample struct {
	known bool
	idle  time.Duration
	at    instant
}

// ungatedMatch is a report-only scan finding (D52).
type ungatedMatch struct {
	proc    platform.ProcInfo
	harness string
	rootID  string
	why     string
}

// run implements Run.
func run(ctx context.Context, o Options) error {
	if ctx == nil {
		return errors.New("agent: nil context")
	}
	o = withDefaults(o)
	if err := o.Harden(); err != nil {
		return err
	}
	l := o.Layout
	if l.RunDir == "" || l.Base == "" {
		return errors.New("agent: incomplete layout")
	}
	ln, err := ipc.Listen(l)
	if err != nil {
		return err
	}
	rec := &recorder{}
	real := isSystemTable(o.Procs)
	d := newDaemon(o, newDeps(l, o.Procs, o.Clock, real, rec), ln)
	d.rec, d.real = rec, real
	return d.serve(ctx)
}

// withDefaults fills unset options with the real implementations.
func withDefaults(o Options) Options {
	if o.Clock == nil {
		o.Clock = platform.SystemClock()
	}
	if o.Procs == nil {
		o.Procs = platform.System()
	}
	if o.IdleExit <= 0 {
		o.IdleExit = defaultIdleExit
	}
	if o.Tick <= 0 {
		o.Tick = defaultTick
	}
	if o.Spawn == nil {
		o.Spawn = platform.Spawn
	}
	if o.Screen == nil {
		o.Screen = platform.ReadScreen
	}
	if o.Harden == nil {
		o.Harden = hardenWith(o.Env, platform.Harden, raiseMemlock)
	}
	if o.Pinentry == nil {
		env := o.Env
		if isSystemTable(o.Procs) {
			o.Pinentry = func(ctx context.Context, desc, prompt string) (*memguard.LockedBuffer, error) {
				return runPinentry(ctx, env, desc, prompt)
			}
		} else {
			// A fake process table means a test: never show a real dialog.
			o.Pinentry = func(context.Context, string, string) (*memguard.LockedBuffer, error) {
				return nil, errNoPinentry
			}
		}
	}
	return o
}

// hardenWith is the default Harden seam: refuse a loader-injected
// environment before anything else (SPEC §4.6), harden the process, then
// raise RLIMIT_MEMLOCK's soft limit to its hard limit (CC-17: every
// released file key and every identity is a locked buffer). A memlock
// limit that cannot be raised is not fatal: memguard falls back as it
// can and the keys request bound keeps the need small.
func hardenWith(env paths.Env, harden func() error, memlock func() error) func() error {
	return func() error {
		if err := platform.CheckLoaderEnv(env.Environ()); err != nil {
			return err
		}
		if err := harden(); err != nil {
			return err
		}
		if memlock != nil {
			if err := memlock(); err != nil {
				log.New(os.Stderr, "precinto agent: ", log.LstdFlags).Printf("RLIMIT_MEMLOCK not raised: %v", err)
			}
		}
		return nil
	}
}

// isSystemTable reports whether t is the kernel's process table: only then
// may the daemon signal processes or write to terminals.
func isSystemTable(t platform.ProcTable) bool {
	return t == nil || t == platform.System()
}

// newDaemon builds a daemon over ln with the given seams.
func newDaemon(o Options, dp deps, ln *ipc.Listener) *daemon {
	o = withDefaults(o)
	d := &daemon{
		o: o, l: o.Layout, clock: o.Clock, procs: o.Procs, deps: dp, ln: ln,
		started:    o.Clock.Now(),
		logger:     log.New(os.Stderr, "precinto agent: ", log.LstdFlags),
		mch:        make(chan mreq, 256),
		attention:  map[string]ipc.Attention{},
		taint:      map[string][]string{},
		subs:       map[*subscriber]struct{}{},
		enterAt:    map[string]instant{},
		sessSeen:   map[string]instant{},
		humanGate:  map[string]instant{},
		hookSeen:   map[platform.ProcID]instant{},
		signalable: map[platform.ProcID]bool{},
		workers:    map[platform.ProcID]bool{},
		ungated:    map[platform.ProcID]ungatedMatch{},
		gui:        map[string]bool{},
		factors:    map[string][]string{},
		versions:   map[platform.ProcID]string{},
		repairs:    map[*pendingRepair]struct{}{},
		shutdown:   make(chan struct{}),
		rec:        &recorder{},
		ctx:        context.Background(),
	}
	invs, err := loadInventories()
	if err != nil {
		d.logf("harness inventories: %v (no harness process can register)", err)
	}
	d.invs = invs
	d.loadPolicy()
	eff := d.effective()
	d.m = NewMachine(eff.Policy, o.Clock)
	d.m.declare(vaultIDs(eff)...)
	d.limiter = NewRateLimiter(eff.Policy, o.Clock)
	d.publish()
	return d
}

// vaultIDs lists the vaults of a configuration: every root and the global
// vault.
func vaultIDs(c config.Config) []string {
	ids := []string{vault.GlobalID}
	for _, r := range c.Roots {
		ids = append(ids, r.ID)
	}
	return ids
}

// now reads both clocks.
func (d *daemon) now() instant { return instant{wall: d.clock.Now(), mono: d.clock.Mono()} }

// serve runs the daemon until ctx ends, shutdown, or the idle-exit rule.
func (d *daemon) serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.ctx = ctx
	d.cleanRepairScratch()
	d.writeRootsList()
	for _, id := range vaultIDs(d.effective()) {
		d.refreshFactors(id) // before any event or status names them (CC-40)
	}
	d.spawnWorker("sweep", "--quiet") // recovery + full sweep at start (SPEC §13.1)
	d.bootstrap()

	d.wg.Add(4)
	go func() { defer d.wg.Done(); d.machineLoop(ctx) }()
	go func() { defer d.wg.Done(); d.acceptLoop(ctx) }()
	go func() { defer d.wg.Done(); d.tickLoop(ctx, cancel) }()
	go func() { defer d.wg.Done(); d.heartbeatLoop(ctx) }()
	jumps := make(chan platform.Jump, 4)
	d.wg.Add(2)
	go func() { defer d.wg.Done(); platform.WatchJumps(ctx, d.clock, d.o.Tick, jumpThreshold, jumps) }()
	go func() {
		defer d.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case j := <-jumps:
				d.post(Input{Kind: InJump, Jump: j})
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-d.shutdown:
	}
	cancel()
	// Keys first: whatever else happens, nothing stays unlocked (I15).
	d.deps.keyring.DropAll()
	d.wipeRepairs()
	_ = d.ln.Close()
	d.mu.Lock()
	for s := range d.subs {
		s.stop()
	}
	d.mu.Unlock()
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return nil
}

// machineLoop owns the Machine: inputs are applied one at a time, the
// immediate actions run before the next input, then a snapshot is
// published.
func (d *daemon) machineLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-d.mch:
			acts := d.m.Apply(r.in)
			if r.in.Kind == InPolicy && r.in.Policy != nil {
				d.updateLimiter(*r.in.Policy)
			}
			// Publish before the events go out: a subscriber that registers
			// between the two reads the new state (its initial event) and
			// may get the event again, never miss it (D71). The actions
			// never change the machine, so this snapshot stays current.
			d.publish()
			switch r.in.Kind {
			case InLock, InScreenLocked, InJump:
				// Any lock wipes a vault_repair dry run's identity (CC-32),
				// also when every vault was locked already.
				d.wipeRepairs()
			}
			d.runActions(acts)
			if r.done != nil {
				r.done <- acts
			}
		}
	}
}

// updateLimiter applies a new policy's rate limits (the limiter itself is
// never replaced: in-flight unlocks keep their single flight).
func (d *daemon) updateLimiter(p config.Policy) {
	l := d.limiter
	l.mu.Lock()
	l.perMinute, l.backoff, l.cooldown = p.PromptRatePerMinute, p.PromptBackoff.D(), p.HookPromptCooldown.D()
	l.mu.Unlock()
}

// apply feeds an input and waits until its immediate actions ran.
func (d *daemon) apply(ctx context.Context, in Input) []Action {
	r := mreq{in: in, done: make(chan []Action, 1)}
	select {
	case d.mch <- r:
	case <-ctx.Done():
		return nil
	}
	select {
	case acts := <-r.done:
		return acts
	case <-ctx.Done():
		return nil
	}
}

// post feeds an input without waiting.
func (d *daemon) post(in Input) {
	select {
	case d.mch <- mreq{in: in}:
	default:
		// The queue is full: deliver from a goroutine rather than drop it.
		go func() {
			select {
			case d.mch <- mreq{in: in}:
			case <-d.shutdown:
			case <-time.After(10 * time.Second):
			}
		}()
	}
}

// publish swaps in a fresh snapshot (machine goroutine or construction).
func (d *daemon) publish() {
	p := &published{snap: d.m.Snapshot(), screenLocked: d.m.screenLocked()}
	p.next, p.hasNext = d.m.NextDeadline()
	d.mu.Lock()
	p.screenKnown = d.screenOK
	d.mu.Unlock()
	d.snap.Store(p)
}

// view returns the published state, conservatively updated to now: a
// folder whose deadline passed reads as locked even if the tick that locks
// it has not run yet (fail closed).
func (d *daemon) view() gateView {
	p := d.snap.Load()
	now := d.clock.Now()
	v := gateView{now: now, vaults: p.snap.Vaults, sessions: p.snap.Sessions, screenLocked: p.screenLocked, screenKnown: p.screenKnown}
	if p.hasNext && !now.Before(p.next) {
		vaults := make(map[string]VaultSnapshot, len(v.vaults))
		for id, vs := range v.vaults {
			if vs.State == VaultUnlocked {
				switch {
				case !now.Before(vs.AbsDeadline):
					vs.State, vs.Reason = VaultLocked, "limit"
				case !now.Before(vs.IdleDeadline):
					vs.State, vs.Reason = VaultLocked, "idle"
				}
			}
			vaults[id] = vs
		}
		v.vaults = vaults
		d.post(Input{Kind: InTick})
	}
	return v
}

// runActions performs the effects of one Apply, in order. Key wipes and
// publishes run at once; everything slow runs in the background so a lock
// never waits for UI, seals or restores (I6, I15).
func (d *daemon) runActions(acts []Action) {
	for _, a := range acts {
		switch a.Kind {
		case ActWipeKey:
			d.deps.keyring.Drop(a.Vault)
			d.wipeRepairs() // any lock wipes a vault_repair dry run's identity (CC-32)
			d.logf("locked %s (%s)", a.Vault, a.Reason)
		case ActPublish, ActNotifyExpiring:
			if a.Kind == ActPublish {
				d.broadcast(a.Event)
			}
		case ActSealRoots:
			for _, id := range a.RootIDs {
				d.sealRoot(id)
			}
		case ActRestoreRoots:
			for _, id := range a.RootIDs {
				d.restoreRoot(id)
			}
		case ActEndSessions:
			d.endSessions(a)
		case ActAuditCapsules:
			d.goBackground(func() { d.audit(a.Vault) })
		case ActWriteRootsList:
			d.goBackground(d.writeRootsList)
		case ActScrubTTY:
		}
	}
}

// goBackground runs fn tracked by the daemon's wait group.
func (d *daemon) goBackground(fn func()) {
	d.wg.Add(1)
	go func() { defer d.wg.Done(); fn() }()
}

// broadcast queues ev for every interested subscriber; a subscriber whose
// queue is full is dropped (its wrapper then locks locally, SPEC §15.3).
// Folder events carry the folder's factor kinds (CC-40).
func (d *daemon) broadcast(ev ipc.Event) {
	if ev.At.IsZero() {
		ev.At = d.clock.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.withFactorsLocked(&ev)
	for s := range d.subs {
		if s.wants(ev) {
			d.enqueueLocked(s, ev)
		}
	}
}

// sendEnd sends EventEnd only on the subscriptions of the wrapper whose
// session the daemon ends (D71): the subscribing process is the session's
// registered wrapper (measured ProcIDs, so nobody else can receive it). A
// broadcast would end every busy wrapped session of the folder early.
func (d *daemon) sendEnd(s SessionInfo, reason string) {
	if s.WrapperPID.IsZero() {
		return
	}
	ev := ipc.Event{Kind: ipc.EventEnd, SIDs: nonEmpty(s.SID), RootIDs: s.RootIDs, Reason: reason, At: d.clock.Now()}
	d.mu.Lock()
	defer d.mu.Unlock()
	sent := 0
	for sub := range d.subs {
		if sub.wrapper && sub.peer == s.WrapperPID {
			d.enqueueLocked(sub, ev)
			sent++
		}
	}
	if sent == 0 {
		d.logf("end of a wrapped session: its wrapper has no subscription (it locks locally)")
	}
}

// enqueueLocked queues ev for s, dropping s when its queue is full (d.mu
// held).
func (d *daemon) enqueueLocked(s *subscriber, ev ipc.Event) {
	select {
	case s.q <- ev:
	default:
		delete(d.subs, s)
		s.stop()
	}
}

// withFactorsLocked fills Factors of a locked/unlocked/expiring event for
// one folder from the factor cache (d.mu held).
func (d *daemon) withFactorsLocked(ev *ipc.Event) {
	switch ev.Kind {
	case ipc.EventLocked, ipc.EventUnlocked, ipc.EventExpiring:
	default:
		return
	}
	if len(ev.Factors) == 0 && len(ev.RootIDs) == 1 {
		ev.Factors = slices.Clone(d.factors[ev.RootIDs[0]])
	}
}

// heartbeatLoop sends EventHeartbeat to every subscriber each second.
func (d *daemon) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.broadcast(ipc.Event{Kind: ipc.EventHeartbeat, At: d.clock.Now()})
		}
	}
}

// acceptLoop serves connections until the listener closes.
func (d *daemon) acceptLoop(ctx context.Context) {
	for {
		c, err := d.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		d.wg.Add(1)
		go func() { defer d.wg.Done(); d.serveConn(ctx, c) }()
	}
}

// tickLoop polls the console, refreshes session facts, evaluates
// deadlines and the idle-exit rule (SPEC §12.5, §13.1).
func (d *daemon) tickLoop(ctx context.Context, stop context.CancelFunc) {
	t := time.NewTicker(d.o.Tick)
	defer t.Stop()
	var idleSince *instant
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.reloadPolicy(ctx)
		d.pollScreen(ctx)
		d.refreshSessions(ctx)
		d.scanUngated(ctx)
		d.drainQueue()
		d.apply(ctx, Input{Kind: InTick})
		if d.idle() {
			now := d.now()
			if idleSince == nil {
				idleSince = &now
			} else if idleSince.elapsed(now, d.o.IdleExit) {
				d.logf("idle for %v: exiting", d.o.IdleExit)
				stop()
				return
			}
		} else {
			idleSince = nil
		}
	}
}

// idle reports the idle-exit condition: no unlocked vault, no subscriber,
// an empty queue and no pending journal (R19).
func (d *daemon) idle() bool {
	p := d.snap.Load()
	for _, v := range p.snap.Vaults {
		if v.State == VaultUnlocked {
			return false
		}
	}
	d.mu.Lock()
	nsubs := len(d.subs)
	d.mu.Unlock()
	return nsubs == 0 && !hasEntries(d.l.QueueDir, ".json") && !hasEntries(d.l.JournalDir, ".json")
}

// pollScreen reads the console once and feeds lock transitions.
func (d *daemon) pollScreen(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	s, err := d.o.Screen(pctx)
	cancel()
	now := d.now()
	d.mu.Lock()
	d.screenOK = err == nil && s.LockKnown
	if err == nil && s.IdleKnown {
		prev := d.hid
		d.hid = hidSample{known: true, idle: s.HIDIdle, at: now}
		if prev.known && s.HIDIdle < prev.idle {
			d.mu.Unlock()
			d.post(Input{Kind: InHIDActivity})
			d.mu.Lock()
		}
	} else if err == nil {
		d.hid = hidSample{}
	}
	d.mu.Unlock()
	if err != nil || !s.LockKnown {
		return
	}
	locked := d.snap.Load().screenLocked
	switch {
	case s.Locked && !locked:
		d.post(Input{Kind: InScreenLocked})
	case !s.Locked && locked:
		d.post(Input{Kind: InScreenUnlocked})
	}
}

// logf writes a content-free line to the daemon log (stderr, redirected to
// logs/precinto.log by autostart). Only ids, counts and reasons.
func (d *daemon) logf(format string, args ...any) {
	if d.logger != nil {
		d.logger.Printf(format, args...)
	}
}

// effective returns the enforced configuration.
func (d *daemon) effective() config.Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pol.eff
}

// rootPath returns the path of root id in the effective configuration.
func (d *daemon) rootPath(id string) (string, bool) {
	r, ok := d.effective().RootByID(id)
	return r.Path, ok
}

// folder renders a vault id for messages: the ~-shortened root path.
func (d *daemon) folder(id string) string {
	if id == vault.GlobalID {
		return "global"
	}
	p, ok := d.rootPath(id)
	if !ok {
		return id
	}
	if home, err := paths.UserHome(d.o.Env); err == nil {
		return paths.Tilde(home, p)
	}
	return p
}

// sealRoot spawns the keyless seal of a locked folder (SPEC §12.7 step 3).
func (d *daemon) sealRoot(id string) {
	if id == vault.GlobalID {
		d.spawnWorker("sweep", "--lock", "--quiet")
		return
	}
	if p, ok := d.rootPath(id); ok {
		d.spawnWorker("sweep", "--lock", "--root", p)
	}
}

// restoreRoot spawns the background restore after an unlock (SPEC §11.6).
func (d *daemon) restoreRoot(id string) {
	p, ok := d.rootPath(id)
	if !ok {
		return
	}
	n := d.effective().Policy.RestoreRecent
	d.spawnWorker("restore", "--root", p, "--recent", strconv.Itoa(n), "--md", "--history", "--background")
}

// spawnWorker starts `<Exe> args…` detached with an allowlisted
// environment (the daemon never seals or restores in-process).
func (d *daemon) spawnWorker(args ...string) {
	argv := append([]string{d.o.Exe}, args...)
	d.mu.Lock()
	d.spawned = append(d.spawned, argv)
	d.mu.Unlock()
	if !filepath.IsAbs(d.o.Exe) {
		d.logf("cannot spawn %s worker: no absolute executable", args[0])
		return
	}
	id, err := d.o.Spawn(argv, platform.SpawnOptions{Dir: "/", Env: d.workerEnv(), LogPath: d.logPath()})
	if err != nil {
		d.logf("spawn %s worker: %v", args[0], err)
		return
	}
	d.mu.Lock()
	d.workers[id] = true
	if args[0] == "seal" {
		d.queueWorker = id
	}
	d.mu.Unlock()
}

// workerEnv is the allowlisted environment of workers: no agent marker, no
// loader variable, no harness configuration (workers read config, D7.0).
func (d *daemon) workerEnv() []string {
	keep := []string{"HOME", "PATH", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
		paths.EnvXDGDataHome, paths.EnvXDGRuntimeDir, "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"}
	if paths.OverridesAllowed(d.o.Env) {
		keep = append(keep, paths.EnvHome, paths.EnvRuntimeDir)
	}
	var env []string
	for _, k := range keep {
		if v, ok := d.o.Env.Lookup(k); ok {
			env = append(env, k+"="+v)
		}
	}
	sort.Strings(env)
	return env
}

// logPath is the workers' stdout/stderr: the daemon log when its directory
// exists.
func (d *daemon) logPath() string {
	if d.l.LogFile == "" {
		return ""
	}
	if st, err := os.Lstat(filepath.Dir(d.l.LogFile)); err == nil && st.IsDir() {
		return d.l.LogFile
	}
	return ""
}

// drainQueue spawns `precinto seal --queue` while requests wait in the
// queue and no queue worker runs (the daemon drains the queue, §10.6).
func (d *daemon) drainQueue() {
	if !hasEntries(d.l.QueueDir, ".json") {
		return
	}
	now := d.now()
	d.mu.Lock()
	busy := !d.queueWorker.IsZero() && d.procs.Alive(d.queueWorker)
	recent := d.lastQueue.mono != 0 && !d.lastQueue.elapsed(now, queueDrainEvery)
	if busy || recent {
		d.mu.Unlock()
		return
	}
	d.lastQueue = now
	d.mu.Unlock()
	d.spawnWorker("seal", "--queue")
}

// writeRootsList writes roots.list with the effective roots (D22): the
// shim blocks in every folder the daemon protects, pinned ones included.
func (d *daemon) writeRootsList() {
	eff := d.effective()
	if err := config.WriteRootsList(d.l.RootsList, eff); err != nil {
		d.logf("write roots.list: %v", err)
	}
}

// setAttention records or clears an attention item.
func (d *daemon) setAttention(a ipc.Attention, on bool) {
	key := a.Code + "\x00" + a.Folder + "\x00" + strconv.Itoa(a.PID)
	d.mu.Lock()
	defer d.mu.Unlock()
	if on {
		d.attention[key] = a
	} else {
		delete(d.attention, key)
	}
}

// cleanRepairScratch removes vault_repair dry-run scratch directories a
// crashed daemon left in the run directory (copies of public vault
// metadata only).
func (d *daemon) cleanRepairScratch() {
	ents, err := os.ReadDir(d.l.RunDir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), repairScratchPrefix) {
			_ = os.RemoveAll(filepath.Join(d.l.RunDir, e.Name()))
		}
	}
}
