package agent

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/vault"
)

// status builds the daemon side of `precinto status` (SPEC §16.4).
func (d *daemon) status() ipc.StatusResp {
	v := d.view()
	eff := d.effective()
	d.mu.Lock()
	resp := ipc.StatusResp{
		Version: d.o.Version, PID: os.Getpid(), Started: d.started,
		ScreenWatch:   d.screenOK,
		PendingPolicy: pendingText(d.pol.pending),
		Vaults:        []ipc.VaultStatus{},
		Sessions:      []ipc.SessionStatus{},
		Attention:     []ipc.Attention{},
	}
	for _, a := range d.attention {
		resp.Attention = append(resp.Attention, a)
	}
	ungated := make([]ungatedMatch, 0, len(d.ungated))
	for _, u := range d.ungated {
		ungated = append(ungated, u)
	}
	factors := make(map[string][]string, len(d.factors))
	for id, k := range d.factors {
		factors[id] = slices.Clone(k)
	}
	versions := make(map[platform.ProcID]string, len(d.versions))
	for id, v := range d.versions {
		versions[id] = v
	}
	d.mu.Unlock()
	if st, err := os.Stat(d.l.SweepLast); err == nil {
		resp.LastSweep = st.ModTime().UTC()
	}
	for _, id := range vaultIDs(eff) {
		vs, ok := v.vaults[id]
		st := ipc.VaultStatus{VaultID: id, State: string(VaultLocked), Reason: "start"}
		if r, found := eff.RootByID(id); found {
			st.RootPath = r.Path
		}
		if ok {
			st.State, st.Reason, st.Since = string(vs.State), vs.Reason, vs.Since
			st.IdleDeadline, st.AbsDeadline, st.LastHuman = vs.IdleDeadline, vs.AbsDeadline, vs.LastHuman
		}
		if st.State == string(VaultLocked) && d.limiter.inFlight(id) {
			st.State = vaultUnlocking // a single-flight unlock is in progress (CC-32)
		}
		st.Factors = factors[id]
		resp.Vaults = append(resp.Vaults, st)
	}
	keys := make([]string, 0, len(v.sessions))
	for k := range v.sessions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := v.sessions[k]
		resp.Sessions = append(resp.Sessions, ipc.SessionStatus{
			Harness: s.Info.Harness, SID: s.Info.SID, Proc: s.Info.Proc, RootIDs: s.Info.RootIDs,
			State: string(s.State), Busy: s.Busy, Wrapper: s.Info.Wrapper, Background: s.Info.Background,
			HooksSeen: s.Info.HooksSeen, Registered: s.Info.Registered, TTY: s.Info.TTY,
			Version: versions[s.Info.Proc],
		})
	}
	sort.Slice(ungated, func(i, j int) bool { return ungated[i].proc.ID.PID < ungated[j].proc.ID.PID })
	for _, u := range ungated {
		state := string(SessionPaused)
		resp.Sessions = append(resp.Sessions, ipc.SessionStatus{Harness: u.harness, Proc: u.proc.ID, RootIDs: []string{u.rootID},
			State: state, Registered: false, TTY: u.proc.TTY})
	}
	sort.Slice(resp.Attention, func(i, j int) bool {
		a, b := resp.Attention[i], resp.Attention[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Folder != b.Folder {
			return a.Folder < b.Folder
		}
		return a.PID < b.PID
	})
	return resp
}

// vaultUnlocking is VaultStatus.State while a single-flight unlock of a
// locked vault is in progress.
const vaultUnlocking = "unlocking"

// maxSubscribeRoots bounds the folders of one subscription.
const maxSubscribeRoots = 256

// subscribe turns the connection into an event stream (SPEC §13.3, D71):
// an acknowledgement, one locked or unlocked event per subscribed folder,
// then every matching event, the end events addressed to this wrapper and
// a heartbeat each second. The initial events are queued in the same
// critical section that registers the subscriber, from a snapshot
// published before any event goes out, so no state change is missed; the
// acknowledgement goes out only after that registration, so a client whose
// Subscribe returned is registered: a lock right after it is an event of
// the stream, never folded into the initial state (D153). Any request on
// the stream ends it.
func (d *daemon) subscribe(ctx context.Context, cs *connState, req ipc.Request) {
	r := req.Subscribe
	roots := dedupe(r.RootIDs)
	if len(roots) > maxSubscribeRoots {
		roots = roots[:maxSubscribeRoots] // bounded: one queued initial event each
	}
	sub := &subscriber{conn: cs.c, id: req.ID, roots: roots, sid: r.SID,
		peer: cs.peer.Proc.ID, wrapper: r.Wrapper,
		q: make(chan ipc.Event, subscriberQueue+len(roots)), done: make(chan struct{})}
	d.mu.Lock()
	v := d.view()
	for _, id := range sub.roots {
		vs, ok := v.vaults[id]
		ev := ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{id}, At: v.now, Reason: "start"}
		if ok && vs.State == VaultUnlocked {
			ev = ipc.Event{Kind: ipc.EventUnlocked, RootIDs: []string{id}, At: v.now, Deadline: vs.AbsDeadline}
		} else if ok {
			ev.Reason = vs.Reason
		}
		d.withFactorsLocked(&ev)
		sub.q <- ev
	}
	d.subs[sub] = struct{}{}
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.subs, sub)
		d.mu.Unlock()
		sub.stop()
	}()
	if err := cs.c.WriteResponse(ipc.Response{ID: req.ID, OK: true}); err != nil {
		return
	}
	d.goBackground(func() {
		_, sec, _ := cs.c.ReadRequest() // EOF, or a request a stream does not take
		destroyAll(sec)
		sub.stop()
	})
	for {
		select {
		case ev := <-sub.q:
			if err := cs.c.WriteResponse(ipc.Response{ID: req.ID, OK: true, Event: &ev}); err != nil {
				return
			}
		case <-sub.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

// ancestry returns the peer's ancestors (nearest first) from the daemon's
// process table; unknown ancestry is empty. In a -tags testing daemon the
// walk ends at the process named by paths.TestAncestryStop of the daemon's
// own environment (D64), exactly like ui.AgentContext: it and its
// ancestors are ignored (peerIsStop reports that the peer itself is that
// process), so a suite run inside an agent session still exercises the
// human paths below it, while a harness below the stop is still found.
// Env markers and the no-controlling-terminal rule still apply. Production
// builds never read the variable.
func (d *daemon) ancestry(peer platform.Peer) (anc []platform.ProcInfo, peerIsStop bool) {
	anc, err := platform.Ancestors(d.procs, peer.PID, maxAncestry)
	if err != nil {
		return nil, false
	}
	if stop, ok := testAncestryStop(d.o.Env); ok {
		if sameIncarnation(peer.Proc.ID, stop) {
			return nil, true
		}
		for i, a := range anc {
			if sameIncarnation(a.ID, stop) {
				return anc[:i], false
			}
		}
	}
	return anc, false
}

// sameIncarnation compares a measured ProcID with the D64 stop; the boot id
// counts only when both carry one (a parsed "PID:START" names this boot).
func sameIncarnation(a, stop platform.ProcID) bool {
	return a.PID == stop.PID && a.StartUS == stop.StartUS && (a.BootID == "" || stop.BootID == "" || a.BootID == stop.BootID)
}

// testAncestryStop parses paths.TestAncestryStop (D64; ok=false outside
// -tags testing builds).
func testAncestryStop(e paths.Env) (platform.ProcID, bool) {
	v, ok := paths.TestAncestryStop(e)
	if !ok {
		return platform.ProcID{}, false
	}
	id, err := platform.ParseProcID(v)
	return id, err == nil
}

// peerFacts measures who asks (D28, D59, D64): the peer's ancestry in the
// daemon's own process table, cut at the testing-build stop, and the
// agent markers the client sent about itself (CC-11), which can only add
// restrictions.
func (d *daemon) peerFacts(peer platform.Peer, markers []string) peerFacts {
	anc, peerIsStop := d.ancestry(peer)
	return factsOf(peer, anc, peerIsStop).withMarkers(markers)
}

// sessionRoots returns the folders of the session an agent-context peer
// runs in: the sessions of its verified harness ancestor, and the folder
// containing that process's working directory (never the peer's own: an
// agent could cd anywhere). A peer that is an agent context only by its
// own markers has no harness the daemon can see; its session is then the
// folder of its own working directory (the claim only ever restricts it).
func (d *daemon) sessionRoots(f peerFacts, peer platform.Peer) []string {
	if !f.agent {
		return nil
	}
	if f.harnessProc.ID.IsZero() {
		if !f.markers || peer.Proc.ID.IsZero() {
			return nil
		}
		if cwd, err := d.procs.Cwd(peer.Proc.ID); err == nil && cwd != "" {
			return d.rootsOf(nil, cwd)
		}
		return nil
	}
	var roots []string
	for _, s := range d.snap.Load().snap.Sessions {
		if s.Info.Proc == f.harnessProc.ID {
			roots = append(roots, s.Info.RootIDs...)
		}
	}
	if cwd, err := d.procs.Cwd(f.harnessProc.ID); err == nil && cwd != "" {
		roots = append(roots, d.rootsOf(nil, cwd)...)
	}
	return dedupe(roots)
}

// vaultExists reports whether vault id has a vault.toml.
func (d *daemon) vaultExists(id string) bool {
	_, err := os.Lstat(filepath.Join(d.l.VaultDir(id), "vault.toml"))
	return err == nil
}

// guiFactor reports (from a cache filled in the background) whether vault
// id has a factor that can prompt without a terminal: Secure Enclave, a
// plugin or passphrase factor marked GUI, or any factor when pinentry is
// installed (D27).
func (d *daemon) guiFactor(id string) bool {
	d.mu.Lock()
	g, ok := d.gui[id]
	d.mu.Unlock()
	if ok {
		return g
	}
	d.goBackground(func() { d.loadFactors(id) })
	return false
}

// unlockOrder is the order in which an unlock picks a factor (vault
// Unwrap with no factor named): Secure Enclave, plugin, passphrase.
var unlockOrder = []vault.FactorKind{vault.FactorSE, vault.FactorPlugin, vault.FactorPassphrase}

// loadFactors reads vault id's factors once into the caches: whether one
// prompts without a terminal (D27), and the enrolled kinds in unlock
// order, never "recovery" (Event/VaultStatus.Factors, CC-40).
func (d *daemon) loadFactors(id string) {
	g := false
	var kinds []string
	if d.vaultExists(id) {
		if meta, err := d.deps.vaults.meta(id); err == nil {
			pin := d.pinentryAvailable()
			for _, f := range meta.Factors {
				switch {
				case f.Kind == vault.FactorRecovery:
				case f.Kind == vault.FactorSE, f.GUI:
					g = true
				case pin:
					g = true
				}
			}
			for _, k := range unlockOrder {
				if slices.ContainsFunc(meta.Factors, func(f vault.Factor) bool { return f.Kind == k }) {
					kinds = append(kinds, string(k))
				}
			}
		}
	}
	d.mu.Lock()
	d.gui[id] = g
	if len(kinds) > 0 {
		d.factors[id] = kinds
	} else {
		delete(d.factors, id)
	}
	d.mu.Unlock()
}

// refreshFactors reloads vault id's factor caches now (start, vault
// creation, factor enrollment, repair).
func (d *daemon) refreshFactors(id string) { d.loadFactors(id) }

// factorKinds returns vault id's enrolled factor kinds in unlock order
// (never "recovery"), loading the cache when it has none yet.
func (d *daemon) factorKinds(id string) []string {
	d.mu.Lock()
	kinds, ok := d.factors[id]
	d.mu.Unlock()
	if !ok {
		d.loadFactors(id)
		d.mu.Lock()
		kinds = d.factors[id]
		d.mu.Unlock()
	}
	return slices.Clone(kinds)
}

// pinentryAvailable reports whether a pinentry program the daemon would
// run is on the PATH (D97: a trusted one only) and has somewhere to draw:
// pinentry-mac needs nothing, the others a display among the dialog
// endpoints the daemon trusts (D139).
func (d *daemon) pinentryAvailable() bool {
	prog, err := findPinentry(d.o.Env)
	if err != nil {
		return false
	}
	return pinentryCanDraw(prog, dialogEnv(d.o.Env))
}

// bootstrap feeds the sessions the ledger shows as running (SPEC §13.1).
// They are liveness evidence only: never signalled until they register or
// the scan finds them (SPEC §9.1).
func (d *daemon) bootstrap() {
	for _, h := range []harness.ID{harness.ClaudeCode, harness.Codex} {
		sessions, err := d.deps.ledgerList(string(h))
		if err != nil {
			d.logf("bootstrap from the %s ledger: %v", h, err)
			continue
		}
		for _, s := range sessions {
			if len(s.RootIDs) == 0 || s.CurrentProc.IsZero() || !d.procs.Alive(s.CurrentProc) {
				continue
			}
			info := SessionInfo{Harness: string(h), SID: s.SID, Proc: s.CurrentProc, RootIDs: s.RootIDs,
				Background: s.Background, HooksSeen: s.HooksSeen}
			d.mu.Lock()
			d.taint[s.SID] = dedupe(append(d.taint[s.SID], s.RootIDs...))
			d.mu.Unlock()
			d.post(Input{Kind: InRegister, Session: &info})
		}
	}
}
