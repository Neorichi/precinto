package agent

import (
	"context"
	"os"
	"path/filepath"
	"sort"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/vault"
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

// subscribe turns the connection into an event stream (SPEC §13.3): an
// acknowledgement, the current state of the subscribed folders, then every
// matching event and a heartbeat each second. Any request on the stream
// ends it.
func (d *daemon) subscribe(ctx context.Context, cs *connState, req ipc.Request) {
	r := req.Subscribe
	sub := &subscriber{conn: cs.c, id: req.ID, roots: dedupe(r.RootIDs), sid: r.SID,
		q: make(chan ipc.Event, subscriberQueue), done: make(chan struct{})}
	if err := cs.c.WriteResponse(ipc.Response{ID: req.ID, OK: true}); err != nil {
		return
	}
	v := d.view()
	for _, id := range sub.roots {
		vs, ok := v.vaults[id]
		ev := ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{id}, At: v.now, Reason: "start"}
		if ok && vs.State == VaultUnlocked {
			ev = ipc.Event{Kind: ipc.EventUnlocked, RootIDs: []string{id}, At: v.now, Deadline: vs.AbsDeadline}
		} else if ok {
			ev.Reason = vs.Reason
		}
		sub.q <- ev
	}
	d.mu.Lock()
	d.subs[sub] = struct{}{}
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.subs, sub)
		d.mu.Unlock()
		sub.stop()
	}()
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
// own environment (D64): it and its ancestors are ignored, so a suite run
// inside an agent session still exercises the human paths below it.
// Production builds never read the variable.
func (d *daemon) ancestry(peer platform.Peer) []platform.ProcInfo {
	anc, err := platform.Ancestors(d.procs, peer.PID, maxAncestry)
	if err != nil {
		return nil
	}
	if stop, ok := testAncestryStop(d.o.Env); ok {
		for i, a := range anc {
			if a.ID.PID == stop.PID && a.ID.StartUS == stop.StartUS && (a.ID.BootID == "" || stop.BootID == "" || a.ID.BootID == stop.BootID) {
				return anc[:i]
			}
		}
	}
	return anc
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

// sessionRoots returns the folders of the session an agent-context peer
// runs in: the sessions of its verified harness ancestor, and the folder
// containing that process's working directory.
func (d *daemon) sessionRoots(f peerFacts) []string {
	if !f.agent || f.harnessProc.ID.IsZero() {
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

func (d *daemon) loadFactors(id string) {
	g := false
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
		}
	}
	d.mu.Lock()
	d.gui[id] = g
	d.mu.Unlock()
}

// pinentryAvailable reports whether a pinentry program is on the PATH.
func (d *daemon) pinentryAvailable() bool {
	for _, n := range pinentryNames {
		if _, err := paths.LookPath(d.o.Env, n); err == nil {
			return true
		}
	}
	return false
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
