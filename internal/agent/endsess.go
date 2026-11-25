package agent

import (
	"context"
	"errors"
	"slices"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
)

// staleSession is how long a session known only from hook events (no
// process) is kept without hearing from it.
const staleSession = 12 * time.Hour

// registryStartSlack is how far a registry entry's startedAt may lie after
// the process start and still name that process (E2, D18).
const registryStartSlack = 2 * time.Second

// claudeHomes returns the registered Claude config dirs (SPEC §7.0): the
// daemon never derives harness homes from its own environment.
func (d *daemon) claudeHomes() []string {
	var out []string
	for _, h := range d.effective().Harness[string(harness.ClaudeCode)].Homes {
		if h.Dir != "" {
			out = append(out, h.Dir)
		}
	}
	return out
}

// registryEntries reads every registered home's registry, by pid. ok is
// false when a registry could not be read (callers then trust nothing).
func (d *daemon) registryEntries() (map[int]claude.RegistryEntry, []string, bool) {
	byPID := map[int]claude.RegistryEntry{}
	ok := true
	homes := d.claudeHomes()
	for _, h := range homes {
		es, err := d.deps.registry(h)
		if err != nil {
			ok = false
			continue
		}
		for _, e := range es {
			byPID[e.PID] = e
		}
	}
	return byPID, homes, ok
}

// registryBusy is RegistryEntry.Busy: status busy and nothing pending
// (a permission or elicitation dialog counts as idle, HA7).
func registryBusy(e claude.RegistryEntry) bool { return e.Status == "busy" && e.WaitingFor == "" }

// refreshSessions drops sessions whose process exited and refreshes busy
// from Claude's registry (authoritative when present, SPEC §12.4).
func (d *daemon) refreshSessions(ctx context.Context) {
	d.pruneProcFacts()
	snap := d.snap.Load().snap
	var reg map[int]claude.RegistryEntry
	now := d.now()
	for _, s := range snap.Sessions {
		if s.Info.Proc.IsZero() {
			// Known only from hook events: forget it after a long silence.
			d.mu.Lock()
			seen, ok := d.sessSeen[s.Info.SID]
			if !ok {
				d.sessSeen[s.Info.SID] = now // first sight: start the clock
			}
			d.mu.Unlock()
			if ok && seen.elapsed(now, staleSession) {
				info := s.Info
				d.post(Input{Kind: InUnregister, SID: info.SID, Session: &info})
				d.mu.Lock()
				delete(d.sessSeen, s.Info.SID)
				d.mu.Unlock()
			}
			continue
		}
		if !d.procs.Alive(s.Info.Proc) {
			info := s.Info
			d.post(Input{Kind: InUnregister, SID: info.SID, Session: &info})
			continue
		}
		if s.Info.Harness != string(harness.ClaudeCode) || s.Info.SID == "" {
			continue
		}
		if reg == nil {
			reg, _, _ = d.registryEntries()
		}
		if e, ok := reg[s.Info.Proc.PID]; ok && e.Valid && e.SessionID == s.Info.SID {
			if b := registryBusy(e); b != s.Busy {
				d.post(Input{Kind: InBusy, SID: s.Info.SID, Busy: b})
			}
		}
	}
}

// pruneProcFacts forgets per-process facts of processes that are gone: a
// ProcID never comes back, so nothing can be signalled or attributed by
// mistake, and the maps stay bounded over a long-running daemon.
func (d *daemon) pruneProcFacts() {
	d.mu.Lock()
	ids := map[platform.ProcID]bool{}
	for id := range d.versions {
		ids[id] = true
	}
	for id := range d.signalable {
		ids[id] = true
	}
	for id := range d.hookSeen {
		ids[id] = true
	}
	d.mu.Unlock()
	var gone []platform.ProcID
	for id := range ids {
		if !d.procs.Alive(id) {
			gone = append(gone, id)
		}
	}
	if len(gone) == 0 {
		return
	}
	d.mu.Lock()
	for _, id := range gone {
		delete(d.versions, id)
		delete(d.signalable, id)
		delete(d.hookSeen, id)
	}
	d.mu.Unlock()
}

// scanUngated looks for harness processes in locked folders that no hook
// and no registration announced within the hook-presence window (SPEC
// §12.6, D52). Interactive Claude sessions feed the machine (they are
// ended at lock); every other match is reported, never signalled (D57).
func (d *daemon) scanUngated(ctx context.Context) {
	v := d.view()
	eff := d.effective()
	var locked []string
	for _, r := range eff.Roots {
		if vs, ok := v.vaults[r.ID]; !ok || vs.State != VaultUnlocked {
			locked = append(locked, r.ID)
		}
	}
	if len(locked) == 0 {
		d.mu.Lock()
		for id := range d.ungated {
			delete(d.ungated, id)
		}
		d.mu.Unlock()
		d.clearUngatedAttention(nil)
		return
	}
	procs, err := d.procs.List()
	if err != nil {
		return
	}
	now := d.now()
	known := map[platform.ProcID]bool{}
	for _, s := range v.sessions {
		if s.Info.Registered || s.Info.HooksSeen || s.Info.Wrapper {
			known[s.Info.Proc] = true
		}
	}
	var reg map[int]claude.RegistryEntry
	var homes []string
	regOK := true
	found := map[platform.ProcID]bool{}
	for _, p := range procs {
		if ctx.Err() != nil {
			return
		}
		h, ok := harnessOfProc(d.invs, eff, p)
		if !ok || p.State == platform.StateZombie || known[p.ID] {
			continue
		}
		d.mu.Lock()
		_, hooked := d.hookSeen[p.ID]
		d.mu.Unlock()
		if hooked {
			continue // a hook event or registration announced it
		}
		if started := platform.StartTime(p.ID); !started.IsZero() && now.wall.Sub(started) < hookPresenceWindow {
			continue // give its hooks time to announce it
		}
		cwd, err := d.procs.Cwd(p.ID)
		if errors.Is(err, platform.ErrNotSame) {
			continue // gone
		}
		var root string
		if cwd != "" {
			for _, id := range d.rootsOf(nil, cwd) {
				if slices.Contains(locked, id) {
					root = id
					break
				}
			}
			if root == "" {
				continue // not in a locked folder
			}
		}
		found[p.ID] = true
		if h == string(harness.ClaudeCode) && root != "" {
			if reg == nil {
				reg, homes, regOK = d.registryEntries()
			}
			if regOK && d.interactiveClaude(p, reg[p.ID.PID], homes) {
				d.mu.Lock()
				d.signalable[p.ID] = true
				delete(d.ungated, p.ID)
				d.mu.Unlock()
				info := SessionInfo{Harness: string(h), SID: reg[p.ID.PID].SessionID, Proc: p.ID, RootIDs: []string{root}, TTY: p.TTY}
				d.post(Input{Kind: InUngated, Session: &info})
				continue
			}
		}
		why := "no hooks"
		if cwd == "" {
			why = "unknown working directory"
			root = locked[0]
		}
		d.reportUngated(p, h, root, why)
	}
	d.mu.Lock()
	for id := range d.ungated {
		if !found[id] {
			delete(d.ungated, id)
		}
	}
	d.mu.Unlock()
	d.clearUngatedAttention(found)
}

// interactiveClaude reports whether the registry proves p is an
// interactive, foreground Claude session: its entry names that pid with a
// matching start, kind interactive, entrypoint cli, and no job record marks
// the session background (D52, D25).
func (d *daemon) interactiveClaude(p platform.ProcInfo, e claude.RegistryEntry, homes []string) bool {
	if !e.Valid || e.PID != p.ID.PID || e.SessionID == "" || e.Kind != "interactive" || e.Entrypoint != "cli" {
		return false
	}
	// The entry belongs to this incarnation: the process started no later
	// than startedAt + 2 s (E2), so a stale file of a reused pid never
	// qualifies. This decides a signal, so the start stays the strict one
	// (the current btime: after a WSL 2 host sleep a later start, never an
	// earlier one), not D157's earliest: a session it no longer matches is
	// reported, never signalled.
	start := platform.StartTime(p.ID) // wall clock, comparable with startedAt (D66)
	if e.StartedAt.IsZero() || start.IsZero() || start.After(e.StartedAt.Add(registryStartSlack)) {
		return false
	}
	for _, h := range homes {
		jobs, err := d.deps.jobs(h)
		if err != nil {
			return false // unreadable jobs: cannot rule out a background session
		}
		for _, j := range jobs {
			if !j.Valid || j.SessionID == e.SessionID {
				return false
			}
		}
	}
	return true
}

// reportUngated records a report-only match (C9.ungated); Harness is the
// {harness} of the message, the command the user runs it with (CC-48).
func (d *daemon) reportUngated(p platform.ProcInfo, h, root, why string) {
	d.mu.Lock()
	d.ungated[p.ID] = ungatedMatch{proc: p, harness: h, rootID: root, why: why}
	d.mu.Unlock()
	cmd := harnessCommand(h)
	d.setAttention(ipc.Attention{Code: ipc.AttnUngatedSession, Folder: d.folder(root), PID: p.ID.PID, Detail: why,
		Fix: "precinto run " + cmd, Harness: cmd}, true)
}

// clearUngatedAttention removes ungated-session items of processes no
// longer found (all when found is nil).
func (d *daemon) clearUngatedAttention(found map[platform.ProcID]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	alive := map[int]bool{}
	for id := range found {
		alive[id.PID] = true
	}
	for k, a := range d.attention {
		if a.Code == ipc.AttnUngatedSession && !alive[a.PID] {
			delete(d.attention, k)
		}
	}
}

// endSessions performs ActEndSessions (SPEC §12.7 step 4, D57): a wrapped
// session gets EventEnd and its wrapper ends its own child; an unwrapped
// Claude process the daemon registered or found itself is ended with
// ProcID-verified signals; everything else is reported, never signalled.
func (d *daemon) endSessions(a Action) {
	for _, s := range a.Sessions {
		switch {
		case s.Background:
		case s.Wrapper:
			d.sendEnd(s, a.Reason)
		case s.Harness == string(harness.ClaudeCode):
			s := s
			d.goBackground(func() { d.endUnwrapped(s, a.Grace, ui.Reason(a.Reason)) })
		default:
			d.logf("not ending a %s session without a wrapper (reported)", s.Harness)
		}
	}
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// endUnwrapped ends an unwrapped Claude process: SIGTERM, wait for the
// grace, SIGKILL, then SIGKILL of its descendants found by PPID walk before
// the first signal (never by session or process group: it shares the
// user's terminal session, R11). Every signal is ProcID-verified.
func (d *daemon) endUnwrapped(s SessionInfo, grace time.Duration, reason ui.Reason) {
	d.mu.Lock()
	ok := d.signalable[s.Proc]
	d.mu.Unlock()
	if !ok || s.Proc.IsZero() {
		d.logf("not ending an unverified session process (ledger evidence only)")
		return
	}
	p, err := d.procs.Lookup(s.Proc.PID)
	if err != nil || p.ID != s.Proc || p.State == platform.StateZombie {
		return
	}
	if !matchHarness(d.invs, d.effective(), string(harness.ClaudeCode), p) {
		return // the pid no longer runs Claude: never signal it
	}
	desc, _ := platform.Descendants(d.procs, s.Proc)
	_ = d.deps.signal(s.Proc, syscall.SIGTERM)
	if !d.waitGone(s.Proc, grace) {
		if d.ctx.Err() != nil {
			return // the daemon stops: the session stays paused (gated)
		}
		_ = d.deps.signal(s.Proc, syscall.SIGKILL)
		d.waitGone(s.Proc, 5*time.Second)
	}
	for _, c := range desc {
		if d.procs.Alive(c.ID) {
			_ = d.deps.signal(c.ID, syscall.SIGKILL)
		}
	}
	if d.procs.Alive(s.Proc) {
		return
	}
	eff := d.effective()
	tty := p.TTY
	if tty == "" {
		tty = s.TTY
	}
	if tty != "" {
		folder := ""
		if len(s.RootIDs) > 0 {
			folder = d.folder(s.RootIDs[0])
		}
		banner := ui.Format(ui.MsgEnded, ui.Vars{Folder: folder, N: 1, Reason: reason, Idle: idleSoft(eff.Policy),
			Limit: ClampTTL(eff.Policy, 0), Resume: "claude --resume " + s.SID})
		_ = d.deps.scrub(tty, platform.ScrubOptions{Clear: eff.Policy.ClearTerminalOnEnd, Banner: banner})
	}
	for _, id := range s.RootIDs {
		d.sealRoot(id)
	}
	info := s
	d.post(Input{Kind: InUnregister, SID: info.SID, Session: &info})
}

// waitGone waits up to d for id to exit on the daemon's process table (or
// until the daemon stops).
func (d *daemon) waitGone(id platform.ProcID, wait time.Duration) bool {
	ctx, cancel := context.WithTimeout(d.ctx, wait)
	defer cancel()
	return d.deps.waitExit(ctx, id) == nil || !d.procs.Alive(id)
}

// audit checks capsules sealed to vault id since its last audit (D5): a
// capsule whose recipients fingerprint is not the vault's, or whose header
// the vault key does not open, is listed as exposed. The watermark lives
// in vault.toml (Store.MarkAudited, CC-07), so it survives a daemon
// restart: it moves to the start of a clean audit only. An audit that
// found an exposed capsule (or could not finish) leaves it where it was,
// so the exposure is reported again at every unlock and vault repair
// still lists it. A last_audit later than now counts as zero: a forged
// future value never hides a capsule.
func (d *daemon) audit(id string) {
	if !d.vaultExists(id) {
		return
	}
	start := d.clock.Now()
	fpr, err := d.deps.vaults.fingerprint(id)
	if err != nil {
		return
	}
	since := time.Time{}
	if meta, err := d.deps.vaults.meta(id); err == nil {
		since = meta.LastAudit
	}
	if since.After(start) {
		since = time.Time{}
	}
	entries, err := d.deps.logged()
	if err != nil {
		return
	}
	exposed := 0
	for _, e := range entries {
		if e.VaultID != id || e.Deleted || !e.SealedAt.After(since) {
			continue
		}
		if e.RecipientsFpr != fpr {
			exposed++
			continue
		}
		hdr, sha, err := d.deps.readHeader(e.Path)
		if err != nil || sha != e.HeaderSHA256 {
			continue // missing or changed: quarantine's business, not an exposure
		}
		if key, err := d.deps.keyring.FileKey(id, hdr); err != nil {
			exposed++
		} else {
			key.Destroy()
		}
	}
	if exposed > 0 {
		d.setAttention(ipc.Attention{Code: ipc.AttnExposed, Folder: d.folder(id), Count: exposed, Fix: "precinto status"}, true)
		return
	}
	if !start.After(since) {
		return // nothing to move (a clock behind the watermark)
	}
	if err := d.deps.vaults.markAudited(id, start); err != nil {
		d.logf("audit watermark of %s not saved: %v", id, err)
	}
}
