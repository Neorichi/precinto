package agent

import (
	"slices"
	"sort"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

// Timing constants of the lock model that are not policy keys.
const (
	// expiryNotice is how long before max_unlock the user is warned (C8).
	expiryNotice = 10 * time.Minute
	// compactionWait bounds how long ending a session waits for an
	// in-flight compaction without --force (SPEC §7.1.6).
	compactionWait = 5 * time.Minute
	// Harness SessionEnd hook budgets (HOOKS-IO §1), for KillGrace.
	claudeSessionEndBudget = 1500 * time.Millisecond
	codexSessionEndBudget  = 3 * time.Second
)

// instant is one reading of both clocks.
type instant struct {
	wall time.Time
	mono time.Duration
}

// since reports how long ago i was on each clock (a negative wall delta, a
// clock stepped back, counts as zero).
func (i instant) since(now instant) (wall, mono time.Duration) {
	wall = now.wall.Sub(i.wall)
	if wall < 0 {
		wall = 0
	}
	return wall, now.mono - i.mono
}

// elapsed reports whether d has passed since i on either clock (R16, IM15).
func (i instant) elapsed(now instant, d time.Duration) bool {
	w, m := i.since(now)
	return w >= d || m >= d
}

// vaultState is one vault's key state.
type vaultState struct {
	state     VaultState
	reason    ui.Reason
	since     time.Time
	lastHuman instant
	unlocked  instant // when the current grant began
	ttl       time.Duration
	expiring  bool // C8 sent for the current grant
}

// absDeadline returns the absolute deadline of an unlocked vault.
func (v *vaultState) absDeadline() time.Time { return v.unlocked.wall.Add(v.ttl) }

// sessionState is one live session.
type sessionState struct {
	info        SessionInfo
	state       SessionState
	busy        bool
	busyAtLock  bool
	strict      bool // paused by a manual lock without --let-finish: no busy grace
	lockedAt    instant
	hasLocked   bool
	lastHook    instant
	compacting  bool
	ungated     bool // found by the scan: cannot be paused (D52)
	ended       bool // SessionEnd seen (the process may still run, R8)
	pendingEnd  bool // end requested while compacting (waits ≤ compactionWait)
	pendingAt   instant
	endReason   ui.Reason
	endRequired bool // ActEndSessions already emitted
}

// originKey pairs a prompt gate with its later activity.
type originKey struct{ sid, prompt string }

// originRec is the origin the daemon computed at gate time (D54).
type originRec struct {
	origin ipc.PromptOrigin
	at     instant
}

// screenState tracks the console lock (D24).
type screenState struct {
	locked bool
	since  instant
}

// newMachine builds the machine (NewMachine).
func newMachine(p config.Policy, c platform.Clock) *Machine {
	m := &Machine{
		policy:   p,
		clock:    c,
		vaults:   map[string]*vaultState{},
		sessions: map[string]*sessionState{},
		origins:  map[originKey]originRec{},
	}
	m.start = m.now()
	return m
}

func (m *Machine) now() instant { return instant{wall: m.clock.Now(), mono: m.clock.Mono()} }

// declare adds vaults the configuration names, locked since the daemon
// started (ReasonStart). Already known vaults are left alone.
func (m *Machine) declare(ids ...string) {
	now := m.now()
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := m.vaults[id]; !ok {
			m.vaults[id] = &vaultState{state: VaultLocked, reason: ui.ReasonStart, since: now.wall, lastHuman: m.start}
		}
	}
}

// vault returns the state of id, creating it locked if unknown.
func (m *Machine) vault(id string) *vaultState {
	v, ok := m.vaults[id]
	if !ok {
		v = &vaultState{state: VaultLocked, reason: ui.ReasonStart, since: m.clock.Now(), lastHuman: m.start}
		m.vaults[id] = v
	}
	return v
}

// unlocked reports whether id is known and unlocked.
func (m *Machine) unlocked(id string) bool {
	v, ok := m.vaults[id]
	return ok && v.state == VaultUnlocked
}

// sessionKey is the map key of a session: its sid, or its process while
// the sid is not known yet (wrapper launch).
func sessionKey(info SessionInfo) string {
	if info.SID != "" {
		return info.SID
	}
	return "proc:" + info.Proc.String()
}

// apply implements Machine.Apply.
func (m *Machine) apply(in Input) []Action {
	now := m.now()
	var acts []Action
	switch in.Kind {
	case InUnlock:
		acts = m.unlock(now, in)
	case InLock:
		acts = m.manualLock(now, in)
	case InActivity:
		m.activity(now, in)
	case InGateOrigin:
		if in.SID != "" && in.PromptID != "" {
			m.origins[originKey{in.SID, in.PromptID}] = originRec{origin: in.Origin, at: now}
		}
	case InRegister:
		acts = m.register(now, in.Session, false)
	case InUngated:
		acts = m.register(now, in.Session, true)
	case InUnregister:
		m.unregister(in)
	case InBusy:
		if s := m.sessions[in.SID]; s != nil {
			s.busy = in.Busy
			if in.Busy {
				s.lastHook = now
			}
		}
	case InScreenLocked:
		if !m.screen.locked {
			m.screen = screenState{locked: true, since: now}
		}
		if m.policy.LockOnScreenLock {
			acts = m.lockAll(now, ui.ReasonScreen, false)
		}
	case InScreenUnlocked:
		// Advisory only: an OS event never unlocks (D24, I6).
		m.screen = screenState{}
	case InHIDActivity:
		// Evidence for prompt origins only (D37): never moves the idle clock.
	case InJump:
		acts = m.lockAll(now, ui.ReasonSleep, false)
	case InPolicy:
		if in.Policy != nil {
			m.policy = *in.Policy
		}
		// The daemon passes the configuration's vaults along: folders new
		// to the machine start locked.
		m.declare(in.Vaults...)
	case InTick:
	}
	return append(acts, m.tick(now)...)
}

// unlock grants every vault of in.Vaults for ClampTTL(in.TTL). A vault that
// is already unlocked keeps its absolute deadline unless Extend.
func (m *Machine) unlock(now instant, in Input) []Action {
	var acts []Action
	for _, id := range dedupe(in.Vaults) {
		v := m.vault(id)
		v.lastHuman = now // the unlock itself is fresh user presence
		if v.state == VaultUnlocked && !in.Extend {
			continue
		}
		wasLocked := v.state == VaultLocked
		v.state, v.reason = VaultUnlocked, ""
		v.unlocked, v.ttl, v.expiring = now, ClampTTL(m.policy, in.TTL), false
		if wasLocked {
			v.since = now.wall
		}
		acts = append(acts, Action{Kind: ActPublish, Vault: id, RootIDs: []string{id},
			Event: ipc.Event{Kind: ipc.EventUnlocked, RootIDs: []string{id}, At: now.wall, Deadline: v.absDeadline()}})
		if wasLocked {
			if id != vault.GlobalID {
				acts = append(acts, Action{Kind: ActRestoreRoots, Vault: id, RootIDs: []string{id}})
			}
			acts = append(acts, Action{Kind: ActAuditCapsules, Vault: id, RootIDs: []string{id}})
		}
	}
	m.refreshSessions(now)
	return acts
}

// manualLock implements `precinto lock` (D50): every vault when none is
// named; End also ends the sessions of those folders.
func (m *Machine) manualLock(now instant, in Input) []Action {
	ids := dedupe(in.Vaults)
	if in.All || len(ids) == 0 {
		ids = m.vaultIDs()
	}
	strict := !in.LetFinish
	var wipes, rest []Action
	for _, id := range ids {
		w, r := m.lockVault(now, id, ui.ReasonManual, strict)
		wipes, rest = append(wipes, w...), append(rest, r...)
	}
	acts := append(wipes, rest...)
	if in.End {
		acts = append(acts, m.endSessionsOf(now, ids, ui.ReasonManual, in.Force)...)
	}
	return acts
}

// lockAll locks every unlocked vault (screen lock, sleep/wake).
func (m *Machine) lockAll(now instant, reason ui.Reason, strict bool) []Action {
	var wipes, rest []Action
	for _, id := range m.vaultIDs() {
		w, r := m.lockVault(now, id, reason, strict)
		wipes, rest = append(wipes, w...), append(rest, r...)
	}
	return append(wipes, rest...)
}

// lockVault changes id's state at once (SPEC §12.7 step 1): the key-wipe
// action comes first, then the event and the keyless seal. Sessions of the
// folder become paused; ungated ones cannot be paused and are ended.
func (m *Machine) lockVault(now instant, id string, reason ui.Reason, strict bool) (wipe, rest []Action) {
	v := m.vault(id)
	affected := m.sessionsOf(id)
	if v.state == VaultLocked {
		// Already locked: a manual lock without --let-finish still ends the
		// busy grace of its paused sessions (UX2 last row), and wipes the
		// key anyway, so an unlock racing the lock never leaves a key
		// behind (the daemon re-locks if it lost the race, I15).
		if reason == ui.ReasonManual {
			if strict {
				for _, s := range affected {
					s.strict = true
				}
			}
			return []Action{{Kind: ActWipeKey, Vault: id, RootIDs: []string{id}, Reason: string(reason)}}, nil
		}
		return nil, nil
	}
	v.state, v.reason, v.since, v.expiring = VaultLocked, reason, now.wall, false
	wipe = []Action{{Kind: ActWipeKey, Vault: id, RootIDs: []string{id}, Reason: string(reason)}}
	var sids []string
	for _, s := range affected {
		if s.state == SessionRunning {
			s.state = SessionPaused
			s.lockedAt, s.hasLocked = now, true
			s.busyAtLock = s.busy
			s.strict = strict
		} else if strict {
			s.strict = true
		}
		if s.info.SID != "" {
			sids = append(sids, s.info.SID)
		}
	}
	sort.Strings(sids)
	busy := false
	for _, s := range affected {
		busy = busy || s.busy
	}
	rest = append(rest,
		Action{Kind: ActPublish, Vault: id, RootIDs: []string{id}, Reason: string(reason),
			Event: ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{id}, SIDs: sids, Reason: string(reason), At: now.wall, Busy: busy}},
		Action{Kind: ActSealRoots, Vault: id, RootIDs: []string{id}, Reason: string(reason)})
	// Ungated sessions cannot be paused: they end at lock (D52).
	var ungated []*sessionState
	for _, s := range affected {
		if s.ungated {
			ungated = append(ungated, s)
		}
	}
	rest = append(rest, m.end(now, ungated, reason, false)...)
	return wipe, rest
}

// endSessionsOf ends the sessions of the given vaults (lock --end).
func (m *Machine) endSessionsOf(now instant, ids []string, reason ui.Reason, force bool) []Action {
	var ss []*sessionState
	seen := map[*sessionState]bool{}
	for _, id := range ids {
		for _, s := range m.sessionsOf(id) {
			if !seen[s] {
				seen[s] = true
				ss = append(ss, s)
			}
		}
	}
	return m.end(now, ss, reason, force)
}

// end requests the end of ss (SPEC §12.7 step 4): background sessions are
// exempt and never signalled (D25); a compacting session waits for its
// compaction (≤ compactionWait) unless force.
func (m *Machine) end(now instant, ss []*sessionState, reason ui.Reason, force bool) []Action {
	byHarness := map[string][]SessionInfo{}
	var order []string
	for _, s := range ss {
		if s.info.Background || s.endRequired {
			continue
		}
		if s.compacting && !force {
			if !s.pendingEnd {
				s.pendingEnd, s.pendingAt, s.endReason = true, now, reason
			}
			continue
		}
		s.pendingEnd, s.endRequired = false, true
		s.state = SessionEnding
		h := s.info.Harness
		if _, ok := byHarness[h]; !ok {
			order = append(order, h)
		}
		byHarness[h] = append(byHarness[h], s.info)
	}
	sort.Strings(order)
	var acts []Action
	for _, h := range order {
		infos := byHarness[h]
		sort.Slice(infos, func(i, j int) bool { return sessionKey(infos[i]) < sessionKey(infos[j]) })
		var roots []string
		for _, in := range infos {
			roots = append(roots, in.RootIDs...)
		}
		acts = append(acts, Action{Kind: ActEndSessions, RootIDs: dedupe(roots), Sessions: infos,
			Reason: string(reason), Grace: KillGrace(sessionEndBudget(h))})
	}
	return acts
}

// sessionEndBudget is the harness's SessionEnd hook budget.
func sessionEndBudget(h string) time.Duration {
	if h == string(harness.Codex) {
		return codexSessionEndBudget
	}
	return claudeSessionEndBudget
}

// activity applies one verified activity signal (D23, D54).
func (m *Machine) activity(now instant, in Input) {
	s := m.sessions[in.SID]
	if s == nil && in.Session != nil {
		m.register(now, in.Session, false)
		s = m.sessions[sessionKey(*in.Session)]
	}
	switch in.Activity {
	case ipc.ActInput, ipc.ActEnter:
		// Keystrokes count only from the verified wrapper of the session,
		// and never while its folder is locked (the lock screen drops them).
		if !in.FromWrapper || s == nil || !s.info.Wrapper {
			return
		}
		m.humanInput(now, s)
	case ipc.ActPrompt:
		key := originKey{in.SID, in.PromptID}
		rec, ok := m.origins[key]
		delete(m.origins, key) // consumed once
		if s != nil {
			s.busy, s.lastHook, s.ended = true, now, false
		}
		if ok && rec.origin == ipc.OriginHuman && !rec.at.elapsed(now, m.busyTimeout()) && s != nil {
			m.humanInput(now, s)
		}
	case ipc.ActTool:
		if s != nil {
			s.busy, s.lastHook = true, now
		}
	case ipc.ActStop, ipc.ActStopFailure, ipc.ActInterrupt, ipc.ActIdlePrompt, ipc.ActPermission:
		// Clear busy; never extend the unlock (D23, HA7).
		if s != nil {
			s.busy, s.lastHook = false, now
			if in.Activity == ipc.ActStop || in.Activity == ipc.ActStopFailure {
				s.compacting = false
			}
		}
	case ipc.ActCompactBegin:
		if s != nil {
			s.compacting, s.lastHook = true, now
		}
	case ipc.ActCompactEnd:
		if s != nil {
			s.compacting, s.lastHook = false, now
		}
	case ipc.ActSessionEnd:
		if s != nil {
			s.busy, s.compacting, s.ended, s.lastHook = false, false, true, now
		}
	}
}

// humanInput moves the idle clock of the session's unlocked folders (or of
// every folder when they share one clock, per_root_auth = false).
func (m *Machine) humanInput(now instant, s *sessionState) {
	ids := s.info.RootIDs
	if !m.policy.PerRootAuth {
		ids = m.vaultIDs()
	}
	for _, id := range ids {
		if v, ok := m.vaults[id]; ok && v.state == VaultUnlocked {
			v.lastHuman = now
		}
	}
}

// register upserts a session. A registration naming the process of a known
// session (the wrapper registered before the sid was known) merges into it.
func (m *Machine) register(now instant, info *SessionInfo, ungated bool) []Action {
	if info == nil || (info.SID == "" && info.Proc.IsZero()) {
		return nil
	}
	key := sessionKey(*info)
	s := m.sessions[key]
	if s == nil && !info.Proc.IsZero() {
		for k, o := range m.sessions {
			if o.info.Proc == info.Proc && (o.info.SID == "" || info.SID == "" || o.info.SID == info.SID) {
				s = o
				delete(m.sessions, k)
				break
			}
		}
	}
	if s == nil {
		s = &sessionState{state: SessionRunning, lastHook: now}
	}
	s.info = mergeInfo(s.info, *info)
	s.ungated = ungated || (s.ungated && !info.HooksSeen && !info.Registered)
	if info.Registered || info.HooksSeen {
		s.ungated = false
	}
	for _, id := range s.info.RootIDs {
		m.vault(id)
	}
	m.sessions[sessionKey(s.info)] = s
	m.refreshSession(now, s)
	if s.ungated && s.state == SessionPaused {
		return m.end(now, []*sessionState{s}, m.lockReasonOf(s), false)
	}
	return nil
}

// lockReasonOf returns the lock reason of the first locked folder of s.
func (m *Machine) lockReasonOf(s *sessionState) ui.Reason {
	for _, id := range s.info.RootIDs {
		if v, ok := m.vaults[id]; ok && v.state == VaultLocked {
			return v.reason
		}
	}
	return ui.ReasonStart
}

// mergeInfo combines what is known about a session. Roots are sticky
// (taint, HA10); a verified wrapper registration is never downgraded.
func mergeInfo(old, n SessionInfo) SessionInfo {
	out := n
	if out.Harness == "" {
		out.Harness = old.Harness
	}
	if out.SID == "" {
		out.SID = old.SID
	}
	if out.Proc.IsZero() {
		out.Proc = old.Proc
	}
	out.RootIDs = dedupe(append(append([]string(nil), old.RootIDs...), n.RootIDs...))
	if old.Wrapper && !n.Wrapper {
		out.Wrapper, out.WrapperPID = true, old.WrapperPID
	}
	out.Background = old.Background || n.Background
	if out.TTY == "" {
		out.TTY = old.TTY
	}
	out.HooksSeen = old.HooksSeen || n.HooksSeen
	out.Registered = old.Registered || n.Registered
	return out
}

// unregister forgets a session (the process exited or the wrapper left).
func (m *Machine) unregister(in Input) {
	for k, s := range m.sessions {
		if (in.SID != "" && s.info.SID == in.SID) ||
			(in.Session != nil && !in.Session.Proc.IsZero() && s.info.Proc == in.Session.Proc) ||
			(in.Session != nil && in.Session.SID != "" && s.info.SID == in.Session.SID) {
			delete(m.sessions, k)
		}
	}
}

// refreshSessions recomputes every session's state after vault changes.
func (m *Machine) refreshSessions(now instant) {
	for _, s := range m.sessions {
		m.refreshSession(now, s)
	}
}

// refreshSession sets running/paused from the session's folders.
func (m *Machine) refreshSession(now instant, s *sessionState) {
	if s.state == SessionEnding {
		return
	}
	allUnlocked := true
	for _, id := range s.info.RootIDs {
		if !m.unlocked(id) {
			allUnlocked = false
		}
	}
	switch {
	case allUnlocked && s.state != SessionRunning:
		s.state, s.hasLocked, s.busyAtLock, s.strict = SessionRunning, false, false, false
	case !allUnlocked && s.state == SessionRunning:
		s.state, s.lockedAt, s.hasLocked, s.busyAtLock = SessionPaused, now, true, s.busy
	}
}

// tick evaluates every deadline (SPEC §12.5).
func (m *Machine) tick(now instant) []Action {
	var wipes, rest []Action
	p := m.policy
	for _, id := range m.vaultIDs() {
		v := m.vaults[id]
		if v.state != VaultUnlocked {
			continue
		}
		absW := v.absDeadline()
		absExpired := !now.wall.Before(absW) || now.mono-v.unlocked.mono >= v.ttl
		idleExpired := v.lastHuman.elapsed(now, idleSoft(p))
		switch {
		case absExpired:
			w, r := m.lockVault(now, id, ui.ReasonLimit, false)
			wipes, rest = append(wipes, w...), append(rest, r...)
		case idleExpired:
			w, r := m.lockVault(now, id, ui.ReasonIdle, false)
			wipes, rest = append(wipes, w...), append(rest, r...)
		case !v.expiring && (absW.Sub(now.wall) <= expiryNotice || v.ttl-(now.mono-v.unlocked.mono) <= expiryNotice):
			v.expiring = true
			ev := ipc.Event{Kind: ipc.EventExpiring, RootIDs: []string{id}, At: now.wall, Deadline: absW}
			rest = append(rest, Action{Kind: ActNotifyExpiring, Vault: id, RootIDs: []string{id}, Event: ev, Reason: string(ui.ReasonLimit)},
				Action{Kind: ActPublish, Vault: id, RootIDs: []string{id}, Event: ev})
		}
	}
	acts := append(wipes, rest...)

	// Busy expiry (D23): hook-derived busy ends after busy_timeout without
	// hook activity (the registry refreshes busy through InBusy).
	for _, s := range m.sessions {
		if s.busy && s.lastHook.elapsed(now, m.busyTimeout()) {
			s.busy = false
		}
	}
	for k, rec := range m.origins {
		if rec.at.elapsed(now, m.busyTimeout()) {
			delete(m.origins, k)
		}
	}

	// Hard locks: idle_hard, continuous screen lock (D24).
	var toEnd []*sessionState
	reasons := map[*sessionState]ui.Reason{}
	for _, k := range m.sessionKeys() {
		s := m.sessions[k]
		if s.state != SessionPaused || s.info.Background || s.endRequired {
			continue
		}
		if s.pendingEnd {
			if !s.compacting || s.pendingAt.elapsed(now, compactionWait) {
				toEnd = append(toEnd, s)
				reasons[s] = s.endReason
			}
			continue
		}
		if d := p.IdleHard.D(); d > 0 && m.humanIdle(now, s, d) {
			toEnd = append(toEnd, s)
			reasons[s] = ui.ReasonIdle
			continue
		}
		if limit, ok := screenHardLimit(p, s.busy); m.screen.locked && ok && m.screen.since.elapsed(now, limit) {
			toEnd = append(toEnd, s)
			reasons[s] = ui.ReasonScreen
		}
	}
	for _, s := range toEnd {
		acts = append(acts, m.end(now, []*sessionState{s}, reasons[s], s.pendingEnd && s.pendingAt.elapsed(now, compactionWait))...)
	}
	return acts
}

// screenHardLimit is how long a continuous screen lock lasts before a
// paused session ends (D24): screen_lock_hard_after for idle sessions, and
// for busy ones busy_grace but never sooner than an idle session would end.
// A zero value means "never" (D62).
func screenHardLimit(p config.Policy, busy bool) (time.Duration, bool) {
	hard := p.ScreenLockHardAfter.D()
	if hard <= 0 {
		return 0, false
	}
	if !busy {
		return hard, true
	}
	grace := p.BusyGrace.D()
	if grace <= 0 {
		return 0, false
	}
	return max(hard, grace), true
}

// humanIdle reports whether every folder of s has seen no human input for
// d (idle_hard counts from the same origin as idle_soft).
func (m *Machine) humanIdle(now instant, s *sessionState, d time.Duration) bool {
	if len(s.info.RootIDs) == 0 {
		return false
	}
	for _, id := range s.info.RootIDs {
		v, ok := m.vaults[id]
		last := m.start
		if ok {
			last = v.lastHuman
		}
		if !last.elapsed(now, d) {
			return false
		}
	}
	return true
}

func (m *Machine) busyTimeout() time.Duration {
	if d := m.policy.BusyTimeout.D(); d > 0 {
		return d
	}
	return config.Default().Policy.BusyTimeout.D()
}

// idleSoft returns idle_soft, or the default when the policy carries no
// positive value (config.Validate refuses that; never "never lock").
func idleSoft(p config.Policy) time.Duration {
	if d := p.IdleSoft.D(); d > 0 {
		return d
	}
	return config.Default().Policy.IdleSoft.D()
}

// sessionsOf returns the sessions that have id among their folders.
func (m *Machine) sessionsOf(id string) []*sessionState {
	var out []*sessionState
	for _, k := range m.sessionKeys() {
		if s := m.sessions[k]; slices.Contains(s.info.RootIDs, id) {
			out = append(out, s)
		}
	}
	return out
}

func (m *Machine) vaultIDs() []string {
	ids := make([]string, 0, len(m.vaults))
	for id := range m.vaults {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (m *Machine) sessionKeys() []string {
	ks := make([]string, 0, len(m.sessions))
	for k := range m.sessions {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// snapshot implements Machine.Snapshot (deep copy).
func (m *Machine) snapshot() Snapshot {
	now := m.now()
	s := Snapshot{At: now.wall, Vaults: make(map[string]VaultSnapshot, len(m.vaults)), Sessions: make(map[string]SessionSnapshot, len(m.sessions))}
	for id, v := range m.vaults {
		vs := VaultSnapshot{State: v.state, Reason: string(v.reason), Since: v.since, LastHuman: v.lastHuman.wall}
		if v.state == VaultUnlocked {
			vs.IdleDeadline = m.idleDeadline(now, v)
			vs.AbsDeadline = v.absDeadline()
		}
		s.Vaults[id] = vs
	}
	for k, ss := range m.sessions {
		info := ss.info
		info.RootIDs = slices.Clone(info.RootIDs)
		snap := SessionSnapshot{Info: info, State: ss.state, Busy: ss.busy, BusyAtLock: ss.busyAtLock && !ss.strict, CompactBusy: ss.compacting}
		if ss.hasLocked {
			snap.LockedAt = ss.lockedAt.wall
		}
		s.Sessions[k] = snap
	}
	return s
}

// idleDeadline is the wall time at which idle_soft fires for v, the
// earlier of the wall and monotonic readings.
func (m *Machine) idleDeadline(now instant, v *vaultState) time.Time {
	d := idleSoft(m.policy)
	byWall := v.lastHuman.wall.Add(d)
	byMono := now.wall.Add(d - (now.mono - v.lastHuman.mono))
	if byMono.Before(byWall) {
		return byMono
	}
	return byWall
}

// nextDeadline implements Machine.NextDeadline.
func (m *Machine) nextDeadline() (time.Time, bool) {
	now := m.now()
	var best time.Time
	consider := func(t time.Time) {
		if best.IsZero() || t.Before(best) {
			best = t
		}
	}
	p := m.policy
	for _, v := range m.vaults {
		if v.state != VaultUnlocked {
			continue
		}
		consider(m.idleDeadline(now, v))
		abs := v.absDeadline()
		consider(abs)
		if !v.expiring {
			consider(abs.Add(-expiryNotice))
		}
	}
	for _, s := range m.sessions {
		if s.busy {
			consider(now.wall.Add(m.busyTimeout() - (now.mono - s.lastHook.mono)))
		}
		if s.state != SessionPaused || s.info.Background || s.endRequired {
			continue
		}
		if s.pendingEnd {
			consider(now.wall.Add(compactionWait - (now.mono - s.pendingAt.mono)))
		}
		if d := p.IdleHard.D(); d > 0 {
			latest := m.start
			for _, id := range s.info.RootIDs {
				if v, ok := m.vaults[id]; ok && v.lastHuman.mono > latest.mono {
					latest = v.lastHuman
				}
			}
			consider(now.wall.Add(d - (now.mono - latest.mono)))
		}
		if s.hasLocked && s.busyAtLock && p.BusyGrace.D() > 0 {
			consider(now.wall.Add(p.BusyGrace.D() - (now.mono - s.lockedAt.mono)))
		}
		if limit, ok := screenHardLimit(p, s.busy); m.screen.locked && ok {
			consider(now.wall.Add(limit - (now.mono - m.screen.since.mono)))
		}
	}
	for _, rec := range m.origins {
		consider(now.wall.Add(m.busyTimeout() - (now.mono - rec.at.mono)))
	}
	if best.IsZero() {
		return time.Time{}, false
	}
	if best.Before(now.wall) {
		best = now.wall
	}
	return best, true
}

// screenLocked reports whether the console is locked.
func (m *Machine) screenLocked() bool { return m.screen.locked }

// dedupe returns the distinct non-empty strings of in, in first-seen order.
func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
