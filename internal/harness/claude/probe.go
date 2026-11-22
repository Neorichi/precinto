package claude

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// registryStartSlack is D18's "start ≤ startedAt + 2 s".
const registryStartSlackUS = 2_000_000

// Probe returns Claude-specific liveness evidence (SPEC §9.2): E2 registry,
// E4 jobs, E6 open files, E7 Claude processes, E8 fork references and plan
// slugs, and D20 warm sessions. A failure to read any of them is evidence
// too (live), never an empty answer.
func (a *adapter) Probe(ctx context.Context, e harness.Env, u harness.Unit) ([]live.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return []live.Evidence{ev(live.ReasonUnknown, "cancelled")}, err
	}
	if e.Procs == nil {
		return []live.Evidence{ev(live.ReasonUnknown, "no process table")}, nil
	}
	cc := u.Home.Bases[capsule.BaseClaudeConfig]
	if !filepath.IsAbs(cc) {
		return []live.Evidence{ev(live.ReasonUnknown, "unit without a config dir")}, nil
	}
	p := &prober{a: a, e: e, u: u, cc: cc, ctx: ctx}
	switch u.Kind {
	case capsule.KindClaudeSession:
		p.session()
	case capsule.KindClaudeProject:
		p.project()
	case capsule.KindClaudePlan:
		p.plan()
	case capsule.KindGlobalStore, capsule.KindClaudeHistory:
		p.anyClaude()
	default:
		p.add(ev(live.ReasonUnknown, "unknown unit kind"))
	}
	return p.out, ctx.Err()
}

type prober struct {
	a   *adapter
	e   harness.Env
	u   harness.Unit
	cc  string
	ctx context.Context
	out []live.Evidence

	regOnce sync.Once
	reg     []RegistryEntry
	regErr  error
}

func (p *prober) add(e live.Evidence) { p.out = append(p.out, e) }

func (p *prober) registry() ([]RegistryEntry, error) {
	p.regOnce.Do(func() { p.reg, p.regErr = readRegistry(p.cc) })
	return p.reg, p.regErr
}

// registryMatches applies D18: the live pid started no later than
// startedAt + 2 s (else the pid was reused); without startedAt the file
// must have been written after the process started (LIVE-5).
func registryMatches(r RegistryEntry, info platform.ProcInfo) bool {
	start := platform.StartTime(info.ID) // wall clock, comparable with the registry (D66)
	if start.IsZero() {
		return true // unknown start: the pid is alive, so the entry may be its own (fail live)
	}
	if !r.StartedAt.IsZero() {
		return start.UnixMicro() <= r.StartedAt.UnixMicro()+registryStartSlackUS
	}
	if r.Mtime.IsZero() {
		return true
	}
	return r.Mtime.UnixMicro() >= start.UnixMicro()
}

// liveSessions returns the session ids of this home that a live process
// owns now: registry entries with a matching live pid, and ledger
// sessions whose current process is alive.
func (p *prober) liveSessions() []string {
	var out []string
	if reg, err := p.registry(); err == nil {
		for _, r := range reg {
			if !r.Valid {
				continue
			}
			info, err := p.e.Procs.Lookup(r.PID)
			if err != nil || info.State == platform.StateZombie || !registryMatches(r, info) {
				continue
			}
			if sid, ok := sidOf(r.SessionID); ok && len(r.SessionID) == uuidLen {
				out = appendUnique(out, sid)
			}
		}
	}
	if p.e.Ledger != nil {
		if sessions, err := p.e.Ledger.List(harnessName); err == nil {
			for _, s := range sessions {
				if !s.CurrentProc.IsZero() && p.e.Procs.Alive(s.CurrentProc) {
					if sid, ok := sidOf(s.SID); ok && len(s.SID) == uuidLen {
						out = appendUnique(out, sid)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// transcriptsOf finds a session's main transcripts in this home by session
// id across every projects/*/ directory (D19).
func (p *prober) transcriptsOf(sid string) []string {
	matches, _ := filepath.Glob(filepath.Join(p.cc, "projects", "*", sid+".jsonl"))
	return matches
}

func (p *prober) session() {
	sid := p.u.UnitID
	reg, err := p.registry()
	if err != nil {
		p.add(ev(live.ReasonRegistryIO, "registry unreadable"))
	}
	var cwds []string
	cwdsKnown := false
	unitCwds := func() ([]string, bool) {
		if !cwdsKnown {
			cwdsKnown = true
			cwds = p.sessionCwds(sid)
		}
		return cwds, len(cwds) > 0
	}
	for _, r := range reg {
		info, lerr := p.e.Procs.Lookup(r.PID)
		if errors.Is(lerr, platform.ErrNoProcess) {
			continue
		}
		if lerr != nil {
			p.add(live.Evidence{Reason: live.ReasonRegistryIO, Path: r.Path, Detail: "process table unreadable"})
			continue
		}
		if info.State == platform.StateZombie {
			continue
		}
		weak := !p.a.inv.MatchProcess(info)
		if r.Valid {
			if strings.EqualFold(r.SessionID, sid) && registryMatches(r, info) {
				p.add(live.Evidence{Reason: live.ReasonRegistry, Proc: info.ID, Path: r.Path, Detail: "registry names the session", Weak: weak})
			}
			continue
		}
		// A malformed entry with a live pid: that pid's cwd sessions are
		// live (D18, LIVE-9).
		cwd, cerr := p.e.Procs.Cwd(info.ID)
		if errors.Is(cerr, platform.ErrNotSame) {
			continue
		}
		known, have := unitCwds()
		if cerr != nil || cwd == "" || !have || touches(known, cwd) {
			p.add(live.Evidence{Reason: live.ReasonRegistryIO, Proc: info.ID, Path: r.Path, Detail: "malformed registry entry of a live process", Weak: weak})
		}
	}

	jobs, err := readJobs(p.cc)
	if err != nil {
		p.add(ev(live.ReasonJob, "job records unreadable"))
	}
	for _, j := range jobs {
		switch {
		case !j.Valid:
			p.add(live.Evidence{Reason: live.ReasonJob, Path: filepath.Join(p.cc, "jobs", j.ID), Detail: "job record of unknown schema", Weak: true})
		case strings.EqualFold(j.SessionID, sid) && !jobStopped(j):
			p.add(live.Evidence{Reason: live.ReasonJob, Path: filepath.Join(p.cc, "jobs", j.ID), Detail: "background job not stopped"})
		}
	}

	p.warm(sid, reg)
	p.openFiles()

	// E8: a live session that forked from, or copied lines of, this one.
	for _, other := range p.liveSessions() {
		if strings.EqualFold(other, sid) {
			continue
		}
		for _, t := range p.transcriptsOf(other) {
			facts, err := p.a.facts(p.ctx, t)
			if err != nil {
				continue
			}
			if containsFold(facts.ForkRefs, sid) || containsFold(facts.CopiedSIDs, sid) {
				p.add(ev(live.ReasonForkParent, "a live session references this transcript"))
				return
			}
		}
	}
}

// warm adds D20 evidence: the ledger's current process for sid is alive
// but no longer runs sid (SessionEnd clear|resume, a newer session of the
// same process, or a registry entry of that pid naming another session).
func (p *prober) warm(sid string, reg []RegistryEntry) {
	if p.e.Ledger == nil {
		return
	}
	s, err := p.e.Ledger.Get(harnessName, sid)
	if err != nil {
		if !errors.Is(err, ledger.ErrNotFound) {
			p.add(ev(live.ReasonUnknown, "ledger unreadable"))
		}
		return
	}
	proc := s.CurrentProc
	if proc.IsZero() || !p.e.Procs.Alive(proc) {
		return
	}
	moved := s.Warm()
	if !moved {
		if cur, err := p.e.Ledger.ByProc(harnessName, proc); err == nil && len(cur) > 0 {
			moved = true
			for _, c := range cur {
				if strings.EqualFold(c.SID, sid) {
					moved = false
				}
			}
		}
	}
	if !moved {
		for _, r := range reg {
			if r.Valid && r.PID == proc.PID && !strings.EqualFold(r.SessionID, sid) {
				if info, err := p.e.Procs.Lookup(r.PID); err == nil && info.ID == proc && registryMatches(r, info) {
					moved = true
				}
			}
		}
	}
	if moved {
		p.add(live.Evidence{Reason: live.ReasonWarm, Proc: proc, Detail: "non-current session of a live process"})
	}
}

// openFiles adds E6 evidence: a process holds a descriptor below one of the
// unit's directories (Bash tasks in $TMP/<P>/<sid>, MCP logs…).
func (p *prober) openFiles() {
	dirs := topDirs(p.u)
	if len(dirs) == 0 {
		return
	}
	holders, err := p.e.Procs.OpenFilesUnder(p.ctx, dirs)
	if err != nil {
		p.add(ev(live.ReasonOpenFD, "open-file check failed"))
		return
	}
	for _, h := range holders {
		p.add(live.Evidence{Reason: live.ReasonOpenFD, Proc: h.Proc.ID, Path: h.Path, Detail: "open descriptor below the unit"})
	}
}

// topDirs returns the unit's directories that exist, without those inside
// another listed directory (one open-file query covers the subtree).
func topDirs(u harness.Unit) []string {
	var dirs []string
	for _, pr := range u.Prune {
		base, rel, ok := strings.Cut(pr, ":")
		if !ok {
			continue
		}
		root, ok := u.Home.Bases[capsule.BaseID(base)]
		if !ok {
			continue
		}
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if isDir(abs) {
			dirs = append(dirs, abs)
		}
	}
	sort.Strings(dirs)
	var out []string
	for _, d := range dirs {
		inside := false
		for _, o := range out {
			if paths.Within(o, d) {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, d)
		}
	}
	return out
}

// sessionCwds returns the directories a session is known to have used:
// ledger cwds and project dir, the project index cwds of its project
// directories, and its transcripts' cwd keys.
func (p *prober) sessionCwds(sid string) []string {
	var out []string
	if p.e.Ledger != nil {
		if s, err := p.e.Ledger.Get(harnessName, sid); err == nil {
			out = append(out, s.Cwds...)
			out = append(out, s.Dirs...)
		}
	}
	for _, t := range p.transcriptsOf(sid) {
		if facts, err := p.a.facts(p.ctx, t); err == nil {
			out = append(out, facts.Cwds...)
		}
		if p.e.Index != nil {
			if x := p.e.Index(harnessName); x != nil {
				proj := filepath.Base(filepath.Dir(t))
				if pr, ok, err := x.Lookup(p.cc, proj); err == nil && ok {
					out = append(out, pr.Cwds...)
				}
			}
		}
	}
	var abs []string
	for _, c := range out {
		if filepath.IsAbs(c) {
			abs = appendUnique(abs, filepath.Clean(c))
		}
	}
	return abs
}

// touches reports whether cwd and any of dirs contain one another.
func touches(dirs []string, cwd string) bool {
	for _, d := range dirs {
		if harness.InFolder(d, cwd) || harness.InFolder(cwd, d) {
			return true
		}
	}
	return false
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// project adds D47/E7 evidence: a Claude process (matched by executable)
// whose cwd lies inside one of the unit's folders, inside the git
// repository containing it, or is unknown; and E6 for the MCP log cache.
func (p *prober) project() {
	var folders []string
	for _, id := range p.u.RootIDs {
		r, ok := p.e.Cfg.RootByID(id)
		if !ok {
			continue
		}
		folders = append(folders, r.Path)
		if repo := repoRoot(r.Path); repo != "" {
			folders = append(folders, repo)
		}
	}
	p.claudeProcesses(func(cwd string) bool {
		for _, f := range folders {
			if harness.InFolder(f, cwd) { // D136: both spellings of the folder
				return true
			}
		}
		return false
	}, "claude runs in the folder or its repository")
	p.openFiles()
}

// plan adds D46/E8 evidence: a live session references the slug.
func (p *prober) plan() {
	slug := p.u.UnitID
	for _, sid := range p.liveSessions() {
		for _, t := range p.transcriptsOf(sid) {
			ts, err := p.a.scanFull(p.ctx, t)
			if err != nil {
				continue
			}
			for _, s := range ts.slugs {
				if sameName(s, slug) {
					p.add(ev(live.ReasonPlanSlug, "a live session references this plan"))
					return
				}
			}
		}
	}
}

// anyClaude adds E7 evidence for global stores (D21, D36): any Claude
// process running anywhere.
func (p *prober) anyClaude() {
	p.claudeProcesses(func(string) bool { return true }, "claude is running")
}

// claudeProcesses scans the process table for Claude processes (by
// executable, never p_comm) and adds weak process evidence for each whose
// cwd is relevant or unknown. A process table that cannot be read is
// evidence too.
func (p *prober) claudeProcesses(relevant func(cwd string) bool, detail string) {
	procs, err := p.e.Procs.List()
	if err != nil {
		p.add(ev(live.ReasonUnknown, "process table unreadable"))
		return
	}
	for _, info := range procs {
		if !p.a.inv.MatchProcess(info) {
			continue
		}
		cwd, err := p.e.Procs.Cwd(info.ID)
		if errors.Is(err, platform.ErrNotSame) {
			continue // exited while scanning
		}
		if err != nil || cwd == "" || relevant(cwd) {
			d := detail
			if err != nil || cwd == "" {
				d = "claude runs with an unknown cwd"
			}
			p.add(live.Evidence{Reason: live.ReasonProcess, Proc: info.ID, Detail: d, Weak: true})
		}
	}
}

// repoRoot returns the closest directory at or above dir that holds a .git
// entry (directory or file: worktrees and submodules), or "".
func repoRoot(dir string) string {
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := fsx.Lstat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if parent := filepath.Dir(d); parent == d {
			return ""
		}
	}
}

// factsCache keeps transcript facts per (path, identity) for the lifetime
// of the adapter, so probing many units does not re-read the same live
// transcripts (they are parsed only while unchanged).
type factsCache struct {
	mu      sync.Mutex
	entries map[string]cachedFacts
}

type cachedFacts struct {
	snap fsx.Stat
	ts   *transcriptScan
}

const maxCachedFacts = 256

func (a *adapter) scanFull(ctx context.Context, path string) (*transcriptScan, error) {
	st, err := fsx.Lstat(path)
	if err != nil {
		return nil, err
	}
	a.cache.mu.Lock()
	if c, ok := a.cache.entries[path]; ok && c.snap.Unchanged(st) {
		a.cache.mu.Unlock()
		return c.ts, nil
	}
	a.cache.mu.Unlock()
	ts, err := scanTranscriptFull(ctx, path)
	if err != nil {
		return nil, err
	}
	a.cache.mu.Lock()
	defer a.cache.mu.Unlock()
	if a.cache.entries == nil || len(a.cache.entries) >= maxCachedFacts {
		a.cache.entries = map[string]cachedFacts{}
	}
	a.cache.entries[path] = cachedFacts{snap: st, ts: ts}
	return ts, nil
}

func (a *adapter) facts(ctx context.Context, path string) (TranscriptFacts, error) {
	ts, err := a.scanFull(ctx, path)
	if err != nil {
		return TranscriptFacts{}, err
	}
	return ts.facts, nil
}
