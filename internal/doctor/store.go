package doctor

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/ui"
)

// Checks of precinto's own store: provenance (D8), plaintext left
// unsealed (§17), interrupted operations (I9), residue (IM14), policy
// pinning (D48, D55) and conflicts (D11).

const (
	// inFlight is how long a journal record with a live owner counts as an
	// operation in progress rather than an interrupted one.
	inFlight = time.Hour
	// waitingSeal is when a queued seal request is worth mentioning.
	waitingSeal = time.Hour
	// staleSnapshot is when a Claude shell snapshot is a crash leftover
	// (SPEC §7.1.1: sweeps delete those older than one day).
	staleSnapshot = 24 * time.Hour
)

// plaintextSummary returns sweep.PlaintextSummary (loaded once).
func (e *env) plaintextSummary() ([]sweep.Plaintext, error) {
	if !e.plainDone {
		e.plainDone = true
		e.plain, e.plainErr = e.d.Plaintext(e.ctx)
	}
	return e.plain, e.plainErr
}

// part runs one independent part of a check: a panic in it (a dependency
// bug) becomes a warning of that check and leaves the other parts alone.
func (e *env) part(code string, fn func() []Finding) (fs []Finding) {
	defer func() {
		if r := recover(); r != nil {
			fs = []Finding{{Code: code, Severity: Warn, Message: internalErrorText,
				Fix: "report this to the precinto maintainers, with the output of precinto version"}}
		}
	}()
	return fn()
}

func checkQuarantine(e *env) []Finding {
	var out []Finding
	out = append(out, e.part(CheckQuarantine, e.quarantined)...)
	out = append(out, e.part(CheckQuarantine, e.unloggedCapsules)...)
	if len(out) == 0 {
		out = append(out, ok(CheckQuarantine, "every capsule in the store is in the provenance log"))
	}
	return out
}

// quarantined counts what <base>/quarantine holds.
func (e *env) quarantined() []Finding {
	dir := e.o.Layout.QuarantineDir
	caps, other := 0, 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if strings.HasSuffix(d.Name(), ".pcap") {
				caps++
			} else {
				other++
			}
		}
		return nil
	})
	var out []Finding
	if caps > 0 {
		out = append(out, warn(CheckQuarantine, plural(caps, "capsule", "capsules")+" without provenance "+verb(caps, "is", "are")+" quarantined in "+e.show(dir)+": precinto never restores them (D8)",
			"delete them once you know where they came from (precinto import is not available yet)"))
	}
	if other > 0 {
		out = append(out, info(CheckQuarantine, plural(other, "file", "files")+" displaced at restore (stray database side files) "+verb(other, "is", "are")+" kept in "+e.show(dir), ""))
	}
	return out
}

// unloggedCapsules compares the capsule store with the provenance log: a
// file there that no log entry names is quarantined by the next sweep, a
// logged capsule whose header changed was replaced, and a logged capsule
// that is gone was lost. Units with a pending journal record are skipped:
// precinto's own crash leftovers are never reported as forgeries (O7).
func (e *env) unloggedCapsules() []Finding {
	l := e.o.Layout
	if !isDir(l.CapsulesDir) {
		return nil
	}
	log, err := e.capsuleLog()
	if err != nil {
		return []Finding{warn(CheckQuarantine, "could not read the capsule log ("+errClass(err)+"), so the capsule store was not checked", "")}
	}
	pending, perr := e.journalPending()
	if perr != nil {
		return []Finding{info(CheckQuarantine, "could not read the operation journal ("+errClass(perr)+"), so the capsule store was not checked", "")}
	}
	busy := map[string]bool{} // "<harness>/<unit>" with an operation in flight or interrupted
	for _, r := range pending {
		busy[r.Harness+"/"+r.Unit] = true
	}
	logged := map[string]string{} // path → header SHA-256
	for _, en := range log {
		logged[filepath.ToSlash(filepath.Clean(en.Path))] = en.HeaderSHA256
	}
	seen := map[string]bool{}
	unlogged, replaced, unreadable, walkErrs := 0, 0, 0, 0
	err = filepath.WalkDir(l.CapsulesDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			walkErrs++ // an unreadable directory: its capsules are not "missing"
			return nil
		}
		if e.ctx.Err() != nil {
			return e.ctx.Err()
		}
		if d.IsDir() || p == l.CapsulesDir {
			return nil
		}
		rel, rerr := filepath.Rel(l.CapsulesDir, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		parts := strings.SplitN(rel, "/", 3)
		if len(parts) == 3 && busy[parts[0]+"/"+parts[1]] {
			return nil
		}
		want, isLogged := logged[rel]
		if !isLogged {
			unlogged++
			return nil
		}
		seen[rel] = true
		if !d.Type().IsRegular() {
			replaced++
			return nil
		}
		got, herr := e.d.CapsuleHeaderSHA(p)
		switch {
		case herr != nil:
			unreadable++
		case !strings.EqualFold(got, want):
			replaced++
		}
		return nil
	})
	missing := 0
	if err == nil && walkErrs == 0 { // only a complete listing can tell a capsule is gone
		for rel := range logged {
			parts := strings.SplitN(rel, "/", 3)
			if !seen[rel] && !(len(parts) == 3 && busy[parts[0]+"/"+parts[1]]) {
				missing++
			}
		}
	}
	var out []Finding
	if replaced > 0 {
		out = append(out, fail(CheckQuarantine, plural(replaced, "capsule", "capsules")+" in the store no longer "+verb(replaced, "matches its", "match their")+" log entry (the file was replaced): precinto refuses to restore "+verb(replaced, "it", "them")+" (D8)",
			"restore "+e.arg(l.CapsulesDir)+" from a backup"))
	}
	if unlogged > 0 {
		out = append(out, warn(CheckQuarantine, plural(unlogged, "file", "files")+" in the capsule store "+verb(unlogged, "is", "are")+" not in the provenance log: the next sweep quarantines what has no provenance, and precinto never restores it (D8)",
			"precinto sweep"))
	}
	if missing > 0 {
		out = append(out, warn(CheckQuarantine, plural(missing, "logged capsule", "logged capsules")+" "+verb(missing, "is", "are")+" missing from the store: the sealed contents are lost unless a backup has them",
			"restore "+e.arg(l.CapsulesDir)+" from a backup"))
	}
	if unreadable > 0 {
		out = append(out, info(CheckQuarantine, plural(unreadable, "capsule", "capsules")+" could not be read to check their provenance", ""))
	}
	if (err != nil || walkErrs > 0) && e.ctx.Err() == nil {
		out = append(out, info(CheckQuarantine, "the capsule store could not be fully listed, so missing capsules were not counted", ""))
	}
	return out
}

func checkUnsealed(e *env) []Finding {
	var out []Finding
	out = append(out, e.part(CheckUnsealed, e.lockedPlaintext)...)
	out = append(out, e.part(CheckUnsealed, e.queuedSeals)...)
	if len(out) == 0 {
		out = append(out, ok(CheckUnsealed, "no plaintext of a locked folder was found"))
	}
	return out
}

// lockedPlaintext reports unencrypted files of locked folders, by reason
// (sweep.PlaintextSummary; SPEC §16.4, §17).
func (e *env) lockedPlaintext() []Finding {
	sums, err := e.plaintextSummary()
	if err != nil {
		return []Finding{info(CheckUnsealed, "could not scan the protected folders for unencrypted files ("+errClass(err)+")", "")}
	}
	var out []Finding
	for _, p := range sums {
		if p.Files <= 0 || e.unlocked(p.RootID) {
			continue
		}
		var reasons []string
		onlyRunning := true
		for _, k := range sortedKeys(p.ByReason) {
			if p.ByReason[k] <= 0 {
				continue
			}
			reasons = append(reasons, fmt.Sprintf("%s %d", strings.ReplaceAll(k, "_", " "), p.ByReason[k]))
			if k != "running" {
				onlyRunning = false
			}
		}
		msg := plural(p.Files, "file", "files") + " (" + ui.HumanBytes(p.Bytes) + ") of " + e.folderOf(p.RootID) + " " + verb(p.Files, "is", "are") + " unencrypted although the folder is locked"
		if len(reasons) > 0 {
			msg += ": " + strings.Join(reasons, ", ")
		}
		if onlyRunning && len(reasons) > 0 {
			out = append(out, info(CheckUnsealed, msg+" (sessions still running are sealed when they end)", "precinto lock --end"))
			continue
		}
		out = append(out, warn(CheckUnsealed, msg, "precinto sweep"))
	}
	return out
}

// interrupted reports journal records of operations that were interrupted
// (their process is gone, or they stopped advancing): until the next sweep
// recovers them, their files may be plaintext on disk (SPEC §10.5).
func (e *env) interrupted() []Finding {
	pending, err := e.journalPending()
	if err != nil {
		return []Finding{info(CheckInterrupted, "could not read the operation journal ("+errClass(err)+")", "")}
	}
	kinds := map[string]int{}
	n := 0
	for _, r := range pending {
		if !e.interruptedRecord(r) {
			continue
		}
		n++
		kinds[string(r.Kind)]++
	}
	if n == 0 {
		return nil
	}
	var ks []string
	for _, k := range sortedKeys(kinds) {
		ks = append(ks, fmt.Sprintf("%s %d", k, kinds[k]))
	}
	return []Finding{warn(CheckInterrupted, plural(n, "interrupted operation", "interrupted operations")+" ("+strings.Join(ks, ", ")+") "+verb(n, "waits", "wait")+" for recovery: the files involved may still be readable on disk (I9)",
		"precinto sweep")}
}

// interruptedRecord reports whether a journal record belongs to an
// operation that is no longer running.
func (e *env) interruptedRecord(r *journal.Record) bool {
	updated := r.Updated
	if updated.IsZero() {
		updated = r.Started
	}
	if !updated.IsZero() && e.now.Sub(updated) > inFlight {
		return true
	}
	if e.o.Procs == nil || r.PID <= 0 {
		return updated.IsZero()
	}
	_, err := e.o.Procs.Lookup(r.PID)
	return err != nil
}

// queuedSeals reports seal requests that gave up or wait for long (SPEC
// §10.6).
func (e *env) queuedSeals() []Finding {
	if !isDir(e.o.Layout.QueueDir) {
		return nil
	}
	reqs, err := e.d.QueueList()
	if err != nil {
		return []Finding{info(CheckUnsealed, "could not read the seal queue ("+errClass(err)+")", "")}
	}
	expired, waiting := 0, 0
	for _, r := range reqs {
		switch {
		case !r.Deadline.IsZero() && e.now.After(r.Deadline):
			expired++
		case !r.At.IsZero() && e.now.Sub(r.At) > waitingSeal:
			waiting++
		}
	}
	var out []Finding
	if expired > 0 {
		out = append(out, warn(CheckUnsealed, plural(expired, "seal request", "seal requests")+" gave up waiting for a session to finish writing: "+verb(expired, "that session is", "those sessions are")+" not sealed yet",
			"precinto sweep"))
	}
	if waiting > 0 {
		out = append(out, info(CheckUnsealed, plural(waiting, "seal request", "seal requests")+" "+verb(waiting, "has", "have")+" been waiting for over an hour for a session to finish writing", ""))
	}
	return out
}

func checkHoldCapped(e *env) []Finding {
	st := e.daemon()
	if st == nil {
		return nil // hold times are tracked by the agent only (S14)
	}
	for _, a := range st.Attention {
		if a.Code == CheckHoldCapped {
			return nil // merged from the agent's attention items
		}
	}
	return []Finding{ok(CheckHoldCapped, "no unit is kept unsealed by weak signs of activity alone")}
}

// checkInterrupted reports what interrupted operations left: journal
// records waiting for recovery, abandoned restore staging and history hold
// links (D12, D58).
func checkInterrupted(e *env) []Finding {
	var out []Finding
	out = append(out, e.part(CheckInterrupted, e.interrupted)...)
	out = append(out, e.part(CheckInterrupted, e.staleStaging)...)
	out = append(out, e.part(CheckInterrupted, func() []Finding {
		var fs []Finding
		for _, d := range e.claudeConfigDirs() {
			fs = append(fs, e.holdLinks(d)...)
		}
		return fs
	})...)
	if len(out) == 0 {
		out = append(out, ok(CheckInterrupted, "no interrupted operation left anything behind"))
	}
	return out
}

func checkResidue(e *env) []Finding {
	var out []Finding
	out = append(out, e.part(CheckResidue, e.staleShellSnapshots)...)
	if e.o.Leaks {
		out = append(out, e.part(CheckResidue, e.leakResidue)...)
	}
	if len(out) == 0 {
		out = append(out, ok(CheckResidue, "no plaintext residue was found outside the vault"))
	}
	return out
}

// staleStaging reports restore staging directories that no pending journal
// record names: decrypted files nobody will place or remove (D12).
func (e *env) staleStaging() []Finding {
	dir := e.o.Layout.StagingDir
	es, err := listDir(dir)
	if err != nil || len(es) == 0 {
		return nil
	}
	pending, perr := e.journalPending()
	if perr != nil {
		return nil
	}
	named := map[string]bool{}
	for _, r := range pending {
		if r.Staging != "" {
			named[filepath.Clean(r.Staging)] = true
		}
	}
	var out []Finding
	for _, en := range es {
		p := filepath.Join(dir, en.Name())
		if named[p] {
			continue // a restore in flight or awaiting recovery (rolled forward or back)
		}
		files := 0
		_ = filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				files++
			}
			return nil
		})
		out = append(out, warn(CheckInterrupted, e.show(p)+" is an abandoned restore staging folder with "+plural(files, "decrypted file", "decrypted files")+" (D12)",
			"rm -r "+e.arg(p)))
	}
	return out
}

// claudeTmpPermissions checks that Claude's temp folder is the user's and
// private (SPEC §7.0, S7): precinto refuses to restore into it otherwise,
// and other users could read session scratch files.
func (e *env) claudeTmpPermissions() []Finding {
	if !e.harnessSelected("claude-code") {
		return nil
	}
	var out []Finding
	for _, d := range e.claudeTmpDirs() {
		if p := dirProblem(d, e.d.EUID); p.text != "" {
			out = append(out, warn(CheckPermissions, "Claude's temp folder "+e.show(d)+" "+p.text+": other users may read session scratch files, and precinto does not restore sessions there (S7)",
				p.fix(e, d, true)))
		}
	}
	return out
}

// staleShellSnapshots counts Claude shell snapshots (environment dumps)
// left by crashes; sweeps delete them once no Claude session runs.
func (e *env) staleShellSnapshots() []Finding {
	if !e.harnessSelected("claude-code") {
		return nil
	}
	var out []Finding
	for _, cc := range e.claudeConfigDirs() {
		dir := filepath.Join(cc, "shell-snapshots")
		es, err := listDir(dir)
		if err != nil {
			continue
		}
		n := 0
		for _, en := range es {
			if !en.Type().IsRegular() || !strings.HasSuffix(en.Name(), ".sh") {
				continue
			}
			if fi, err := en.Info(); err == nil && e.now.Sub(fi.ModTime()) > staleSnapshot {
				n++
			}
		}
		if n > 0 {
			out = append(out, warn(CheckResidue, plural(n, "old shell snapshot", "old shell snapshots")+" in "+e.show(dir)+" "+verb(n, "holds", "hold")+" copies of your environment variables (crash leftovers, IM14)",
				"precinto sweep (it removes them while no Claude session runs)"))
		}
	}
	return out
}

// leakResidue scans the slower residue locations of --leaks: Claude's
// usage data, bash edit diffs and Codex hook outputs (IM14).
func (e *env) leakResidue() []Finding {
	var out []Finding
	if e.harnessSelected("claude-code") {
		for _, cc := range e.claudeConfigDirs() {
			ud := filepath.Join(cc, "usage-data")
			if n, size := countFiles(ud, 4); n > 0 {
				out = append(out, info(CheckResidue, e.show(ud)+" holds "+plural(n, "file", "files")+" ("+ui.HumanBytes(size)+") of Claude usage data: it is sealed only while no Claude session runs", "precinto sweep"))
			}
			for _, d := range findDirs(cc, "bash-edit-diff", 3) {
				if n, size := countFiles(d, 4); n > 0 {
					out = append(out, warn(CheckResidue, e.show(d)+" holds "+plural(n, "file", "files")+" ("+ui.HumanBytes(size)+") of edit diffs outside precinto's inventory", "remove "+e.arg(d)+" while no Claude session runs"))
				}
			}
		}
		for _, t := range e.claudeTmpDirs() {
			for _, d := range findDirs(t, "bash-edit-diff", 3) {
				if n, size := countFiles(d, 4); n > 0 {
					out = append(out, warn(CheckResidue, e.show(d)+" holds "+plural(n, "file", "files")+" ("+ui.HumanBytes(size)+") of edit diffs outside precinto's inventory", "remove "+e.arg(d)+" while no Claude session runs"))
				}
			}
		}
	}
	if e.harnessSelected("codex") {
		if tmp := e.o.Env.Get("TMPDIR"); filepath.IsAbs(tmp) {
			for _, d := range findDirsMatching(filepath.Clean(tmp), func(n string) bool {
				return strings.Contains(n, "hook_outputs") || strings.Contains(n, "hook-outputs")
			}, 2) {
				if n, size := countFiles(d, 4); n > 0 {
					out = append(out, warn(CheckResidue, e.show(d)+" holds "+plural(n, "file", "files")+" ("+ui.HumanBytes(size)+") of Codex hook outputs written outside a sealed Codex home (D44)", "remove "+e.arg(d)+" while Codex is not running"))
				}
			}
		}
	}
	return out
}

// countFiles counts the regular files below dir (at most depth levels) and
// their total size, without following symlinks.
func countFiles(dir string, depth int) (n int, size int64) {
	base := strings.Count(filepath.Clean(dir), string(filepath.Separator))
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && strings.Count(p, string(filepath.Separator))-base >= depth {
			return fs.SkipDir
		}
		if d.Type().IsRegular() {
			n++
			if fi, err := d.Info(); err == nil {
				size += fi.Size()
			}
			if n >= maxDirEntries {
				return fs.SkipAll
			}
		}
		return nil
	})
	return n, size
}

// findDirs returns the directories named name below top (at most depth
// levels down), without following symlinks.
func findDirs(top, name string, depth int) []string {
	return findDirsMatching(top, func(n string) bool { return n == name }, depth)
}

func findDirsMatching(top string, match func(string) bool, depth int) []string {
	var out []string
	base := strings.Count(filepath.Clean(top), string(filepath.Separator))
	seen := 0
	_ = filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if seen++; seen > maxDirEntries {
			return fs.SkipAll
		}
		if p != top && match(d.Name()) {
			out = append(out, p)
			return fs.SkipDir
		}
		if strings.Count(p, string(filepath.Separator))-base >= depth {
			return fs.SkipDir
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// pinned loads state/policy.pinned. It refuses anything but a regular file
// first: config.LoadPinned would block on a FIFO planted there.
func (e *env) pinned() (p config.Pinned, present bool, err error) {
	path := e.o.Layout.PolicyPinned
	if !exists(path) {
		return config.Pinned{}, false, nil
	}
	if pp := fileProblem(path, e.d.EUID); pp.severe && !pp.mode {
		return config.Pinned{}, true, fsx.ErrUnsafe // a symlink, a FIFO or another user's file
	}
	p, ok, err := config.LoadPinned(path)
	if err != nil {
		return config.Pinned{}, true, err
	}
	return p, ok, nil
}

func checkPendingPolicy(e *env) []Finding {
	p, present, err := e.pinned()
	if !present || err != nil {
		return nil // nothing confirmed yet, or policy-tampered reports the file
	}
	var keys []string
	for _, c := range config.Diff(p.Config, e.o.Cfg) {
		if c.Weakening {
			keys = append(keys, e.changeText(c, p.Config))
		}
	}
	if len(keys) == 0 {
		if st := e.daemon(); st != nil && len(st.PendingPolicy) > 0 {
			keys = append(keys, st.PendingPolicy...)
		}
	}
	if len(keys) > 0 {
		return []Finding{warn(CheckPendingPolicy, catalog(ui.MsgPolicyPending, ui.Vars{N: len(keys)})+" ("+joinNames(keys)+")",
			"precinto unlock (in a terminal), then confirm the changes")}
	}
	return []Finding{ok(CheckPendingPolicy, "config.toml does not weaken the settings you confirmed")}
}

// changeText names a config change for users: a folder by its path rather
// than the roots[<id>] key (user-facing text says "folder", SPEC §16.3).
func (e *env) changeText(c config.Change, pinned config.Config) string {
	rest, isRoot := strings.CutPrefix(c.Key, "roots[")
	if !isRoot {
		return oneLine(c.Key)
	}
	id, field, _ := strings.Cut(rest, "]")
	path := c.Old
	if r, ok := e.o.Cfg.RootByID(id); ok {
		path = r.Path
	} else if r, ok := pinned.RootByID(id); ok {
		path = r.Path
	}
	name := "folder " + e.show(path)
	if field = strings.TrimPrefix(field, "."); field != "" {
		return name + " " + oneLine(field)
	}
	if c.New == "" {
		return name + " removed"
	}
	return name
}

func checkPolicyTampered(e *env) []Finding {
	p, present, err := e.pinned()
	fix := "precinto unlock (in a terminal), then confirm the settings again"
	if !present {
		for _, id := range e.vaultIDs() {
			if vi := e.vault(id); vi.v != nil && !vi.v.Meta.LastAudit.IsZero() {
				return []Finding{warn(CheckPolicyTampered, "the saved copy of the settings you confirmed (state/policy.pinned) is missing although folders have been unlocked before: config.toml alone decides the policy now (D55)", fix)}
			}
		}
		return nil
	}
	text := catalog(ui.MsgPolicyTampered, ui.Vars{})
	if err != nil {
		return []Finding{fail(CheckPolicyTampered, text+" (state/policy.pinned cannot be read: "+errClass(err)+")", fix)}
	}
	if len(p.MACs) == 0 {
		return []Finding{fail(CheckPolicyTampered, text+" (state/policy.pinned carries no vault MAC)", fix)}
	}
	known := map[string]bool{}
	for _, id := range e.vaultIDs() {
		known[id] = true
	}
	var out []Finding
	var foreign []string
	for id, mac := range p.MACs {
		if !isHexMAC(mac) {
			return []Finding{fail(CheckPolicyTampered, text+" (state/policy.pinned has a malformed MAC)", fix)}
		}
		if !known[id] {
			foreign = append(foreign, id)
		}
	}
	if err := p.Config.Validate(); err != nil {
		out = append(out, fail(CheckPolicyTampered, text+" (the saved settings in state/policy.pinned are not valid)", fix))
	}
	if len(foreign) > 0 {
		out = append(out, warn(CheckPolicyTampered, "state/policy.pinned names "+plural(len(foreign), "vault", "vaults")+" that no protected folder uses ("+joinNames(foreign)+")", fix))
	}
	if len(out) == 0 {
		out = append(out, ok(CheckPolicyTampered, "the saved copy of the confirmed settings is well-formed (the agent checks its MACs at unlock)"))
	}
	return out
}

// isHexMAC reports whether s is a hex HMAC-SHA256.
func isHexMAC(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

func checkConflict(e *env) []Finding {
	units, err := e.d.Units(e.ctx, true)
	if err != nil {
		return []Finding{info(CheckConflict, "could not list kept-both conflicts ("+errClass(err)+")", "")}
	}
	counts := map[string]int{}
	for _, u := range units {
		if u.Conflicts <= 0 {
			continue
		}
		id := "global"
		if len(u.RootIDs) > 0 {
			id = u.RootIDs[0]
		}
		counts[id] += u.Conflicts
	}
	var out []Finding
	for _, id := range sortedKeys(counts) {
		out = append(out, warn(CheckConflict, plural(counts[id], "file", "files")+" of "+e.folderOf(id)+" "+verb(counts[id], "has", "have")+" two versions kept side by side (the sealed one and a newer copy, D11)",
			"precinto ls --conflicts, then precinto resolve FILE"))
	}
	if len(out) == 0 {
		out = append(out, ok(CheckConflict, "no kept-both conflicts wait to be resolved"))
	}
	return out
}
