package main

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/ui"
)

// Report helpers. They read Report.Units directly (content-free unit
// results) and never call Report methods, so they behave the same over
// real and fake reports.

// countOutcome returns the number of units of r with one of the outcomes.
func countOutcome(r *sweep.Report, outs ...sweep.Outcome) int {
	if r == nil {
		return 0
	}
	n := 0
	for _, u := range r.Units {
		for _, o := range outs {
			if u.Outcome == o {
				n++
				break
			}
		}
	}
	return n
}

// totals sums files and bytes of the units with one of the outcomes.
func totals(r *sweep.Report, outs ...sweep.Outcome) (units, files int, bytes int64) {
	if r == nil {
		return 0, 0, 0
	}
	for _, u := range r.Units {
		for _, o := range outs {
			if u.Outcome == o {
				units++
				files += u.Files
				bytes += u.Bytes
				break
			}
		}
	}
	return units, files, bytes
}

// mergeReport appends the units of src to dst.
func mergeReport(dst, src *sweep.Report) {
	if dst == nil || src == nil {
		return
	}
	if dst.Started.IsZero() || (!src.Started.IsZero() && src.Started.Before(dst.Started)) {
		dst.Started = src.Started
	}
	if src.Finished.After(dst.Finished) {
		dst.Finished = src.Finished
	}
	dst.Units = append(dst.Units, src.Units...)
}

// liveOutcomes are the outcomes of units left alone because something may
// still write them.
var liveOutcomes = []sweep.Outcome{sweep.OutLive, sweep.OutWarm, sweep.OutLeased}

// Detail prefixes of unit results the summaries explain (internal/sweep
// failure codes and skip details; never content, I7).
const (
	detailNoSpace      = "no-space:"     // the free-space floor refused the seal (SPEC §17)
	detailUnregistered = "unregistered:" // the capsule's Claude home is not registered (SPEC §7.0)
	detailAdopted      = "adopted:"      // a sweep left an adopted session to seal --adopt (S6)
)

// printSeal prints the summary of a seal or sweep run and returns the
// sentinel errors of the failures it explained with a line of its own,
// whose error chain the caller does not print again (D111). It never says
// "nothing to seal" when units failed, are held or were left adopted;
// held units are listed under their line by kind and reason, indented
// and without the "precinto: " prefix (D113); units sealed whose files
// could not be removed get a line of their own (D111).
func (a *app) printSeal(r *sweep.Report) []error {
	units, files, bytes := totals(r, sweep.OutSealed, sweep.OutUnchanged)
	held := heldGroups(r)
	nHeld := countOutcome(r, liveOutcomes...)
	adopted := countDetail(r, detailAdopted)
	noSpace, need := detailTotals(r, detailNoSpace)
	failures := countFailures(r)
	switch {
	case units > 0:
		a.sayOut(textSealed, units, files, ui.HumanBytes(bytes))
	case nHeld == 0 && adopted == 0 && failures == 0:
		a.sayOut(textSealNone)
	}
	if n := countOutcome(r, sweep.OutRemoveFailed); n > 0 {
		a.sayOut(textRemoveFailed, n)
	}
	if nHeld > 0 {
		a.sayOut(textSealSkipped, nHeld)
		for _, g := range held {
			fmt.Fprintf(a.out, textSealHeldLine+"\n", g.what, g.n, g.why)
		}
	}
	if adopted > 0 {
		a.sayOut(textSealAdopted, adopted)
	}
	var shown []error
	if noSpace > 0 {
		a.say(textSealNoSpace, noSpace, ui.HumanBytes(need), a.minFreeText())
		shown = append(shown, sweep.ErrNoSpace)
	}
	return shown
}

// printRestore prints the summary of a restore run and returns the
// sentinel errors it explained with a line of its own (D109). Like
// printSeal it never says "nothing to restore" when units failed: those
// stay sealed, and their line or error says why (D111).
func (a *app) printRestore(r *sweep.Report) []error {
	units, files, bytes := totals(r, sweep.OutRestored, sweep.OutMerged)
	switch {
	case units > 0:
		a.sayOut(textRestored, units, files, ui.HumanBytes(bytes))
	case countFailures(r) == 0:
		a.sayOut(textRestoreNone)
	}
	if n := countOutcome(r, sweep.OutConflict); n > 0 {
		a.sayOut(textConflicts, n)
	}
	if n := countOutcome(r, sweep.OutSkipped); n > 0 {
		a.sayOut(textSkippedUnits, n)
	}
	var shown []error
	if n := countDetail(r, detailUnregistered); n > 0 {
		a.line(ui.MsgHomeUnregistered, ui.Vars{N: n})
		shown = append(shown, harness.ErrUnregistered)
	}
	return shown
}

// unshown returns err without the failures a summary line explained (its
// leaves that wrap one of shown), nil when nothing else is left; the exit
// code is still the whole error's.
func unshown(err error, shown []error) error {
	if err == nil || len(shown) == 0 {
		return err
	}
	var keep []error
	var walk func(error)
	walk = func(e error) {
		if j, ok := e.(interface{ Unwrap() []error }); ok {
			for _, c := range j.Unwrap() {
				walk(c)
			}
			return
		}
		for _, s := range shown {
			if errors.Is(e, s) {
				return
			}
		}
		keep = append(keep, e)
	}
	walk(err)
	return errors.Join(keep...)
}

// failShown is failWith for a command whose summary explained some
// failures: their chain is not printed again, the exit code stays the
// whole error's (restore: exitForRestore).
func (a *app) failShown(name string, err error, shown []error, restore bool) int {
	code := exitFor(err)
	if restore {
		code = exitForRestore(err)
	}
	rest := unshown(err, shown)
	if rest == nil {
		return code
	}
	return a.failWith(name, rest, code)
}

// minFreeText is the effective policy.min_free as configured ("2GiB"),
// the floor every seal of this process keeps (floorPolicy, D76).
func (a *app) minFreeText() string {
	cfg, err := a.config()
	if err != nil {
		cfg = config.Default()
	}
	min := config.DefaultMinFree
	if l, err := a.layout(); err == nil {
		min = config.Size(floorPolicy(cfg, l).MinFreeBytes())
	}
	b, err := min.MarshalText()
	if err != nil {
		return ui.HumanBytes(int64(min))
	}
	return string(b)
}

// countDetail counts the units whose Detail starts with prefix.
func countDetail(r *sweep.Report, prefix string) int {
	n, _ := detailTotals(r, prefix)
	return n
}

// detailTotals counts the units whose Detail starts with prefix and sums
// their bytes.
func detailTotals(r *sweep.Report, prefix string) (n int, bytes int64) {
	if r == nil {
		return 0, 0
	}
	for _, u := range r.Units {
		if strings.HasPrefix(u.Detail, prefix) {
			n++
			bytes += u.Bytes
		}
	}
	return n, bytes
}

// countFailures counts the units that failed (or are inaccessible or
// could not be removed): a run with any of them sealed something less than
// it was asked to, so it never says "nothing to seal".
func countFailures(r *sweep.Report) int {
	return countOutcome(r, sweep.OutFailed, sweep.OutInaccessible, sweep.OutRemoveFailed)
}

// heldGroup is one line of the held-units summary: what is held, how
// many, and why (D113).
type heldGroup struct {
	what string
	n    int
	why  string
}

// heldGroups groups the held units of r by kind and reason, in a stable
// order.
func heldGroups(r *sweep.Report) []heldGroup {
	if r == nil {
		return nil
	}
	idx := map[[2]string]int{}
	var out []heldGroup
	for _, u := range r.Units {
		if !slices.Contains(liveOutcomes, u.Outcome) {
			continue
		}
		k := [2]string{kindText(u.Kind), heldReason(u)}
		if i, ok := idx[k]; ok {
			out[i].n++
			continue
		}
		idx[k] = len(out)
		out = append(out, heldGroup{what: k[0], n: 1, why: k[1]})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].what != out[j].what {
			return out[i].what < out[j].what
		}
		return out[i].why < out[j].why
	})
	return out
}

// kindText names a unit kind for the held-units summary.
func kindText(k capsule.Kind) string {
	switch k {
	case capsule.KindClaudeSession:
		return "Claude session"
	case capsule.KindClaudeProject:
		return "Claude project memory"
	case capsule.KindClaudePlan:
		return "Claude plan"
	case capsule.KindClaudeHistory:
		return "Claude prompt history"
	case capsule.KindGlobalStore:
		return "Claude global data"
	case capsule.KindCodexHome, capsule.KindCodexBlob:
		return "Codex history"
	case capsule.KindMarkdown:
		return "note"
	case capsule.KindGeneric:
		return "experimental harness data"
	}
	return "unit"
}

// heldReason is a short, content-free reason a unit is held, from its
// strongest piece of evidence (D113).
func heldReason(u sweep.UnitResult) string {
	if strings.HasSuffix(u.Detail, "hold-capped") {
		return "only weak signs of use, kept to be safe (see precinto doctor)"
	}
	var pick *live.Evidence
	for i := range u.Evidence {
		if pick == nil || (pick.Weak && !u.Evidence[i].Weak) {
			pick = &u.Evidence[i]
		}
	}
	if pick == nil {
		if u.Outcome == sweep.OutLeased {
			return "a precinto run holds it"
		}
		return "it may still be in use"
	}
	switch pick.Reason {
	case live.ReasonLease:
		return "a precinto run holds it"
	case live.ReasonLedgerProc, live.ReasonRegistry:
		return "its session is running"
	case live.ReasonRegistryIO:
		return "Claude's list of running sessions could not be read"
	case live.ReasonJob:
		return "a background job uses it"
	case live.ReasonWriterLock, live.ReasonOpenFD:
		return "a program has it open"
	case live.ReasonProcess:
		if u.Harness == string(harness.Codex) {
			return "Codex is running"
		}
		return "Claude is running"
	case live.ReasonUnstable, live.ReasonFutureTime:
		return "its files are still changing"
	case live.ReasonUnobserved:
		return "not watched long enough yet"
	case live.ReasonWarm:
		return "its session moved on, not quiet yet"
	case live.ReasonForkParent, live.ReasonPlanSlug:
		return "a running session uses it"
	}
	return "it may still be in use"
}
