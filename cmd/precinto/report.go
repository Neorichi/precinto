package main

import (
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

// printSeal prints the summary of a seal or sweep run.
func (a *app) printSeal(r *sweep.Report) {
	units, files, bytes := totals(r, sweep.OutSealed, sweep.OutUnchanged)
	held := countOutcome(r, liveOutcomes...)
	switch {
	case units > 0:
		a.sayOut(textSealed, units, files, ui.HumanBytes(bytes))
	case held == 0:
		a.sayOut(textSealNone)
	}
	if held > 0 {
		a.sayOut(textSealSkipped, held)
	}
}

// printRestore prints the summary of a restore run.
func (a *app) printRestore(r *sweep.Report) {
	units, files, bytes := totals(r, sweep.OutRestored, sweep.OutMerged)
	if units > 0 {
		a.sayOut(textRestored, units, files, ui.HumanBytes(bytes))
	} else {
		a.sayOut(textRestoreNone)
	}
	if n := countOutcome(r, sweep.OutConflict); n > 0 {
		a.sayOut(textConflicts, n)
	}
	if n := countOutcome(r, sweep.OutSkipped); n > 0 {
		a.sayOut(textSkippedUnits, n)
	}
}
