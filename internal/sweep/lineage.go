package sweep

import (
	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/sweep/capslog"
)

// fileClass is how one plaintext file relates to its receipt (SPEC §10.4).
type fileClass int

const (
	classNew       fileClass = iota // no receipt entry
	classUnchanged                  // same bytes as the receipt
	classAppended                   // the receipt bytes are a prefix (append-only successor)
	classChanged                    // anything else
)

func (c fileClass) String() string {
	return [...]string{"new", "unchanged", "appended", "changed"}[c]
}

// classifiedFile is one present file and its class.
type classifiedFile struct {
	File  harness.File
	Class fileClass
	RF    *ReceiptFile // nil for classNew
}

// lineagePlan is the lineage decision for one re-seal.
type lineagePlan struct {
	Files   []classifiedFile
	Missing []ReceiptFile // receipt files no longer present (never a deletion, I12)
	Lineage capsule.Lineage
	Parent  uint64
	// Unchanged: every present file equals its receipt, none is new, and
	// every generation the receipt points at is still logged, so the
	// plaintext can go without a new generation (D10).
	Unchanged bool
}

// hasher reads current file contents for classification.
type hasher interface {
	// prefix returns the SHA-256 of the first n bytes of f.
	prefix(f harness.File, n int64) (string, error)
}

// classifyFile classifies one file against its receipt entry. The identity
// shortcut applies only when the receipt covers the whole file (same size):
// a receipt of a kept superset records the capsule's shorter prefix.
func classifyFile(f harness.File, rf *ReceiptFile, h hasher) (fileClass, error) {
	if rf == nil {
		return classNew, nil
	}
	switch {
	case f.Snap.Size == rf.Size:
		if !rf.Absent && f.Snap.Unchanged(rf.Snap) {
			return classUnchanged, nil
		}
		sum, err := h.prefix(f, f.Snap.Size)
		if err != nil {
			return 0, err
		}
		if sum == rf.SHA256 {
			return classUnchanged, nil
		}
		return classChanged, nil
	case f.Snap.Size > rf.Size:
		sum, err := h.prefix(f, rf.Size)
		if err != nil {
			return 0, err
		}
		if sum == rf.SHA256 {
			return classAppended, nil
		}
		return classChanged, nil
	default:
		return classChanged, nil
	}
}

// planLineage classifies files against the receipt and derives the
// generation lineage (D10, D42):
//
//	fresh      no receipt and no logged generation
//	successor  every receipt file present, each unchanged or appended
//	partial    some receipt files missing (absent ones included, D85),
//	           the rest unchanged or appended
//	diverged   some file changed (other than an exact-placement file
//	           rewritten after its restore, which supersedes, D87), or
//	           plaintext without a receipt while generations exist (its
//	           parent is then the newest)
func planLineage(files []harness.File, rd *receiptDisk, logged []capslog.Entry, h hasher) (lineagePlan, error) {
	var lp lineagePlan
	idx := receiptIndex(rd)
	present := map[fileKey]bool{}
	changed, grown, fresh, superseded := false, false, false, false
	for _, f := range files {
		k := fileKey{f.Base, f.Rel}
		present[k] = true
		rf := idx[k]
		c, err := classifyFile(f, rf, h)
		if err != nil {
			return lineagePlan{}, err
		}
		switch c {
		case classChanged:
			if supersedes(f, rf) {
				superseded = true // D87: a newer version of the file precinto placed
			} else {
				changed = true
			}
		case classAppended:
			grown = true
		case classNew:
			fresh = true
		}
		lp.Files = append(lp.Files, classifiedFile{File: f, Class: c, RF: rf})
	}
	if rd != nil {
		for _, rf := range rd.Files {
			if !present[fileKey{rf.Base, rf.Rel}] {
				lp.Missing = append(lp.Missing, rf)
			}
		}
	}
	newest, haveGens := newestEntry(logged)
	switch {
	case rd == nil && !haveGens:
		lp.Lineage = capsule.LineageFresh
	case rd == nil:
		lp.Lineage, lp.Parent = capsule.LineageDiverged, newest.Gen
	case changed:
		lp.Lineage, lp.Parent = capsule.LineageDiverged, rd.Gen
	case len(lp.Missing) > 0:
		lp.Lineage, lp.Parent = capsule.LineagePartial, rd.Gen
	default:
		lp.Lineage, lp.Parent = capsule.LineageSuccessor, rd.Gen
	}
	if rd != nil && !changed && !grown && !fresh && !superseded && len(files) > 0 {
		lp.Unchanged = receiptGensLogged(rd, logged, files)
	}
	return lp, nil
}

// supersedes reports whether a changed file is a newer version of the
// version precinto placed there (D87): an exact-placement file (tasks,
// todos, memory, notes, global stores; never an append-only transcript)
// rewritten in place after its restore. Its new bytes replace the placed
// ones like any edit; a file precinto did not place (no receipt entry, or
// an absent one) is a real divergence.
func supersedes(f harness.File, rf *ReceiptFile) bool {
	if rf == nil || rf.Absent || f.Append {
		return false
	}
	return supersedable(f.Placement)
}

// supersedable is the placement policies whose in-place rewrites supersede
// (D87).
func supersedable(p harness.Placement) bool {
	return p == "" || p == harness.PlaceExact || p == harness.PlaceMarkdown
}

// receiptGensLogged reports whether the receipt generation and the
// generation every present file came from are still logged: plaintext is
// dropped without a new generation only when its bytes provably live on
// in a logged capsule.
func receiptGensLogged(rd *receiptDisk, logged []capslog.Entry, files []harness.File) bool {
	have := map[uint64]bool{}
	for _, en := range logged {
		if !en.Blob {
			have[en.Gen] = true
		}
	}
	if !have[rd.Gen] {
		return false
	}
	idx := receiptIndex(rd)
	for _, f := range files {
		rf := idx[fileKey{f.Base, f.Rel}]
		if rf == nil {
			return false
		}
		g := rf.FromGen
		if g == 0 {
			g = rd.Gen
		}
		if !have[g] {
			return false
		}
	}
	return true
}

// dirHasher hashes files through the unit's base handles, requiring the
// snapshot identity while reading.
type dirHasher struct {
	bases map[capsule.BaseID]dirHandle
}

func (h dirHasher) prefix(f harness.File, n int64) (string, error) {
	d := h.bases[f.Base]
	if d == nil {
		return "", fsx.ErrUnsafe
	}
	snap := f.Snap
	return hashPrefix(d, f.Rel, n, &snap)
}
