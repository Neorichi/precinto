package sweep

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
)

// placeAction is the decision of the placement table (SPEC §11.3, D11) for
// a capsule version C meeting an existing version F at the same path. The
// same table folds two generations of a layered unit, with the newer
// version as F and the older as C (SPEC §10.4).
type placeAction string

const (
	actNoop     placeAction = "noop"          // equal bytes: nothing to write (recorded in the receipt)
	actKeep     placeAction = "keep-existing" // jsonl-append: F starts with C
	actReplace  placeAction = "replace"       // jsonl-append: C starts with F (stale prefix); F re-checked first
	actMerge    placeAction = "merge"         // jsonl-append: classic fragment, write C (+"\n") + F
	actUnion    placeAction = "line-union"    // add C's missing lines to F with O_APPEND
	actConflict placeAction = "conflict"      // keep F, write C under a conflict name
)

// pairFacts are the content-free facts the table decides on.
type pairFacts struct {
	Policy       harness.Placement
	CSize, FSize int64
	CSHA, FSHA   string
	FStartsWithC bool // len(F) ≥ len(C) and F[:len(C)] == C
	CStartsWithF bool // len(C) > len(F) and C[:len(F)] == F
	// Linked: F's first record's parentUuid or logicalParentUuid is a uuid
	// of C and the uuid sets are disjoint (classic fragment, from
	// claude.ScanLinks; sweep never parses Claude records itself).
	Linked bool
}

// decidePlacement is the placement table. A missing target ("place") and
// a unit that became live ("abort") are handled by the caller.
func decidePlacement(p pairFacts) placeAction {
	if p.CSize == p.FSize && p.CSHA == p.FSHA && p.CSHA != "" {
		return actNoop
	}
	switch p.Policy {
	case harness.PlaceJSONLAppend:
		switch {
		case p.FStartsWithC:
			return actKeep
		case p.CStartsWithF:
			return actReplace
		case p.Linked:
			return actMerge
		}
		return actConflict
	case harness.PlaceLineUnion:
		return actUnion
	default:
		// exact, md, sqlite-group (an existing group without a receipt is a
		// conflict, SPEC §7.2) and anything unknown: never overwrite.
		return actConflict
	}
}

// linkedFragment evaluates the classic-fragment rule of SPEC §11.3.
func linkedFragment(c, f claude.Links) bool {
	if !c.Valid || !f.Valid || len(c.UUIDs) == 0 || len(f.UUIDs) == 0 {
		return false
	}
	if !(f.FirstParent != "" && c.UUIDs[f.FirstParent] || f.FirstLogicalParent != "" && c.UUIDs[f.FirstLogicalParent]) {
		return false
	}
	for u := range f.UUIDs {
		if c.UUIDs[u] {
			return false
		}
	}
	return true
}

// version is one byte sequence of a path: staged (from a capsule) or the
// existing file at the target.
type version struct {
	dir  dirHandle
	rel  string
	size int64
	sha  string
	snap fsx.Stat
}

// gatherFacts reads what decidePlacement needs about C and F. Prefix and
// link checks read the files through their handles, never following
// symlinks, and require F's identity to hold while it is read.
func (r *run) gatherFacts(ctx context.Context, policy harness.Placement, c, f version) (pairFacts, error) {
	p := pairFacts{Policy: policy, CSize: c.size, FSize: f.size, CSHA: c.sha, FSHA: f.sha}
	if p.CSize == p.FSize && p.CSHA == p.FSHA {
		return p, nil
	}
	if policy != harness.PlaceJSONLAppend {
		return p, nil
	}
	fsnap := f.snap
	switch {
	case f.size >= c.size:
		sum, err := hashPrefix(f.dir, f.rel, c.size, snapPtr(fsnap))
		if err != nil {
			return p, err
		}
		p.FStartsWithC = sum == c.sha
	default:
		sum, err := hashPrefix(c.dir, c.rel, f.size, snapPtr(c.snap))
		if err != nil {
			return p, err
		}
		p.CStartsWithF = sum == f.sha
	}
	if p.FStartsWithC || p.CStartsWithF || r.p.scanLinks == nil {
		return p, nil
	}
	cl, err := r.links(ctx, c)
	if err != nil {
		return p, nil // unparseable: conflict, never a merge
	}
	fl, err := r.links(ctx, f)
	if err != nil {
		return p, nil
	}
	p.Linked = linkedFragment(cl, fl)
	return p, nil
}

func snapPtr(s fsx.Stat) *fsx.Stat {
	if s.Ino == 0 && s.Dev == 0 {
		return nil
	}
	return &s
}

// links scans one version with claude.ScanLinks.
func (r *run) links(ctx context.Context, v version) (claude.Links, error) {
	fh, st, err := v.dir.Open(v.rel)
	if err != nil {
		return claude.Links{}, err
	}
	defer fh.Close()
	if v.snap.Ino != 0 && !st.Unchanged(v.snap) {
		return claude.Links{}, fsx.ErrChanged
	}
	return r.p.scanLinks(ctx, fh)
}

// writeMerged writes C + ("\n" if C lacks a trailing newline) + F into a
// new temporary of dst (dirRel "") and returns its name and identity. F
// must keep identity fsnap while it is read.
func writeMerged(dst dirHandle, c, f version) (string, int64, error) {
	out, name, err := dst.CreateTemp(".", ".merge-*")
	if err != nil {
		return "", 0, err
	}
	ok := false
	defer func() {
		if !ok {
			out.Close()
			_ = dst.Remove(name)
		}
	}()
	var n int64
	last := byte('\n')
	for i, v := range []version{c, f} {
		fh, st, err := v.dir.Open(v.rel)
		if err != nil {
			return "", 0, err
		}
		if v.snap.Ino != 0 && !st.Unchanged(v.snap) {
			fh.Close()
			return "", 0, fsx.ErrChanged
		}
		if i == 1 && last != '\n' {
			if _, err := out.Write([]byte{'\n'}); err != nil {
				fh.Close()
				return "", 0, err
			}
			n++
		}
		w := &lastByteWriter{w: out}
		m, err := io.Copy(w, fh)
		fh.Close()
		if err != nil {
			return "", 0, err
		}
		n += m
		if m > 0 {
			last = w.last
		}
	}
	if err := fsx.FullSync(out); err != nil {
		return "", 0, err
	}
	if err := out.Close(); err != nil {
		return "", 0, err
	}
	ok = true
	return name, n, nil
}

type lastByteWriter struct {
	w    io.Writer
	last byte
}

func (l *lastByteWriter) Write(p []byte) (int, error) {
	n, err := l.w.Write(p)
	if n > 0 {
		l.last = p[n-1]
	}
	return n, err
}

// unionLines returns the lines of c (split on '\n', a final line without
// newline included) that do not occur in f byte-for-byte.
func unionLines(c, f []byte) [][]byte {
	have := map[string]bool{}
	for _, l := range splitLines(f) {
		have[string(l)] = true
	}
	var out [][]byte
	for _, l := range splitLines(c) {
		if len(l) == 0 || have[string(l)] {
			continue
		}
		have[string(l)] = true
		out = append(out, l)
	}
	return out
}

// splitLines splits b into lines without their '\n'.
func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := indexByte(b, '\n')
		if i < 0 {
			out = append(out, b)
			break
		}
		out = append(out, b[:i])
		b = b[i+1:]
	}
	return out
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// conflictStyle selects how conflict copies are named.
type conflictStyle string

const (
	conflictRestored conflictStyle = "restored" // <name>.precinto-restored
	conflictNote     conflictStyle = "note"     // <stem>.conflict-<YYYYMMDD-HHMM>.md
)

// conflictName returns the k-th candidate conflict name for rel (k = 0
// first; later candidates add ".<k>" before the extension).
func conflictName(rel string, style conflictStyle, at time.Time, k int) string {
	dir, base := path.Split(rel)
	switch style {
	case conflictNote:
		ext := path.Ext(base)
		stem := strings.TrimSuffix(base, ext)
		name := stem + ".conflict-" + at.UTC().Format("20060102-1504")
		if k > 0 {
			name += "." + strconv.Itoa(k)
		}
		return dir + name + ext
	default:
		name := base + ".precinto-restored"
		if k > 0 {
			name += "." + strconv.Itoa(k)
		}
		return dir + name
	}
}

// genConflictName names the older version of a path that two generations
// hold in conflict: <stem>.precinto-g<k><ext> (SPEC §10.4).
func genConflictName(rel string, gen uint64) string {
	dir, base := path.Split(rel)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if stem == "" { // dotfile without extension: keep the whole name
		stem, ext = base, ""
	}
	return dir + stem + ".precinto-g" + strconv.FormatUint(gen, 10) + ext
}

// restorePerm is the restored permission: 0600, or 0700 if owner-exec (I8).
func restorePerm(mode uint32) fs.FileMode {
	if mode&0o100 != 0 {
		return 0o700
	}
	return 0o600
}

// errAbortLive aborts a unit that became live during placement.
var errAbortLive = fmt.Errorf("%w: unit became live during restore", ErrLive)

// errPlaceRetry is returned when a target changed while it was evaluated.
var errPlaceRetry = errors.New("sweep: target changed while placing")
