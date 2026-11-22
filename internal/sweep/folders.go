package sweep

import (
	"context"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
)

// A run decides from the folders' state as it is when it seals, not as it
// was when it started (R4, U6-3, D133): a sweep's own units, notes and the
// global history are sealed only while their folders are locked and still
// protected; a queued request seals nothing in a folder that is no longer
// protected, and leaves the session a restore placed after it in a folder
// that is open now. A run's quiet wait can last minutes, during which the
// user may unlock or unprotect a folder, so the run takes the folders'
// state again for every decision pass (folderView), and decides each unit
// under its unit lock by it.

// Details of the units a run leaves in place because their folder is open.
const (
	detailUnlockedNow    = "folder unlocked: left in place"
	detailUnprotectedNow = "folder no longer protected: left in place"
)

// folderView is a run's view of the folders: the unlocked roots (Grants)
// and the roots of the run's configuration that config.toml, as it is on
// disk now, no longer lists — unprotected since the run started, which a
// run started now would not know (gone).
type folderView struct {
	unlocked map[string]bool
	gone     map[string]bool
}

// open reports whether u's folder is open in v, and why: one of its roots
// (its vault, for a unit without roots) is unlocked, or none of its roots
// is protected any more.
func (v *folderView) open(u harness.Unit) (bool, string) {
	ids := u.RootIDs
	if len(ids) == 0 {
		ids = []string{u.VaultID}
	}
	for _, id := range ids {
		if v.unlocked[id] {
			return true, detailUnlockedNow
		}
	}
	if v.unprotected(u) {
		return true, detailUnprotectedNow
	}
	return false, ""
}

// unprotected reports a unit none of whose roots config.toml lists now (a
// unit without roots never is: it belongs to the global vault).
func (v *folderView) unprotected(u harness.Unit) bool {
	if len(u.RootIDs) == 0 || len(v.gone) == 0 {
		return false
	}
	for _, id := range u.RootIDs {
		if !v.gone[id] {
			return false
		}
	}
	return true
}

// staleView makes the next look at the folders take their state again: at
// the start of every decision pass (sealPass) and before the notes of a
// sweep are decided.
func (r *run) staleView() {
	r.viewMu.Lock()
	r.view = nil
	r.viewMu.Unlock()
}

// folders returns the run's view of the folders, taking it when stale (or
// always, with fresh).
func (r *run) folders(ctx context.Context, fresh bool) *folderView {
	r.viewMu.Lock()
	defer r.viewMu.Unlock()
	if r.view == nil || fresh {
		r.view = &folderView{unlocked: r.unlocked(ctx), gone: r.goneRoots()}
	}
	return r.view
}

// goneRoots returns the roots of the run's configuration that config.toml
// on disk no longer lists. Only a config.toml that is there and reads
// (the same file before and after the read) says so: anything else says
// nothing, and every root counts as still protected (seal on doubt).
func (r *run) goneRoots() map[string]bool {
	p := r.l.ConfigFile
	if p == "" || len(r.e.Cfg.Roots) == 0 {
		return nil
	}
	before, err := fsx.Lstat(p)
	if err != nil {
		return nil
	}
	disk, err := config.Load(p)
	if err != nil {
		return nil
	}
	if after, err := fsx.Lstat(p); err != nil || after.Dev != before.Dev || after.Ino != before.Ino {
		return nil // replaced meanwhile: decided at the next look
	}
	var gone map[string]bool
	for _, root := range r.e.Cfg.Roots {
		if _, ok := disk.RootByID(root.ID); !ok {
			if gone == nil {
				gone = map[string]bool{}
			}
			gone[root.ID] = true
		}
	}
	return gone
}

// leaveInPlace decides, under the unit lock and before anything is
// written, whether a job leaves the unit's plaintext where it is because
// its folder is open now:
//   - a sweep's own job (Options.lockedOnly) seals only while the unit's
//     folders are locked and still protected (R4), judged by the run's view
//     of this decision pass, so a unit decided after the quiet wait is
//     judged by the folders' state after it;
//   - a queued job (Options.queued) seals a session that ended whatever its
//     folder's state, except: one whose unit a restore placed after the
//     request (D133) stays in a folder that is unlocked or no longer
//     protected, judged afresh (in a locked folder it is sealed, as a sweep
//     would); and nothing is sealed in a folder no longer protected, which
//     a run started now would not even look at.
func (r *run) leaveInPlace(ctx context.Context, u harness.Unit, o Options, rd receiptDisk, hasRc bool) (bool, string) {
	switch {
	case o.lockedOnly:
		return r.folders(ctx, false).open(u)
	case o.queued:
		if restoredSince(o, rd, hasRc) {
			if open, _ := r.folders(ctx, true).open(u); open {
				return true, detailRestoredSince
			}
		}
		if r.folders(ctx, false).unprotected(u) {
			return true, detailUnprotectedNow
		}
	}
	return false, ""
}
