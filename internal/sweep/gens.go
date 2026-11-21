package sweep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/sweep/capslog"
)

// Generations returns the logged generations of a unit, oldest first.
func Generations(e Env, unit string) ([]Generation, error) {
	r := newRun(e, ports{})
	entries, err := r.log.Unit(unit)
	if err != nil {
		return nil, err
	}
	out := make([]Generation, 0, len(entries))
	for _, en := range entries {
		out = append(out, generationOf(en))
	}
	return out, nil
}

func generationOf(en capslog.Entry) Generation {
	return Generation{
		Gen: en.Gen, Parent: en.Parent, Lineage: capsule.Lineage(en.Lineage),
		Path: en.Path, Size: en.Size, SealedAt: en.SealedAt,
	}
}

// NextGen reserves the next generation number of a unit: a counter in
// state/gens/<unit> persisted with FullSync before use, never a timestamp
// (D9, R16). Numbers are never reused; a crash can leave gaps (a reserved
// generation whose capsule recovery removed), and nothing may assume
// consecutive numbers (lineage uses logged Parent links, D58).
func NextGen(e Env, unit string) (uint64, error) {
	return newRun(e, ports{}).nextGen(context.Background(), unit, nil)
}

// nextGen implements NextGen. The counter is read and written under the
// gens lock (waited for at most a minute, and never past ctx); the new
// value is max(counter, highest logged generation, highest generation
// file in capsDir) + 1, so a lost or damaged counter file can never make a
// number repeat.
func (r *run) nextGen(ctx context.Context, unit string, capsDir dirHandle) (uint64, error) {
	if !validKey(unit) {
		return 0, fmt.Errorf("%w: invalid unit key", harness.ErrUnitKey)
	}
	if err := ensurePrivateDir(r.l.GensDir); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	lk, err := r.waitLockName(ctx, "gens")
	if err != nil {
		return 0, err
	}
	defer lk.Unlock()

	p := filepath.Join(r.l.GensDir, unit)
	n, err := readCounter(p)
	if err != nil {
		return 0, err
	}
	entries, err := r.log.Unit(unit)
	if err != nil {
		return 0, err
	}
	for _, en := range entries {
		n = max(n, en.Gen)
	}
	if capsDir != nil {
		ents, err := capsDir.ReadDir(".")
		if err != nil && !isMissing(err) {
			return 0, err
		}
		for _, de := range ents {
			if g, ok := capsule.ParseGenName(de.Name); ok {
				n = max(n, g)
			}
		}
	}
	n++
	if err := fsx.WriteFileAtomic(p, []byte(strconv.FormatUint(n, 10)+"\n"), 0o600); err != nil {
		return 0, err
	}
	return n, nil
}

// readCounter reads a generation counter; a missing, undecodable or
// non-regular file (a FIFO, a device) reads as 0: the log and the store
// then decide (see nextGen), and the new value replaces it atomically.
func readCounter(p string) (uint64, error) {
	b, err := readState(p, 64)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, fsx.ErrUnsafe), errors.Is(err, errStateTooLarge):
		return 0, nil
	case err != nil:
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, nil
	}
	return n, nil
}

// errStateTooLarge: a precinto state file is larger than its bound.
var errStateTooLarge = errors.New("sweep: state file too large")

// readState reads one of precinto's own state files (counters, refs, the
// pending-notes index): opened O_RDONLY|O_NOFOLLOW|O_NONBLOCK, so a
// symlink is refused and a FIFO never blocks, required to be a regular
// file (fsx.ErrUnsafe otherwise) and at most max bytes (errStateTooLarge).
func readState(p string, max int64) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symlink", fsx.ErrUnsafe, filepath.Base(p))
		}
		return nil, err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return nil, err
	}
	if !st.IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", fsx.ErrUnsafe, filepath.Base(p))
	}
	if st.Size > max {
		return nil, errStateTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errStateTooLarge
	}
	return b, nil
}

// LoadReceipt reads the receipt of a unit (ok=false if none).
func LoadReceipt(e Env, unit string) (Receipt, bool, error) {
	rd, ok, err := newRun(e, ports{}).loadReceipt(unit)
	return rd.Receipt, ok, err
}

// receiptDisk is the on-disk receipt: the exported Receipt plus what only
// sweep needs (G4 owns the format, docs/API.md §6). Unknown fields are
// ignored by older readers.
type receiptDisk struct {
	Receipt
	Kind    capsule.Kind              `json:"kind,omitempty"`
	Harness string                    `json:"harness,omitempty"`
	Bases   map[capsule.BaseID]string `json:"bases,omitempty"` // absolute base dirs (resolve)
	Blobs   map[string]string         `json:"blobs,omitempty"` // codex-home: rel → blob unit key
}

// maxReceiptBytes bounds a receipt read.
const maxReceiptBytes = 64 << 20

func (r *run) receiptPath(unit string) string {
	return filepath.Join(r.l.ReceiptsDir, unit+".json")
}

// loadReceipt reads state/receipts/<unit>.json.
func (r *run) loadReceipt(unit string) (receiptDisk, bool, error) {
	if !validKey(unit) {
		return receiptDisk{}, false, fmt.Errorf("%w: invalid unit key", harness.ErrUnitKey)
	}
	f, err := os.OpenFile(r.receiptPath(unit), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return receiptDisk{}, false, nil
	}
	if err != nil {
		return receiptDisk{}, false, err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return receiptDisk{}, false, err
	}
	if !st.IsRegular() {
		return receiptDisk{}, false, fmt.Errorf("%w: receipt is not a regular file", fsx.ErrUnsafe)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxReceiptBytes+1))
	if err != nil {
		return receiptDisk{}, false, err
	}
	if len(b) > maxReceiptBytes {
		return receiptDisk{}, false, errors.New("sweep: receipt too large")
	}
	var rd receiptDisk
	if err := json.Unmarshal(b, &rd); err != nil {
		return receiptDisk{}, false, fmt.Errorf("sweep: receipt of %s: %w", short(unit), err)
	}
	if rd.Unit != unit {
		return receiptDisk{}, false, fmt.Errorf("sweep: receipt of %s names another unit", short(unit))
	}
	return rd, true, nil
}

// writeReceipt replaces the receipt atomically.
func (r *run) writeReceipt(rd receiptDisk) error {
	if !validKey(rd.Unit) {
		return fmt.Errorf("%w: invalid unit key", harness.ErrUnitKey)
	}
	if err := ensurePrivateDir(r.l.ReceiptsDir); err != nil {
		return err
	}
	rd.V = 1
	sort.SliceStable(rd.Files, func(a, b int) bool {
		if rd.Files[a].Base != rd.Files[b].Base {
			return rd.Files[a].Base < rd.Files[b].Base
		}
		return rd.Files[a].Rel < rd.Files[b].Rel
	})
	b, err := json.Marshal(rd)
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(r.receiptPath(rd.Unit), b, 0o600)
}

// deleteReceipt removes the receipt (missing is fine).
func (r *run) deleteReceipt(unit string) error {
	if !validKey(unit) {
		return fmt.Errorf("%w: invalid unit key", harness.ErrUnitKey)
	}
	err := os.Remove(r.receiptPath(unit))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fsx.SyncDir(r.l.ReceiptsDir)
}

// receiptKey indexes receipt files by base and rel.
type fileKey struct {
	Base capsule.BaseID
	Rel  string
}

func receiptIndex(rd *receiptDisk) map[fileKey]*ReceiptFile {
	m := map[fileKey]*ReceiptFile{}
	if rd == nil {
		return m
	}
	for i := range rd.Files {
		f := &rd.Files[i]
		m[fileKey{f.Base, f.Rel}] = f
	}
	return m
}

// chain returns the generations a layered restore of the newest needs,
// newest first: the newest, then through each partial or diverged link its
// parent, until a fresh or successor generation (whose parent is fully
// contained in it) or a parent that is no longer logged (D42).
func chain(entries []capslog.Entry) []capslog.Entry {
	byGen := map[uint64]capslog.Entry{}
	var newest *capslog.Entry
	for i := range entries {
		en := entries[i]
		if en.Blob {
			continue
		}
		byGen[en.Gen] = en
		if newest == nil || en.Gen > newest.Gen {
			e := en
			newest = &e
		}
	}
	if newest == nil {
		return nil
	}
	out := []capslog.Entry{*newest}
	seen := map[uint64]bool{newest.Gen: true}
	cur := *newest
	for {
		l := capsule.Lineage(cur.Lineage)
		if l != capsule.LineagePartial && l != capsule.LineageDiverged {
			break
		}
		if cur.Parent == 0 || seen[cur.Parent] {
			break
		}
		p, ok := byGen[cur.Parent]
		if !ok {
			break
		}
		out = append(out, p)
		seen[p.Gen] = true
		cur = p
	}
	return out
}

// newestEntry returns the newest non-blob entry.
func newestEntry(entries []capslog.Entry) (capslog.Entry, bool) {
	var best capslog.Entry
	ok := false
	for _, en := range entries {
		if en.Blob {
			continue
		}
		if !ok || en.Gen > best.Gen {
			best, ok = en, true
		}
	}
	return best, ok
}
