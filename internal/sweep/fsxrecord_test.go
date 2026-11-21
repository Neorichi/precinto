//go:build failpoints

package sweep

// powerRecording is a local copy of internal/fsx/fsxtest (G1, CC-27) for
// the power-loss rows (FX-G4-12), kept until fsxtest reads synced files
// it cannot read through their descriptor: fsxtest.Recording reads every
// FullSynced file with ReadAt on the descriptor fsx reports, which fails
// with EBADF for the O_WRONLY descriptors of fsx.WriteFileAtomic and
// AppendLine — the journal, receipts, counters and capsule log of every
// sweep run — so a recording of a sweep always fails. The copy differs
// only in readAt, which then reads the file through its reported path,
// and in its unexported names. Delete it and use fsxtest once G1 applies
// the same fix.

import (
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/fsx/failpoint"
)

// Bounds on what a recording keeps in memory.
const (
	maxFileSnapshot  = 64 << 20  // one synced, renamed-over or unlinked file
	maxTotalSnapshot = 512 << 20 // all of them
)

// powerRecording is the operation log of one test (Record).
type powerRecording struct {
	mu      sync.Mutex
	ops     []op
	pre     map[string]*node // snapshots taken at a Done=false report
	created map[nodeID]bool  // inodes created while recording
	bytes   int64
	err     error // first recording failure, reported by Images
	stop    func()
}

type nodeID struct{ dev, ino uint64 }

// node is one file system entry of the model.
type node struct {
	dir  bool
	link string // symlink target ("" for files and directories)
	data []byte
	perm fs.FileMode
	id   nodeID
}

type op struct {
	kind   failpoint.FSOpKind
	path   string
	target string
	prev   *node  // rename: the target before it was replaced; unlink/rmdir: the removed entry
	id     nodeID // fsync: the synced inode
	data   []byte // fsync: its content at that moment
}

// recordPowerLoss starts logging every mutating fsx operation of the process until
// the test ends. It skips the test in builds without -tags failpoints.
func recordPowerLoss(t testing.TB) *powerRecording {
	t.Helper()
	if !failpoint.Enabled() {
		t.Skip("power-loss recording needs -tags failpoints")
	}
	r := &powerRecording{pre: map[string]*node{}, created: map[nodeID]bool{}}
	r.stop = failpoint.ObserveFS(r.observe)
	t.Cleanup(r.stop)
	return r
}

func preKey(o failpoint.FSOp) string {
	return string(o.Kind) + "\x00" + o.Path + "\x00" + o.Target
}

// observe is the failpoint.ObserveFS callback. It uses the os package
// only, never fsx (fsx would report to it again).
func (r *powerRecording) observe(o failpoint.FSOp) {
	if !filepath.IsAbs(o.Path) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !o.Done {
		switch o.Kind {
		case failpoint.FSRename:
			if n, ok := r.snapshot(o.Target); ok {
				r.pre[preKey(o)] = n
			}
		case failpoint.FSUnlink, failpoint.FSRmdir:
			if n, ok := r.snapshot(o.Path); ok {
				r.pre[preKey(o)] = n
			}
		}
		return
	}
	rec := op{kind: o.Kind, path: filepath.Clean(o.Path)}
	if o.Target != "" {
		rec.target = filepath.Clean(o.Target)
	}
	switch o.Kind {
	case failpoint.FSRename, failpoint.FSUnlink, failpoint.FSRmdir:
		rec.prev = r.pre[preKey(o)]
		delete(r.pre, preKey(o))
	case failpoint.FSCreate, failpoint.FSMkdir:
		if st, err := fsx.Lstat(o.Path); err == nil {
			r.created[nodeID{st.Dev, st.Ino}] = true
		}
	case failpoint.FSFsync:
		if o.File == nil {
			return
		}
		st, err := fsx.Fstat(o.File)
		if err != nil {
			r.fail(fmt.Errorf("fstat of a synced file: %w", err))
			return
		}
		data, err := r.readAt(o.File, st.Size)
		if err != nil {
			r.fail(err)
			return
		}
		rec.id, rec.data = nodeID{st.Dev, st.Ino}, data
	}
	r.ops = append(r.ops, rec)
}

func (r *powerRecording) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

// account charges n snapshot bytes against the memory bounds.
func (r *powerRecording) account(n int64) error {
	if n > maxFileSnapshot || r.bytes+n > maxTotalSnapshot {
		return fmt.Errorf("fsxtest: snapshot of %d bytes exceeds the recording bounds", n)
	}
	r.bytes += n
	return nil
}

func (r *powerRecording) readAt(f *os.File, size int64) ([]byte, error) {
	if err := r.account(size); err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	n, err := f.ReadAt(buf, 0)
	if errors.Is(err, syscall.EBADF) {
		// The local fix: fsx syncs O_WRONLY descriptors (WriteFileAtomic,
		// AppendLine), which ReadAt cannot read; the reported path still
		// names the file at this point, so it is read through a fresh
		// read-only descriptor instead.
		g, oerr := os.OpenFile(f.Name(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if oerr != nil {
			return nil, fmt.Errorf("fsxtest: reopen synced file: %w", oerr)
		}
		n, err = g.ReadAt(buf, 0)
		g.Close()
	}
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("fsxtest: read synced file: %w", err)
	}
	return buf[:n], nil
}

// snapshot captures the entry at path before it is replaced or removed.
func (r *powerRecording) snapshot(path string) (*node, bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, false
	}
	st, err := fsx.Lstat(path)
	if err != nil {
		return nil, false
	}
	n := &node{perm: fi.Mode().Perm(), id: nodeID{st.Dev, st.Ino}}
	switch {
	case fi.IsDir():
		n.dir = true
	case fi.Mode()&fs.ModeSymlink != 0:
		n.link, _ = os.Readlink(path)
	case fi.Mode().IsRegular():
		if err := r.account(fi.Size()); err != nil {
			r.fail(err)
			return nil, false
		}
		data, err := os.ReadFile(path)
		if err != nil {
			r.fail(fmt.Errorf("fsxtest: snapshot %s: %w", filepath.Base(path), err))
			return nil, false
		}
		n.data = data
	default:
		return nil, false
	}
	return n, true
}

// images builds up to n power-loss images of dir (n ≥ 2: the first keeps
// only what is durable, the second everything; the rest are random subsets
// of the non-durable operations, deterministic per test name). Each image
// is a directory tree under t.TempDir() with dir's layout, returned by
// path; journals inside hold absolute paths, so callers copy an image over
// dir before running recovery on it. dir must be the absolute path the
// code under test used (or its realpath).
func (r *powerRecording) images(t testing.TB, dir string, n int) []string {
	t.Helper()
	r.mu.Lock()
	ops := append([]op(nil), r.ops...)
	created := make(map[nodeID]bool, len(r.created))
	for k, v := range r.created {
		created[k] = v
	}
	err := r.err
	r.mu.Unlock()
	if err != nil {
		t.Fatalf("fsxtest: recording failed: %v", err)
	}
	if !filepath.IsAbs(dir) {
		t.Fatalf("fsxtest: Images needs an absolute directory, got %q", dir)
	}
	dir = filepath.Clean(dir)
	prefixes := []string{dir}
	if real, err := fsx.Realpath(dir); err == nil && real != dir {
		prefixes = append(prefixes, real)
	}
	final, err := loadTree(dir)
	if err != nil {
		t.Fatalf("fsxtest: read %s: %v", dir, err)
	}
	b := newBuilder(ops, prefixes, created)
	if n < 1 {
		return nil
	}
	seed := fnv.New64a()
	seed.Write([]byte(t.Name()))
	rng := rand.New(rand.NewSource(int64(seed.Sum64())))
	var out []string
	seen := map[string]bool{}
	root := t.TempDir()
	for i := 0; i < n*4 && len(out) < n; i++ {
		var mode int
		switch i {
		case 0:
			mode = modeStrict
		case 1:
			mode = modeFull
		default:
			mode = modeRandom
		}
		img := b.image(final, mode, rng)
		sum := img.digest()
		if seen[sum] {
			continue
		}
		seen[sum] = true
		path := filepath.Join(root, fmt.Sprintf("image-%02d", len(out)))
		if err := img.write(path); err != nil {
			t.Fatalf("fsxtest: write image: %v", err)
		}
		out = append(out, path)
	}
	return out
}

// tree is a model of a directory: entries by slash-separated relative
// path ("" is never stored).
type tree map[string]*node

func loadTree(dir string) (tree, error) {
	t := tree{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, err := fsx.Lstat(p)
		if err != nil {
			return err
		}
		n := &node{perm: fi.Mode().Perm(), id: nodeID{st.Dev, st.Ino}}
		switch {
		case fi.IsDir():
			n.dir = true
		case fi.Mode()&fs.ModeSymlink != 0:
			n.link, err = os.Readlink(p)
			if err != nil {
				return err
			}
		case fi.Mode().IsRegular():
			if fi.Size() > maxFileSnapshot {
				return fmt.Errorf("%s is too large to image", rel)
			}
			n.data, err = os.ReadFile(p)
			if err != nil {
				return err
			}
		default:
			return nil // FIFOs, sockets: not imaged
		}
		t[rel] = n
		return nil
	})
	return t, err
}

func (t tree) clone() tree {
	c := make(tree, len(t))
	for k, v := range t {
		cp := *v
		c[k] = &cp
	}
	return c
}

// removeSubtree deletes rel and everything below it.
func (t tree) removeSubtree(rel string) {
	delete(t, rel)
	for k := range t {
		if strings.HasPrefix(k, rel+"/") {
			delete(t, k)
		}
	}
}

// move renames rel (and everything below it) to dst.
func (t tree) move(rel, dst string) {
	moved := tree{}
	for k, v := range t {
		if k == rel || strings.HasPrefix(k, rel+"/") {
			moved[dst+k[len(rel):]] = v
			delete(t, k)
		}
	}
	for k, v := range moved {
		t[k] = v
	}
}

// digest identifies an image's content for de-duplication.
func (t tree) digest() string {
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := fnv.New128a()
	for _, k := range keys {
		n := t[k]
		fmt.Fprintf(h, "%s\x00%v\x00%s\x00%o\x00", k, n.dir, n.link, n.perm)
		h.Write(n.data)
		h.Write([]byte{0})
	}
	return string(h.Sum(nil))
}

// write materializes the tree at root (directories first, parents before
// children; modes keep only the owner bits).
func (t tree) write(root string) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if di, dj := strings.Count(keys[i], "/"), strings.Count(keys[j], "/"); di != dj {
			return di < dj
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		n := t[k]
		p := filepath.Join(root, filepath.FromSlash(k))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		switch {
		case n.dir:
			if err := os.Mkdir(p, 0o700); err != nil && !os.IsExist(err) {
				return err
			}
		case n.link != "":
			if err := os.Symlink(n.link, p); err != nil {
				return err
			}
		default:
			perm := n.perm & 0o700
			if perm == 0 {
				perm = 0o600
			}
			if err := os.WriteFile(p, n.data, perm); err != nil {
				return err
			}
		}
	}
	// Directory modes last, so restrictive ones do not block their children.
	for i := len(keys) - 1; i >= 0; i-- {
		if n := t[keys[i]]; n.dir {
			perm := n.perm & 0o700
			if perm == 0 {
				perm = 0o700
			}
			if err := os.Chmod(filepath.Join(root, filepath.FromSlash(keys[i])), perm); err != nil {
				return err
			}
		}
	}
	return nil
}

// Image modes.
const (
	modeStrict = iota // only durable operations and data
	modeFull          // everything (the state at the moment of the call)
	modeRandom        // a random dependency-closed subset of the rest
)

// rop is an operation relative to the imaged directory.
type rop struct {
	op
	rel, relTarget string // "" when outside the directory
	inPath, inTgt  bool
	durable        bool
	forced         bool // a durable operation depends on it: persisted
	deps           []int
}

type builder struct {
	ops     []rop
	syncs   map[nodeID][]byte // last synced content per inode
	created map[nodeID]bool
}

func newBuilder(ops []op, prefixes []string, created map[nodeID]bool) *builder {
	relOf := func(p string) (string, bool) {
		for _, pre := range prefixes {
			if p == pre {
				return "", true
			}
			if strings.HasPrefix(p, pre+string(filepath.Separator)) {
				return filepath.ToSlash(p[len(pre)+1:]), true
			}
		}
		return "", false
	}
	b := &builder{syncs: map[nodeID][]byte{}, created: created}
	// Directory syncs, by relative path, with their positions.
	var all []rop
	for _, o := range ops {
		x := rop{op: o}
		x.rel, x.inPath = relOf(o.path)
		if o.target != "" {
			x.relTarget, x.inTgt = relOf(o.target)
		}
		all = append(all, x)
	}
	lastDirSync := map[string]int{}
	for i, x := range all {
		if x.kind == failpoint.FSDirSync && x.inPath {
			lastDirSync[x.rel] = i
		}
		if x.kind == failpoint.FSFsync {
			b.syncs[x.id] = x.data
		}
	}
	parent := func(rel string) string {
		if i := strings.LastIndexByte(rel, '/'); i >= 0 {
			return rel[:i]
		}
		return ""
	}
	syncedAfter := func(dirRel string, i int) bool {
		j, ok := lastDirSync[dirRel]
		return ok && j > i
	}
	for i := range all {
		x := &all[i]
		switch x.kind {
		case failpoint.FSCreate, failpoint.FSMkdir, failpoint.FSUnlink, failpoint.FSRmdir:
			if !x.inPath || x.rel == "" {
				continue
			}
			x.durable = syncedAfter(parent(x.rel), i)
		case failpoint.FSRename, failpoint.FSLink:
			switch {
			case x.inTgt && x.relTarget != "":
				x.durable = syncedAfter(parent(x.relTarget), i)
			case x.inPath && x.rel != "":
				// Renamed out of the directory: cannot be undone.
				x.durable = true
			default:
				continue
			}
		default:
			continue
		}
		b.ops = append(b.ops, *x)
	}
	// Dependencies: a later operation touching a name an earlier one
	// touched (equal, or one below the other).
	names := func(x rop) []string {
		var ns []string
		if x.inPath && x.rel != "" {
			ns = append(ns, x.rel)
		}
		if x.inTgt && x.relTarget != "" {
			ns = append(ns, x.relTarget)
		}
		return ns
	}
	related := func(a, b string) bool {
		return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
	}
	for j := range b.ops {
		for i := 0; i < j; i++ {
			dep := false
			for _, a := range names(b.ops[j]) {
				for _, c := range names(b.ops[i]) {
					if related(a, c) {
						dep = true
					}
				}
			}
			if dep {
				b.ops[j].deps = append(b.ops[j].deps, i)
			}
		}
	}
	// Whatever a durable operation depends on was persisted too.
	for j := len(b.ops) - 1; j >= 0; j-- {
		if b.ops[j].durable || b.ops[j].forced {
			for _, i := range b.ops[j].deps {
				b.ops[i].forced = true
			}
		}
	}
	return b
}

// image builds one power-loss state from the final tree.
func (b *builder) image(final tree, mode int, rng *rand.Rand) tree {
	t := final.clone()
	persisted := make([]bool, len(b.ops))
	for i, x := range b.ops {
		switch {
		case x.durable || x.forced || mode == modeFull:
			persisted[i] = true
		case mode == modeStrict:
			persisted[i] = false
		default:
			ok := rng.Intn(2) == 0
			for _, d := range x.deps {
				if !persisted[d] {
					ok = false
				}
			}
			persisted[i] = ok
		}
	}
	// A persisted operation needs every operation it depends on.
	for j := len(b.ops) - 1; j >= 0; j-- {
		if persisted[j] {
			for _, i := range b.ops[j].deps {
				persisted[i] = true
			}
		}
	}
	for i := len(b.ops) - 1; i >= 0; i-- {
		if !persisted[i] {
			b.undo(t, b.ops[i])
		}
	}
	if mode == modeFull {
		return t
	}
	// File data: the last synced content, or nothing for a file created
	// while recording and never synced; random images keep the current
	// content half of the time.
	for _, n := range t {
		if n.dir || n.link != "" {
			continue
		}
		synced, ok := b.syncs[n.id]
		var durable []byte
		switch {
		case ok:
			durable = synced
		case b.created[n.id]:
			durable = nil
		default:
			continue
		}
		if bytes.Equal(durable, n.data) {
			continue
		}
		if mode == modeStrict || rng.Intn(2) == 0 {
			n.data = append([]byte(nil), durable...)
		}
	}
	return t
}

// undo reverts one name operation on the model.
func (b *builder) undo(t tree, x rop) {
	switch x.kind {
	case failpoint.FSCreate, failpoint.FSLink:
		rel := x.rel
		if x.kind == failpoint.FSLink {
			rel = x.relTarget
		}
		if n, ok := t[rel]; ok && !n.dir {
			delete(t, rel)
		}
	case failpoint.FSMkdir:
		t.removeSubtree(x.rel)
	case failpoint.FSRename:
		if !x.inTgt {
			return
		}
		if x.inPath {
			t.move(x.relTarget, x.rel)
		} else {
			t.removeSubtree(x.relTarget)
		}
		if x.prev != nil {
			cp := *x.prev
			t[x.relTarget] = &cp
		}
	case failpoint.FSUnlink, failpoint.FSRmdir:
		if x.prev != nil {
			cp := *x.prev
			t[x.rel] = &cp
		} else if x.kind == failpoint.FSRmdir {
			t[x.rel] = &node{dir: true, perm: 0o700}
		}
	}
}
