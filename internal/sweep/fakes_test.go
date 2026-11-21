package sweep

// In-package fakes of the ports (docs/OWNERSHIP.md §4): the other groups'
// implementations (fsx directory handles, capsule, live, ledger, vault,
// the harness adapters) are stubs in this worktree, so the planner, the
// executor and recovery are tested against these. They work on real files
// under testkit homes, so crash tests see real leftovers.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/fsx/failpoint"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/testkit"
)

// ---------------------------------------------------------------- osFS

// osFS is a fileSystem over plain paths. It refuses symlinks in every
// component below a base (the property fsx guarantees with dir fds) and
// injects errors per operation and path.
type osFS struct {
	mu       sync.Mutex
	free     int64            // bytes available to CheckSpace/Space
	fail     map[string]error // "<op>:<abs path>" → error
	device   map[string]uint64
	onRename func(dst string) // called before every rename (tests)
	onUnlink func(p string)   // called before every UnlinkIfUnchanged (tests)
}

func newOSFS() *osFS { return &osFS{free: 1 << 50, fail: map[string]error{}} }

func (f *osFS) inject(op, abs string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[op+":"+abs] = err
}

func (f *osFS) failure(op, abs string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fail[op+":"+abs]
}

func (f *osFS) OpenBase(p string) (dirHandle, error) {
	st, err := fsx.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fsx.ErrUnsafe
	}
	return &osDir{fs: f, path: filepath.Clean(p)}, nil
}
func (f *osFS) MkdirPrivate(p string) error { return os.MkdirAll(p, 0o700) }
func (f *osFS) CheckSpace(p string, need int64, floor fsx.Floor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if need+floor.MinBytes > f.free {
		return fsx.ErrNoSpace
	}
	return nil
}
func (f *osFS) Space(p string) (uint64, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return uint64(f.free), uint64(f.free) * 2, nil
}
func (f *osFS) NewStaging(preferred, target, id string) (stagingHandle, error) {
	if err := os.MkdirAll(preferred, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(preferred, id)
	if err := os.Mkdir(p, 0o700); err != nil {
		return nil, err
	}
	return &osStaging{dir: &osDir{fs: f, path: p}}, nil
}
func (f *osFS) OpenStaging(p string) (stagingHandle, error) {
	st, err := fsx.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fsx.ErrUnsafe
	}
	return &osStaging{dir: &osDir{fs: f, path: p}}, nil
}

type osStaging struct{ dir *osDir }

func (s *osStaging) Dir() dirHandle { return s.dir }
func (s *osStaging) Path() string   { return s.dir.path }
func (s *osStaging) ID() string     { return filepath.Base(s.dir.path) }
func (s *osStaging) Remove() error  { return os.RemoveAll(s.dir.path) }

type osDir struct {
	fs   *osFS
	path string
}

// resolve joins rel below d, refusing escapes and symlinked components.
func (d *osDir) resolve(rel string, final bool) (string, error) {
	rel = filepath.ToSlash(rel)
	if rel == "" || rel == "." {
		return d.path, nil
	}
	if path.IsAbs(rel) || !filepath.IsLocal(rel) {
		return "", fsx.ErrUnsafe
	}
	cur := d.path
	comps := strings.Split(path.Clean(rel), "/")
	for i, c := range comps {
		cur = filepath.Join(cur, c)
		if i == len(comps)-1 && !final {
			break
		}
		st, err := fsx.Lstat(cur)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return filepath.Join(d.path, filepath.FromSlash(path.Clean(rel))), nil
			}
			return "", err
		}
		if st.Mode&0o170000 == 0o120000 {
			return "", fmt.Errorf("%w: symlink component", fsx.ErrUnsafe)
		}
	}
	return cur, nil
}

func (d *osDir) Path() string { return d.path }
func (d *osDir) Close() error { return nil }
func (d *osDir) OpenDir(rel string, create bool) (dirHandle, error) {
	rel = filepath.ToSlash(rel)
	cur := d.path
	if rel != "" && rel != "." {
		if path.IsAbs(rel) || !filepath.IsLocal(rel) {
			return nil, fsx.ErrUnsafe
		}
		for _, c := range strings.Split(path.Clean(rel), "/") {
			cur = filepath.Join(cur, c)
			st, err := fsx.Lstat(cur)
			if errors.Is(err, fs.ErrNotExist) && create {
				if err := os.Mkdir(cur, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
					return nil, err
				}
				st, err = fsx.Lstat(cur)
			}
			if err != nil {
				return nil, err
			}
			if !st.IsDir() {
				return nil, fsx.ErrUnsafe
			}
		}
	}
	if err := d.fs.failure("opendir", cur); err != nil {
		return nil, &fs.PathError{Op: "open", Path: cur, Err: err}
	}
	return &osDir{fs: d.fs, path: cur}, nil
}
func (d *osDir) Open(rel string) (*os.File, fsx.Stat, error) {
	p, err := d.resolve(rel, false)
	if err != nil {
		return nil, fsx.Stat{}, err
	}
	if err := d.fs.failure("open", p); err != nil {
		return nil, fsx.Stat{}, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fsx.Stat{}, err
	}
	st, err := fsx.Fstat(f)
	if err != nil || !st.IsRegular() {
		f.Close()
		if err == nil {
			err = fsx.ErrUnsafe
		}
		return nil, fsx.Stat{}, err
	}
	return f, st, nil
}
func (d *osDir) Lstat(rel string) (fsx.Stat, error) {
	p, err := d.resolve(rel, false)
	if err != nil {
		return fsx.Stat{}, err
	}
	if err := d.fs.failure("lstat", p); err != nil {
		return fsx.Stat{}, &fs.PathError{Op: "lstat", Path: p, Err: err}
	}
	return fsx.Lstat(p)
}
func (d *osDir) ReadDir(rel string) ([]fsx.Entry, error) {
	p, err := d.resolve(rel, true)
	if err != nil {
		return nil, err
	}
	if err := d.fs.failure("readdir", p); err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: p, Err: err}
	}
	ents, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	var out []fsx.Entry
	for _, e := range ents {
		st, err := fsx.Lstat(filepath.Join(p, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, fsx.Entry{Name: e.Name(), Type: typeOf(st), Stat: st})
	}
	return out, nil
}

func typeOf(st fsx.Stat) fsx.EntryType {
	switch {
	case st.IsRegular():
		return fsx.TypeRegular
	case st.IsDir():
		return fsx.TypeDir
	case st.Mode&0o170000 == 0o120000:
		return fsx.TypeSymlink
	}
	return fsx.TypeOther
}

func (d *osDir) Walk(rel string, fn func(fsx.WalkEntry) error) error {
	start, err := d.resolve(rel, true)
	if err != nil {
		return err
	}
	var walk func(abs, r string) error
	walk = func(abs, r string) error {
		if err := d.fs.failure("readdir", abs); err != nil {
			return &fs.PathError{Op: "readdir", Path: abs, Err: err}
		}
		ents, err := os.ReadDir(abs)
		if err != nil {
			return err
		}
		sort.Slice(ents, func(a, b int) bool { return ents[a].Name() < ents[b].Name() })
		for _, e := range ents {
			p := filepath.Join(abs, e.Name())
			wr := path.Join(r, e.Name())
			st, err := fsx.Lstat(p)
			if err != nil {
				continue
			}
			we := fsx.WalkEntry{Rel: wr, Type: typeOf(st), Stat: st}
			switch {
			case we.Type == fsx.TypeSymlink:
				we.Hazard = fsx.HazardSymlink
			case we.Type == fsx.TypeOther:
				we.Hazard = fsx.HazardSpecial
			case we.Type == fsx.TypeRegular && st.Nlink > 1:
				we.Hazard = fsx.HazardHardlink
			}
			err = fn(we)
			if errors.Is(err, fs.SkipDir) {
				continue
			}
			if err != nil {
				return err
			}
			if we.Type == fsx.TypeDir && we.Hazard == fsx.HazardNone {
				if err := walk(p, wr); err != nil {
					return err
				}
			}
		}
		return nil
	}
	r := filepath.ToSlash(rel)
	if r == "" {
		r = "."
	}
	return walk(start, r)
}
func (d *osDir) CreateTemp(dirRel, pattern string) (*os.File, string, error) {
	sub, err := d.OpenDir(dirRel, true)
	if err != nil {
		return nil, "", err
	}
	dir := sub.Path()
	if err := d.fs.failure("create", dir); err != nil {
		return nil, "", &fs.PathError{Op: "open", Path: dir, Err: err}
	}
	// fsx.Dir.CreateTemp semantics (CC-02), not os.CreateTemp's: the last
	// '*' is replaced by a random string; a pattern without '*' is the
	// exact name, created O_EXCL (fsx.ErrExist when it exists).
	var f *os.File
	if i := strings.LastIndexByte(pattern, '*'); i >= 0 {
		f, err = os.CreateTemp(dir, pattern[:i]+"*"+pattern[i+1:])
	} else {
		f, err = os.OpenFile(filepath.Join(dir, pattern), os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if errors.Is(err, fs.ErrExist) {
			err = fmt.Errorf("%w: %s", fsx.ErrExist, pattern)
		}
	}
	if err != nil {
		return nil, "", err
	}
	name := filepath.Base(f.Name())
	if dirRel != "" && dirRel != "." {
		name = path.Join(filepath.ToSlash(dirRel), name)
	}
	return f, name, nil
}
func (d *osDir) renameFiles(src, dst string, mode fsx.RenameMode) error {
	if d.fs.onRename != nil {
		d.fs.onRename(dst)
	}
	if err := d.fs.failure("rename", dst); err != nil {
		return &os.LinkError{Op: "rename", Old: src, New: dst, Err: err}
	}
	if mode == fsx.NoReplace {
		st, err := fsx.Lstat(src)
		if err != nil {
			return err
		}
		if st.IsDir() {
			if _, err := fsx.Lstat(dst); err == nil {
				return fsx.ErrExist
			}
			return os.Rename(src, dst)
		}
		if err := os.Link(src, dst); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return fsx.ErrExist
			}
			return err
		}
		return os.Remove(src)
	}
	return os.Rename(src, dst)
}
func (d *osDir) Rename(oldRel, newRel string, mode fsx.RenameMode) error {
	src, err := d.resolve(oldRel, false)
	if err != nil {
		return err
	}
	dst, err := d.resolve(newRel, false)
	if err != nil {
		return err
	}
	return d.renameFiles(src, dst, mode)
}
func (d *osDir) RenameTo(oldRel string, dst dirHandle, newRel string, mode fsx.RenameMode) error {
	src, err := d.resolve(oldRel, false)
	if err != nil {
		return err
	}
	od, ok := dst.(*osDir)
	if !ok {
		return errMixedHandles
	}
	to, err := od.resolve(newRel, false)
	if err != nil {
		return err
	}
	return d.renameFiles(src, to, mode)
}
func (d *osDir) Link(oldRel, newRel string) error {
	src, err := d.resolve(oldRel, false)
	if err != nil {
		return err
	}
	dst, err := d.resolve(newRel, false)
	if err != nil {
		return err
	}
	return os.Link(src, dst)
}
func (d *osDir) UnlinkIfUnchanged(rel string, expect fsx.Stat) error {
	p, err := d.resolve(rel, false)
	if err != nil {
		return err
	}
	if d.fs.onUnlink != nil {
		d.fs.onUnlink(p)
	}
	if err := d.fs.failure("unlink", p); err != nil {
		return &fs.PathError{Op: "unlink", Path: p, Err: err}
	}
	st, err := fsx.Lstat(p)
	if err != nil {
		return err
	}
	if !st.Unchanged(expect) {
		return fsx.ErrChanged
	}
	if st.Nlink > 1 {
		return fsx.ErrHardlink
	}
	return os.Remove(p)
}
func (d *osDir) Remove(rel string) error {
	p, err := d.resolve(rel, false)
	if err != nil {
		return err
	}
	return os.Remove(p)
}
func (d *osDir) RemoveEmptyDirs(rel, stopAt string) error {
	stop := filepath.Join(d.path, filepath.FromSlash(stopAt))
	p, err := d.resolve(rel, false)
	if err != nil {
		return err
	}
	for p != stop && p != d.path && strings.HasPrefix(p, d.path) {
		if err := os.Remove(p); err != nil {
			return nil
		}
		p = filepath.Dir(p)
	}
	return nil
}
func (d *osDir) Chtimes(rel string, mtime time.Time) error {
	p, err := d.resolve(rel, false)
	if err != nil {
		return err
	}
	return os.Chtimes(p, mtime, mtime)
}
func (d *osDir) Chmod(rel string, perm fs.FileMode) error {
	p, err := d.resolve(rel, false)
	if err != nil {
		return err
	}
	return os.Chmod(p, perm&0o700)
}
func (d *osDir) Sync() error { return fsx.SyncDir(d.path) }
func (d *osDir) Device() (uint64, error) {
	if d.fs.device != nil {
		for prefix, dev := range d.fs.device {
			if strings.HasPrefix(d.path, prefix) {
				return dev, nil
			}
		}
	}
	st, err := fsx.Lstat(d.path)
	return st.Dev, err
}

// ---------------------------------------------------------------- codec

// fakeCodec writes a test-only capsule format: a magic line, a header line
// (its SHA-256 is the provenance key; the file key derives from it) and a
// JSON body with the manifest and base64 contents. It keeps the two-pass
// identity checks, the OnPhase milestones and the no-replace rename of the
// real capsule.Seal, and validates entries on Extract like the real one.
type fakeCodec struct {
	mu            sync.Mutex
	betweenPasses func()
	sealErr       error // returned before writing anything
	tmpErr        error // returned while writing the temporary
	corrupt       bool  // flip a byte in the temporary: ErrVerify
	stanzas       int   // header stanzas (default 3)
	midTmp        func()
	afterRename   func() // right after the commit rename (where Seal evaluates capsule.renamed)
	duringExtract func(n int)
	seals         int
}

const fakeMagic = "FAKECAPSULE1\n"

type fakeBody struct {
	Manifest capsule.Manifest `json:"manifest"`
	Data     []string         `json:"data"`
}

type fakeHeader struct {
	Nonce   string `json:"nonce"`
	Stanzas int    `json:"stanzas"`
	Fpr     string `json:"fpr"`
}

func fakeFileKey(header []byte) []byte {
	s := sha256.Sum256(append([]byte("key:"), header...))
	return s[:16]
}

func readInput(in sealInput) ([]byte, fsx.Stat, error) {
	var f *os.File
	var st fsx.Stat
	var err error
	if in.Open != nil {
		f = in.Open
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, fsx.Stat{}, err
		}
		st, err = fsx.Fstat(f)
		if err != nil {
			return nil, fsx.Stat{}, err
		}
	} else {
		f, st, err = in.Dir.Open(in.Rel)
		if err != nil {
			return nil, fsx.Stat{}, err
		}
		defer f.Close()
	}
	if !st.Unchanged(in.Snap) {
		return nil, st, capsule.ErrChanged
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, st, err
	}
	if int64(len(b)) != in.Snap.Size {
		return nil, st, capsule.ErrChanged
	}
	return b, st, nil
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (c *fakeCodec) Seal(ctx context.Context, r sealRequest) (*capsule.Sealed, error) {
	c.mu.Lock()
	c.seals++
	sealErr, tmpErr, corrupt, stanzas, between, mid, renamed := c.sealErr, c.tmpErr, c.corrupt, c.stanzas, c.betweenPasses, c.midTmp, c.afterRename
	c.mu.Unlock()
	if stanzas == 0 {
		stanzas = capsule.HeaderStanzas
	}
	if sealErr != nil {
		return nil, sealErr
	}
	if r.Recipients.fpr == "" {
		return nil, capsule.ErrRecipients
	}
	// Pass 1.
	var data [][]byte
	var snaps []fsx.Stat
	man := r.Manifest
	man.Files = nil
	for i, in := range r.Inputs {
		b, st, err := readInput(in)
		if err != nil {
			return nil, err
		}
		data = append(data, b)
		snaps = append(snaps, st)
		man.Files = append(man.Files, capsule.Entry{Name: fmt.Sprintf("f/%06d", i+1), Base: in.Base, Rel: in.Rel, Path: in.Path,
			Mode: in.Snap.Mode & 0o7777, MtimeNS: in.Snap.MtimeNS, Size: in.Snap.Size, SHA256: sum(b), Append: in.Append, Group: in.Group})
	}
	man.Files = append(man.Files, r.Dirs...)
	if between != nil {
		between()
	}
	// Pass 2: same identity and bytes.
	for i, in := range r.Inputs {
		in.Snap = snaps[i]
		b, _, err := readInput(in)
		if err != nil {
			return nil, err
		}
		if sum(b) != man.Files[i].SHA256 {
			return nil, capsule.ErrChanged
		}
	}
	nonce := make([]byte, 8)
	_, _ = io.ReadFull(randReader{}, nonce)
	hdr, _ := json.Marshal(fakeHeader{Nonce: hex.EncodeToString(nonce), Stanzas: stanzas, Fpr: r.Recipients.fpr})
	header := append([]byte(fakeMagic), append(hdr, '\n')...)
	var body fakeBody
	body.Manifest = man
	for _, b := range data {
		body.Data = append(body.Data, base64.StdEncoding.EncodeToString(b))
	}
	bb, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	file := append(append([]byte(nil), header...), bb...)
	// Like capsule.Seal: only Out/TmpName(Name), created O_EXCL (a leftover
	// fails with fsx.ErrExist and is left), committed with a no-replace
	// rename straight into Out.
	tmp, name, err := r.Out.CreateTemp("", capsule.TmpName(r.Name))
	if err != nil {
		return nil, err
	}
	cleanup := func() { tmp.Close(); _ = r.Out.Remove(name) }
	half := len(file) / 2
	if _, err := tmp.Write(file[:half]); err != nil {
		cleanup()
		return nil, err
	}
	if mid != nil {
		mid()
	}
	if tmpErr != nil {
		cleanup()
		return nil, tmpErr
	}
	if _, err := tmp.Write(file[half:]); err != nil {
		cleanup()
		return nil, err
	}
	if corrupt {
		if _, err := tmp.WriteAt([]byte{'#'}, int64(len(header)+len(bb)/2)); err != nil {
			cleanup()
			return nil, err
		}
	}
	if err := fsx.FullSync(tmp); err != nil {
		cleanup()
		return nil, err
	}
	tmp.Close()
	if err := failpoint.Hit("capsule.tmp_written"); err != nil {
		_ = r.Out.Remove(name)
		return nil, err
	}
	if r.OnPhase != nil {
		if err := r.OnPhase(capsule.PhaseTmpWritten, nil); err != nil {
			_ = r.Out.Remove(name)
			return nil, err
		}
	}
	// Verify the round trip and the header.
	got, _, err := readAllBounded(r.Out, name, 1<<30)
	if err != nil {
		_ = r.Out.Remove(name)
		return nil, err
	}
	if !bytes.Equal(got, file) {
		_ = r.Out.Remove(name)
		return nil, capsule.ErrVerify
	}
	if stanzas != capsule.HeaderStanzas {
		_ = r.Out.Remove(name)
		return nil, capsule.ErrHeader
	}
	if r.OnPhase != nil {
		if err := r.OnPhase(capsule.PhaseVerified, nil); err != nil {
			_ = r.Out.Remove(name)
			return nil, err
		}
	}
	if err := r.Out.Rename(name, r.Name, fsx.NoReplace); err != nil {
		_ = r.Out.Remove(name)
		return nil, err
	}
	if renamed != nil {
		renamed()
	}
	// The real Seal evaluates capsule.renamed here (SEAL-6).
	if err := failpoint.Hit("capsule.renamed"); err != nil {
		return nil, err
	}
	s := &capsule.Sealed{Name: r.Name, Path: filepath.Join(r.Out.Path(), r.Name), SHA256: sum(file), HeaderSHA256: sum(header),
		Size: int64(len(file)), Manifest: man, Snaps: snaps}
	if r.OnPhase != nil {
		if err := r.OnPhase(capsule.PhaseCommitted, s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

type randReader struct{}

func (randReader) Read(p []byte) (int, error) {
	n := time.Now().UnixNano()
	for i := range p {
		p[i] = byte(n >> (8 * (i % 8)))
		n = n*6364136223846793005 + 1442695040888963407
	}
	return len(p), nil
}

func splitFake(b []byte) (header []byte, body []byte, err error) {
	if !bytes.HasPrefix(b, []byte(fakeMagic)) {
		return nil, nil, capsule.ErrFormat
	}
	i := bytes.IndexByte(b[len(fakeMagic):], '\n')
	if i < 0 {
		return nil, nil, capsule.ErrFormat
	}
	end := len(fakeMagic) + i + 1
	return b[:end], b[end:], nil
}

func (c *fakeCodec) ReadHeader(dir dirHandle, name string) ([]byte, string, error) {
	b, _, err := readAllBounded(dir, name, 1<<30)
	if err != nil {
		return nil, "", err
	}
	h, _, err := splitFake(b)
	if err != nil {
		return nil, "", err
	}
	return h, sum(h), nil
}

func (c *fakeCodec) HashFile(dir dirHandle, name string) (string, int64, error) {
	b, _, err := readAllBounded(dir, name, 1<<30)
	if err != nil {
		return "", 0, err
	}
	return sum(b), int64(len(b)), nil
}

func (c *fakeCodec) open(r io.Reader, key []byte) (fakeBody, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return fakeBody{}, err
	}
	h, body, err := splitFake(b)
	if err != nil {
		return fakeBody{}, err
	}
	if !bytes.Equal(key, fakeFileKey(h)) {
		return fakeBody{}, errors.New("fake: wrong file key")
	}
	var fb fakeBody
	if err := json.Unmarshal(body, &fb); err != nil {
		return fakeBody{}, capsule.ErrFormat
	}
	return fb, nil
}

func (c *fakeCodec) OpenManifest(r io.Reader, key []byte) (capsule.Manifest, error) {
	fb, err := c.open(r, key)
	return fb.Manifest, err
}

func (c *fakeCodec) Extract(ctx context.Context, r io.Reader, o extractRequest) (capsule.Manifest, []capsule.Staged, error) {
	fb, err := c.open(r, o.FileKey)
	if err != nil {
		return capsule.Manifest{}, nil, err
	}
	var total int64
	for _, en := range fb.Manifest.Files {
		if o.Check != nil {
			if err := o.Check(en); err != nil {
				return capsule.Manifest{}, nil, err
			}
		}
		if !en.Dir && en.Blob == "" {
			total += en.Size
		}
	}
	if o.Limits.MaxTotal > 0 && total > o.Limits.MaxTotal {
		return capsule.Manifest{}, nil, capsule.ErrTooLarge
	}
	var out []capsule.Staged
	k := 0
	for _, en := range fb.Manifest.Files {
		if en.Dir || en.Blob != "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return capsule.Manifest{}, nil, err
		}
		if k >= len(fb.Data) {
			return capsule.Manifest{}, nil, capsule.ErrFormat
		}
		b, err := base64.StdEncoding.DecodeString(fb.Data[k])
		if err != nil || int64(len(b)) != en.Size || sum(b) != en.SHA256 {
			return capsule.Manifest{}, nil, capsule.ErrFormat
		}
		if c.duringExtract != nil {
			c.duringExtract(k)
		}
		name := fmt.Sprintf("f-%06d", k+1)
		f, err := os.OpenFile(filepath.Join(o.Staging.Path(), name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return capsule.Manifest{}, nil, err
		}
		if _, err := f.Write(b); err != nil {
			f.Close()
			return capsule.Manifest{}, nil, err
		}
		f.Close()
		st, _ := fsx.Lstat(filepath.Join(o.Staging.Path(), name))
		out = append(out, capsule.Staged{Entry: en, StagedRel: name, Stat: st})
		k++
	}
	return fb.Manifest, out, nil
}

// ---------------------------------------------------------------- live

// fakeLive decides from configured verdicts; StillQuiet also compares the
// real current identity of every path with its snapshot.
type fakeLive struct {
	mu       sync.Mutex
	verdicts map[string]live.Verdict
	notQuiet bool
	decided  []string
}

func newFakeLive() *fakeLive { return &fakeLive{verdicts: map[string]live.Verdict{}} }

func (l *fakeLive) set(key string, v live.Verdict) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.verdicts[key] = v
}

func (l *fakeLive) Decide(ctx context.Context, s live.Subject, extra []live.Evidence) (live.Verdict, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.decided = append(l.decided, s.Key)
	if v, ok := l.verdicts[s.Key]; ok {
		return v, nil
	}
	if len(extra) > 0 {
		return live.Verdict{Live: true, Evidence: extra}, nil
	}
	return live.Verdict{}, nil
}

func (l *fakeLive) StillQuiet(ctx context.Context, s live.Subject, snaps map[string]fsx.Stat) (bool, error) {
	l.mu.Lock()
	nq := l.notQuiet
	_, isLive := l.verdicts[s.Key]
	l.mu.Unlock()
	if nq || isLive {
		return false, nil
	}
	for p, snap := range snaps {
		st, err := fsx.Lstat(p)
		if err != nil {
			continue
		}
		if !st.Unchanged(snap) {
			return false, nil
		}
	}
	return true, nil
}

// ---------------------------------------------------------------- ledger

type fakeLedger struct {
	mu       sync.Mutex
	raw      map[string][]byte
	sessions map[string][]ledger.Session
	archived map[string]int64
}

func newFakeLedger() *fakeLedger {
	return &fakeLedger{raw: map[string][]byte{}, sessions: map[string][]ledger.Session{}, archived: map[string]int64{}}
}

func (l *fakeLedger) Snapshot(h, sid string) ([]byte, int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.raw[h+"/"+sid]
	return append([]byte(nil), b...), int64(len(b)), nil
}

func (l *fakeLedger) Archive(h, sid string, n int64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.archived[h+"/"+sid] = n
	b := l.raw[h+"/"+sid]
	if int64(len(b)) >= n {
		l.raw[h+"/"+sid] = b[n:]
	}
	return nil
}

func (l *fakeLedger) List(h string) ([]ledger.Session, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]ledger.Session(nil), l.sessions[h]...), nil
}

// ---------------------------------------------------------------- vaults

type fakeVaults struct {
	mu       sync.Mutex
	tripwire map[string]bool
}

func (v *fakeVaults) recipients(id string) (recipientSet, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.tripwire[id] {
		return recipientSet{}, ErrTripwire
	}
	return recipientSet{fpr: "fpr-" + id, apply: func(*capsule.SealRequest) {}}, nil
}

// ---------------------------------------------------------------- git, busy

type fakeGit struct {
	tracked map[string]map[string]bool
	err     error
	calls   int
}

func (g *fakeGit) Tracked(ctx context.Context, repo string) (map[string]bool, error) {
	g.calls++
	if g.err != nil {
		return nil, g.err
	}
	return g.tracked[repo], nil
}

type fakeBusy struct{ busy bool }

func (b *fakeBusy) RootBusy(context.Context, Env, string) (bool, error) { return b.busy, nil }

// ---------------------------------------------------------------- keys

// fakeKeys releases the file key of each requested logged capsule (the
// daemon's job, D39), recording purposes; deny refuses everything.
type fakeKeys struct {
	mu        sync.Mutex
	capsules  string
	deny      bool
	purposes  []string
	requested []string
	sets      []*fakeKeySet
}

type fakeKeySet struct {
	mu        sync.Mutex
	keys      map[string]*memguard.LockedBuffer
	destroyed bool
}

func (k *fakeKeys) FileKeys(ctx context.Context, ps []string, purpose string) (FileKeys, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.purposes = append(k.purposes, purpose)
	k.requested = append(k.requested, ps...)
	if k.deny {
		return nil, ErrKeyDenied
	}
	set := &fakeKeySet{keys: map[string]*memguard.LockedBuffer{}}
	for _, p := range ps {
		b, err := os.ReadFile(filepath.Join(k.capsules, filepath.FromSlash(p)))
		if err != nil {
			continue
		}
		h, _, err := splitFake(b)
		if err != nil {
			continue
		}
		set.keys[p] = memguard.NewBufferFromBytes(fakeFileKey(h))
	}
	k.sets = append(k.sets, set)
	return set, nil
}

func (s *fakeKeySet) Key(p string) (*memguard.LockedBuffer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.keys[p]
	return b, ok && !s.destroyed
}

func (s *fakeKeySet) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return
	}
	s.destroyed = true
	for _, b := range s.keys {
		b.Destroy()
	}
}

func (k *fakeKeys) allDestroyed() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, s := range k.sets {
		s.mu.Lock()
		d := s.destroyed
		s.mu.Unlock()
		if !d {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- links

// testScanLinks reads JSONL records ({"uuid","parentUuid",
// "logicalParentUuid"}) like claude.ScanLinks.
func testScanLinks(ctx context.Context, r io.Reader) (claude.Links, error) {
	l := claude.Links{UUIDs: map[string]bool{}, Valid: true}
	br := bufio.NewReader(r)
	first := true
	var last byte
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			last = line[len(line)-1]
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 {
				var rec struct {
					UUID       string  `json:"uuid"`
					Parent     *string `json:"parentUuid"`
					LogicalPar *string `json:"logicalParentUuid"`
				}
				if json.Unmarshal(trimmed, &rec) != nil {
					l.Valid = false
				} else {
					if rec.UUID != "" {
						l.UUIDs[rec.UUID] = true
					}
					if first {
						if rec.Parent != nil {
							l.FirstParent = *rec.Parent
						}
						if rec.LogicalPar != nil {
							l.FirstLogicalParent = *rec.LogicalPar
						}
						first = false
					}
					l.Records++
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return l, err
		}
	}
	l.TrailingNL = last == '\n'
	return l, nil
}

// testHistoryLine parses claudetest history lines.
func testHistoryLine(b []byte) claude.HistoryLine {
	var raw struct {
		Project   string `json:"project"`
		SessionID string `json:"sessionId"`
		Timestamp int64  `json:"timestamp"`
		Pasted    map[string]struct {
			ContentHash string `json:"contentHash"`
		} `json:"pastedContents"`
	}
	if json.Unmarshal(b, &raw) != nil {
		return claude.HistoryLine{Raw: b}
	}
	hl := claude.HistoryLine{Raw: b, Project: raw.Project, SessionID: raw.SessionID,
		Timestamp: time.UnixMilli(raw.Timestamp).UTC(), Valid: true}
	for _, p := range raw.Pasted {
		if p.ContentHash != "" {
			hl.PasteRefs = append(hl.PasteRefs, p.ContentHash+".txt")
		}
	}
	sort.Strings(hl.PasteRefs)
	return hl
}

// testCodexClass mirrors the codex SQLite classes for synthetic homes.
func testCodexClass(rel string) codex.Class {
	switch {
	case strings.HasSuffix(rel, "-shm"):
		return codex.ClassSHM
	case strings.HasSuffix(rel, "-wal"), strings.HasSuffix(rel, "-journal"):
		return codex.ClassSQLiteSide
	case strings.HasSuffix(rel, ".sqlite"):
		return codex.ClassSQLiteMain
	}
	return codex.ClassContent
}

// ---------------------------------------------------------------- adapter

// fakeAdapter is a harness.Adapter over synthetic layouts: Claude-like
// sessions found fail-closed by session id, Codex-like per-root homes,
// or explicit units.
type fakeAdapter struct {
	te       *testEnv
	id       harness.ID
	homes    []harness.Home
	sids     []string // claude: session ids to inventory
	codex    map[string]string
	probe    map[string][]live.Evidence
	probeErr error
	mdPaths  map[string][]string
	allow    func(ref harness.UnitRef, unitID string, b capsule.BaseID, rel string) bool
	extra    []harness.Unit
}

func (a *fakeAdapter) ID() harness.ID { return a.id }
func (a *fakeAdapter) Homes(ctx context.Context, e harness.Env) ([]harness.Home, error) {
	return a.homes, nil
}

// sessionUnit inventories one Claude-like session (fail closed, I10): every
// regular file whose path has a component equal to the sid or a basename
// starting with "<sid>." or "<sid>-".
func (a *fakeAdapter) sessionUnit(h harness.Home, sid string) (harness.Unit, bool) {
	key, err := harness.UnitKeyFor(a.te.e.Harness.Salt, capsule.KindClaudeSession, harness.ClaudeCode, h.ID, "", sid)
	if err != nil {
		a.te.t.Fatal(err)
	}
	u := harness.Unit{Harness: harness.ClaudeCode, Kind: capsule.KindClaudeSession, Key: key, UnitID: sid, VaultID: rootID,
		RootIDs: []string{rootID}, Home: h, Mode: harness.GenLayered}
	match := func(rel string) bool {
		for _, c := range strings.Split(rel, "/") {
			if c == sid || strings.HasPrefix(c, sid+".") || strings.HasPrefix(c, sid+"-") {
				return true
			}
		}
		return false
	}
	for _, b := range []capsule.BaseID{capsule.BaseClaudeConfig, capsule.BaseClaudeTmp} {
		dir := h.Bases[b]
		if dir == "" {
			continue
		}
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			rel, _ := filepath.Rel(dir, p)
			rel = filepath.ToSlash(rel)
			if rel == "." {
				return nil
			}
			st, err := fsx.Lstat(p)
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if match(rel) {
					u.Prune = append(u.Prune, string(b)+":"+rel)
				}
				return nil
			}
			if !match(rel) {
				return nil
			}
			if !st.IsRegular() || st.Nlink > 1 {
				u.Hazards = append(u.Hazards, harness.Hazard{Base: b, Rel: rel, Hazard: hazardOf(st)})
				return nil
			}
			f := harness.File{Base: b, Rel: rel, Snap: st, Placement: harness.PlaceExact}
			if strings.HasSuffix(rel, ".jsonl") {
				f.Placement, f.Append = harness.PlaceJSONLAppend, true
			}
			if path.Base(rel) == sid+".jsonl" {
				f.Last = true
			}
			u.Files = append(u.Files, f)
			return nil
		})
	}
	return u, len(u.Files) > 0
}

// codexUnit inventories a per-root home: every file except -shm.
func (a *fakeAdapter) codexUnit(rootID, home string) (harness.Unit, bool) {
	key, err := harness.UnitKeyFor(a.te.e.Harness.Salt, capsule.KindCodexHome, harness.Codex, "", rootID, "")
	if err != nil {
		a.te.t.Fatal(err)
	}
	h := harness.Home{Harness: harness.Codex, ID: "c0dec0dec0dec0de", Bases: map[capsule.BaseID]string{capsule.BaseCodexHome: home}, RootID: rootID}
	u := harness.Unit{Harness: harness.Codex, Kind: capsule.KindCodexHome, Key: key, UnitID: rootID, VaultID: rootID,
		RootIDs: []string{rootID}, Home: h, Mode: harness.GenSnapshot}
	_ = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(home, p)
		rel = filepath.ToSlash(rel)
		if testCodexClass(rel) == codex.ClassSHM || codexNeverTouch(rel) {
			return nil
		}
		st, err := fsx.Lstat(p)
		if err != nil || !st.IsRegular() {
			return nil
		}
		f := harness.File{Base: capsule.BaseCodexHome, Rel: rel, Snap: st, Placement: harness.PlaceExact}
		if g := sqliteGroup(rel); g != "" {
			f.Group, f.Placement = g, harness.PlaceSQLiteGroup
		}
		u.Files = append(u.Files, f)
		return nil
	})
	return u, len(u.Files) > 0
}

// codexNeverTouch mirrors the never-touch list of SPEC §7.2.
func codexNeverTouch(rel string) bool {
	first, _, _ := strings.Cut(rel, "/")
	switch first {
	case "auth.json", "config.toml", "hooks.json", "plugins", "skills", "cache", "packages", "models_cache.json",
		"installation_id", "version.json", ".tmp", "tmp", "thread-writer-locks", "app-server-control", "log",
		"rollout-maintenance.lock":
		return true
	}
	return false
}

func sqliteGroup(rel string) string {
	for _, suf := range []string{"-wal", "-journal"} {
		if strings.HasSuffix(rel, ".sqlite"+suf) {
			return strings.TrimSuffix(rel, suf)
		}
	}
	if strings.HasSuffix(rel, ".sqlite") {
		return rel
	}
	return ""
}

func (a *fakeAdapter) Scan(ctx context.Context, e harness.Env, s harness.Scope) ([]harness.Unit, error) {
	var out []harness.Unit
	inScope := func(u harness.Unit) bool {
		if len(s.RootIDs) > 0 {
			ok := false
			for _, id := range u.RootIDs {
				if contains(s.RootIDs, id) {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
		if len(s.SIDs) > 0 && !contains(s.SIDs, u.UnitID) {
			return false
		}
		if len(s.Kinds) > 0 {
			ok := false
			for _, k := range s.Kinds {
				if k == u.Kind {
					ok = true
				}
			}
			return ok
		}
		return true
	}
	for _, h := range a.homes {
		for _, sid := range a.sids {
			if u, ok := a.sessionUnit(h, sid); ok && inScope(u) {
				out = append(out, u)
			}
		}
	}
	for root, home := range a.codex {
		if u, ok := a.codexUnit(root, home); ok && inScope(u) {
			out = append(out, u)
		}
	}
	for _, u := range a.extra {
		if inScope(u) {
			out = append(out, u)
		}
	}
	return out, nil
}

func (a *fakeAdapter) Probe(ctx context.Context, e harness.Env, u harness.Unit) ([]live.Evidence, error) {
	if a.probeErr != nil {
		return nil, a.probeErr
	}
	return a.probe[u.Key], nil
}

func (a *fakeAdapter) Targets(ctx context.Context, e harness.Env, ref harness.UnitRef, unitID string) (harness.TargetRules, error) {
	bases := map[capsule.BaseID]string{}
	for _, h := range a.homes {
		if h.ID == ref.HomeID || ref.Kind == capsule.KindCodexHome {
			for k, v := range h.Bases {
				bases[k] = v
			}
		}
	}
	if ref.Kind == capsule.KindCodexHome || ref.Kind == capsule.KindCodexBlob {
		for root, home := range a.codex {
			if contains(ref.RootIDs, root) {
				bases = map[capsule.BaseID]string{capsule.BaseCodexHome: home}
			}
		}
	}
	allow := func(b capsule.BaseID, rel string) bool {
		if _, ok := bases[b]; !ok || !cleanRel(rel) {
			return false
		}
		if a.allow != nil {
			return a.allow(ref, unitID, b, rel)
		}
		if ref.Kind == capsule.KindClaudeSession {
			for _, c := range strings.Split(rel, "/") {
				if c == unitID || strings.HasPrefix(c, unitID+".") || strings.HasPrefix(c, unitID+"-") {
					return true
				}
			}
			return false
		}
		return true
	}
	policy := func(en capsule.Entry) harness.Placement {
		switch {
		case en.Group != "":
			return harness.PlaceSQLiteGroup
		case strings.HasSuffix(en.Rel, ".jsonl"):
			return harness.PlaceJSONLAppend
		}
		return harness.PlaceExact
	}
	mode := harness.GenLayered
	if ref.Kind == capsule.KindCodexHome {
		mode = harness.GenSnapshot
	}
	return harness.TargetRules{Bases: bases, Allow: allow, Policy: policy, Mode: mode}, nil
}

func (a *fakeAdapter) PlanLaunch(ctx context.Context, e harness.Env, cwd string, argv []string) (harness.LaunchPlan, error) {
	return harness.LaunchPlan{}, errors.New("fake: no launch plans")
}

func (a *fakeAdapter) MarkdownPaths(ctx context.Context, e harness.Env, u harness.Unit) ([]string, error) {
	return a.mdPaths[u.UnitID], nil
}

func (a *fakeAdapter) Describe(ctx context.Context, e harness.Env, u harness.Unit) (string, time.Time, error) {
	return "title of " + u.UnitID, time.Time{}, nil
}

// ---------------------------------------------------------------- env

const rootID = "root-acme"

// testEnv is a fake HOME (testkit) with every port faked.
type testEnv struct {
	t       *testing.T
	h       *testkit.Home
	e       Env
	p       ports
	fs      *osFS
	codec   *fakeCodec
	live    *fakeLive
	ledger  *fakeLedger
	vaults  *fakeVaults
	git     *fakeGit
	busy    *fakeBusy
	keys    *fakeKeys
	claude  *fakeAdapter
	codexAd *fakeAdapter
	cc      harness.Home
	sleptMu sync.Mutex
	slept   []time.Duration
}

// testSalt is the fixed name salt of test homes (00 01 … 1f, TESTPLAN §8).
func testSalt() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvWith(t, testkit.NewHome(t))
}

// homeAt rebuilds the testkit.Home of an existing fake home (crash-test
// children work on their parent's home).
func homeAt(t *testing.T, dir, runDir string) *testkit.Home {
	t.Helper()
	h := &testkit.Home{Dir: dir, HomeDir: filepath.Join(dir, "home"), Base: filepath.Join(dir, "base"), RunDir: runDir,
		ClaudeConfig: filepath.Join(dir, "claude"), ClaudeTmp: filepath.Join(dir, "claude-tmp"),
		CodexUser: filepath.Join(dir, "codex-user")}
	h.Root = filepath.Join(h.HomeDir, "work", "acme")
	h.ClaudeCache = filepath.Join(h.HomeDir, "Library", "Caches", "claude-cli-nodejs")
	if runtime.GOOS == "linux" {
		h.ClaudeCache = filepath.Join(dir, "xdg", "cache", "claude-cli-nodejs")
	}
	l, err := paths.LayoutAt(h.Base, runDir)
	mustNoErr(t, err)
	h.Layout = l
	cfg, err := config.Load(l.ConfigFile)
	mustNoErr(t, err)
	h.Cfg = cfg
	h.Clock = fakeplatform.NewClock(testkit.Epoch)
	h.Procs = fakeplatform.NewProcs()
	return h
}

func newTestEnvWith(t *testing.T, h *testkit.Home) *testEnv {
	t.Helper()
	te := &testEnv{t: t, h: h, fs: newOSFS(), codec: &fakeCodec{}, live: newFakeLive(), ledger: newFakeLedger(),
		vaults: &fakeVaults{tripwire: map[string]bool{}}, git: &fakeGit{tracked: map[string]map[string]bool{}}, busy: &fakeBusy{}}
	cfg := h.Cfg
	cfg.Policy.QuietWindow = config.Duration(0)
	te.e = Env{
		Cfg: cfg,
		Harness: harness.Env{Cfg: cfg, Layout: h.Layout, Clock: h.Clock, Procs: h.Procs, Salt: testSalt(),
			Host: paths.FromMap(map[string]string{"HOME": h.HomeDir, "PATH": "/usr/bin:/bin"})},
		Log: capslog.Open(h.Layout.CapsuleLog), Journal: journal.Open(h.Layout.JournalDir),
		Procs: h.Procs, Clock: h.Clock, Sealer: "precinto test", Parallel: 2,
	}
	te.keys = &fakeKeys{capsules: h.Layout.CapsulesDir}
	te.cc = harness.Home{Harness: harness.ClaudeCode, ID: "0123456789abcdef", Default: true, Bases: map[capsule.BaseID]string{
		capsule.BaseClaudeConfig: h.ClaudeConfig, capsule.BaseClaudeTmp: h.ClaudeTmp, capsule.BaseClaudeCache: h.ClaudeCache}}
	te.claude = &fakeAdapter{te: te, id: harness.ClaudeCode, homes: []harness.Home{te.cc}, probe: map[string][]live.Evidence{},
		mdPaths: map[string][]string{}, codex: map[string]string{}}
	te.e.Adapters = []harness.Adapter{te.claude}
	te.p = ports{
		fs: te.fs, codec: te.codec, live: te.live, ledger: te.ledger, vaults: te.vaults, git: te.git, busy: te.busy,
		scanLinks: testScanLinks, historyLine: testHistoryLine, codexClass: testCodexClass,
		sleep: func(ctx context.Context, d time.Duration) error {
			te.sleptMu.Lock()
			te.slept = append(te.slept, d)
			te.sleptMu.Unlock()
			return ctx.Err()
		},
		rescueWait: time.Second, tailQuiet: 50 * time.Millisecond,
	}
	return te
}

func (te *testEnv) run() *run { return newRun(te.e, te.p) }

// unitKey of a Claude session of the default home.
func (te *testEnv) sessionKey(sid string) string {
	k, err := harness.UnitKeyFor(te.e.Harness.Salt, capsule.KindClaudeSession, harness.ClaudeCode, te.cc.ID, "", sid)
	if err != nil {
		te.t.Fatal(err)
	}
	return k
}

// scanSession returns the current unit of a session.
func (te *testEnv) scanSession(sid string) harness.Unit {
	te.t.Helper()
	u, ok := te.claude.sessionUnit(te.cc, sid)
	if !ok {
		te.t.Fatalf("no plaintext for session %s", sid)
	}
	return u
}

// snapshotTree returns path → content hash of every regular file below
// dir (excluding the precinto base), for byte-exact comparisons.
func snapshotTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		st, err := fsx.Lstat(p)
		if err != nil || !st.IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		out[p] = sum(b)
		return nil
	})
	return out
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func exists(p string) bool {
	_, err := fsx.Lstat(p)
	return err == nil
}

// mustNoErr fails on err.
func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// outcome returns the first result for unit (or fails).
func outcome(t *testing.T, rep *Report, unit string) UnitResult {
	t.Helper()
	for _, u := range rep.Units {
		if u.Unit == unit {
			return u
		}
	}
	t.Fatalf("no result for unit %s in %+v", short(unit), rep.Units)
	return UnitResult{}
}

// logged returns the live log entries of a unit.
func (te *testEnv) logged(unit string) []capslog.Entry {
	te.t.Helper()
	en, err := te.e.Log.Unit(unit)
	mustNoErr(te.t, err)
	return en
}

func itoa(n int) string { return strconv.Itoa(n) }
