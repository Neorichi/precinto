package capsule

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"

	"github.com/Neorichi/precinto/internal/fsx"
)

// fileKeySize is the size of an age file key.
const fileKeySize = 16

// payload is an open capsule plaintext stream: age → magic → zstd → tar.
type payload struct {
	ar io.Reader
	zr *zstd.Decoder
	tr *tar.Reader
}

func openPayload(src io.Reader, id age.Identity) (*payload, error) {
	ar, err := age.Decrypt(src, id)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerify, err)
	}
	var magic [len(Magic)]byte
	if _, err := io.ReadFull(ar, magic[:]); err != nil {
		return nil, fmt.Errorf("%w: reading the magic: %w", ErrFormat, err)
	}
	if string(magic[:]) != Magic {
		return nil, fmt.Errorf("%w: bad magic", ErrFormat)
	}
	zr, err := zstd.NewReader(ar,
		zstd.WithDecoderMaxWindow(MaxZstdWindow),
		zstd.WithDecoderMaxMemory(MaxZstdMemory),
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	return &payload{ar: ar, zr: zr, tr: tar.NewReader(zr)}, nil
}

func (p *payload) close() { p.zr.Close() }

// next reads the next member header and requires it to be a plain regular
// member named name of exactly size bytes (size < 0: at most max bytes).
func (p *payload) next(name string, size, max int64) (*tar.Header, error) {
	h, err := p.tr.Next()
	if err == io.EOF {
		return nil, fmt.Errorf("%w: missing member %s", ErrFormat, name)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	if err := checkMember(h); err != nil {
		return nil, err
	}
	if h.Name != name {
		return nil, fmt.Errorf("%w: member %q where %q was expected", ErrFormat, h.Name, name)
	}
	switch {
	case size >= 0 && h.Size != size:
		return nil, fmt.Errorf("%w: member %s has %d bytes, the manifest says %d", ErrFormat, name, h.Size, size)
	case size < 0 && h.Size > max:
		return nil, fmt.Errorf("%w: member %s has %d bytes (limit %d)", ErrTooLarge, name, h.Size, max)
	}
	return h, nil
}

// checkMember refuses everything but plain regular members: links,
// directories, devices, sparse files, GNU long names and any PAX record
// other than the size of a member above 8 GiB (SPEC §5 rule 2).
func checkMember(h *tar.Header) error {
	if h.Typeflag != tar.TypeReg {
		return fmt.Errorf("%w: member %q has type flag %q", ErrFormat, h.Name, h.Typeflag)
	}
	if h.Linkname != "" {
		return fmt.Errorf("%w: member %q has a link name", ErrFormat, h.Name)
	}
	if h.Format != tar.FormatUSTAR && h.Format != tar.FormatPAX {
		return fmt.Errorf("%w: member %q uses tar format %v", ErrFormat, h.Name, h.Format)
	}
	for k := range h.PAXRecords {
		if k != "size" {
			return fmt.Errorf("%w: member %q carries a PAX %q record", ErrFormat, h.Name, k)
		}
	}
	if h.Size < 0 {
		return fmt.Errorf("%w: member %q has a negative size", ErrFormat, h.Name)
	}
	return nil
}

// manifest reads MANIFEST.json (at most MaxManifestBytes) and decodes it
// strictly.
func (p *payload) manifest() (Manifest, []byte, error) {
	h, err := p.next(ManifestName, -1, MaxManifestBytes)
	if err != nil {
		return Manifest{}, nil, err
	}
	raw := make([]byte, h.Size)
	if _, err := io.ReadFull(p.tr, raw); err != nil {
		return Manifest{}, nil, fmt.Errorf("%w: reading the manifest: %w", ErrFormat, err)
	}
	m, err := decodeManifest(raw)
	if err != nil {
		return Manifest{}, nil, err
	}
	return m, raw, nil
}

func decodeManifest(raw []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: manifest: %w", ErrFormat, err)
	}
	if dec.More() {
		return Manifest{}, fmt.Errorf("%w: trailing data after the manifest", ErrFormat)
	}
	if m.Format != FormatVersion {
		return Manifest{}, fmt.Errorf("%w: manifest format %d", ErrFormat, m.Format)
	}
	return m, nil
}

// finish requires the end of the archive, then the end of the zstd stream,
// then the end of the authenticated age stream: no trailing members or
// bytes, and no truncation.
func (p *payload) finish() error {
	h, err := p.tr.Next()
	if err == nil {
		return fmt.Errorf("%w: trailing member %q", ErrFormat, h.Name)
	}
	if err != io.EOF {
		return fmt.Errorf("%w: %w", ErrFormat, err)
	}
	var b [1]byte
	if n, err := io.ReadFull(p.zr, b[:]); n != 0 || err != io.EOF {
		if n != 0 {
			return fmt.Errorf("%w: trailing data after the archive", ErrFormat)
		}
		return fmt.Errorf("%w: %w", ErrFormat, err)
	}
	if n, err := io.ReadFull(p.ar, b[:]); n != 0 || err != io.EOF {
		if n != 0 {
			return fmt.Errorf("%w: trailing data after the compressed stream", ErrFormat)
		}
		return fmt.Errorf("%w: %w", ErrVerify, err)
	}
	return nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// conflictKey orders entries so that every path sorts right before its
// descendants ('/' becomes the lowest byte).
func conflictKey(e Entry, fold bool) string {
	rel := e.Rel
	if fold {
		rel = strings.ToLower(rel)
	}
	return string(e.Base) + "\x01" + strings.ReplaceAll(rel, "/", "\x00")
}

// checkConflicts refuses two entries for the same path and an entry below
// another one (files have no children; directory entries are empty
// directories). fold compares case-insensitively, as a darwin volume would.
func checkConflicts(entries []Entry, fold bool) error {
	keys := make([]string, len(entries))
	for i, e := range entries {
		keys[i] = conflictKey(e, fold)
	}
	sort.Strings(keys)
	for i := 1; i < len(keys); i++ {
		if keys[i] == keys[i-1] || strings.HasPrefix(keys[i], keys[i-1]+"\x00") {
			return fmt.Errorf("%w: conflicting entries for the same path", ErrUnsafe)
		}
	}
	return nil
}

// validateManifest checks every entry of an untrusted manifest before
// anything is written: structure, member numbering, limits, local clean
// paths, conflicts, and the caller's target check (D8).
func validateManifest(m *Manifest, lim Limits, check func(Entry) error) error {
	maxFiles := lim.MaxFiles
	if maxFiles <= 0 || maxFiles > MaxEntries {
		maxFiles = MaxEntries
	}
	if len(m.Files) > maxFiles {
		return fmt.Errorf("%w: %d entries (limit %d)", ErrTooLarge, len(m.Files), maxFiles)
	}
	var total int64
	next := 1
	for i, e := range m.Files {
		if e.Size < 0 {
			return fmt.Errorf("%w: entry %d has a negative size", ErrFormat, i)
		}
		if !validBase(e.Base) || !validRel(e.Rel) {
			return fmt.Errorf("%w: entry %d: base %q, rel %q", ErrUnsafe, i, e.Base, e.Rel)
		}
		switch {
		case e.Dir:
			if e.Name != "" || e.Size != 0 || e.SHA256 != "" || e.Blob != "" {
				return fmt.Errorf("%w: directory entry %d carries file data", ErrFormat, i)
			}
		case e.Blob != "":
			if e.Name != "" || !isLowerHex(e.Blob, 32) || !isLowerHex(e.SHA256, 64) {
				return fmt.Errorf("%w: blob entry %d", ErrFormat, i)
			}
		default:
			if e.Name != memberName(next) {
				return fmt.Errorf("%w: entry %d is member %q, want %q", ErrFormat, i, e.Name, memberName(next))
			}
			next++
			if !isLowerHex(e.SHA256, 64) {
				return fmt.Errorf("%w: entry %d has no valid sha256", ErrFormat, i)
			}
			if total > math.MaxInt64-e.Size {
				return fmt.Errorf("%w: total size overflows", ErrTooLarge)
			}
			total += e.Size
		}
	}
	// A budget ≤ 0 (no free space above the floor) refuses any capsule with
	// plaintext bytes; one of empty files and directories needs none.
	if budget := max(lim.MaxTotal, 0); total > budget {
		return fmt.Errorf("%w: %d bytes of plaintext (budget %d)", ErrTooLarge, total, lim.MaxTotal)
	}
	if err := checkConflicts(m.Files, runtime.GOOS == "darwin"); err != nil {
		return err
	}
	if check == nil {
		return fmt.Errorf("%w: no target check supplied (D8)", ErrUnsafe)
	}
	for i, e := range m.Files {
		if err := check(e); err != nil {
			return fmt.Errorf("%w: entry %d: %w", ErrUnsafe, i, err)
		}
	}
	return nil
}

func openManifest(r io.Reader, fileKey []byte) (Manifest, error) {
	if len(fileKey) != fileKeySize {
		return Manifest{}, fmt.Errorf("%w: file key of %d bytes", ErrFormat, len(fileKey))
	}
	p, err := openPayload(r, age.NewInjectedFileKeyIdentity(fileKey))
	if err != nil {
		return Manifest{}, err
	}
	defer p.close()
	m, _, err := p.manifest()
	return m, err
}

func extract(ctx context.Context, r io.Reader, o ExtractOptions) (Manifest, []Staged, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, nil, err
	}
	if o.Staging == nil || o.Staging.Dir == nil {
		return Manifest{}, nil, errors.New("capsule: Extract needs a staging directory")
	}
	if o.Check == nil {
		return Manifest{}, nil, fmt.Errorf("%w: no target check supplied (D8)", ErrUnsafe)
	}
	if len(o.FileKey) != fileKeySize {
		return Manifest{}, nil, fmt.Errorf("%w: file key of %d bytes", ErrFormat, len(o.FileKey))
	}
	p, err := openPayload(r, age.NewInjectedFileKeyIdentity(o.FileKey))
	if err != nil {
		return Manifest{}, nil, err
	}
	defer p.close()
	m, _, err := p.manifest()
	if err != nil {
		return Manifest{}, nil, err
	}
	if err := validateManifest(&m, o.Limits, o.Check); err != nil {
		return Manifest{}, nil, err
	}
	var staged []Staged
	for _, e := range m.Files {
		if e.Dir || e.Blob != "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return Manifest{}, nil, err
		}
		if _, err := p.next(e.Name, e.Size, 0); err != nil {
			return Manifest{}, nil, err
		}
		s, err := writeStaged(ctx, o.Staging.Dir, p.tr, e)
		if err != nil {
			return Manifest{}, nil, err
		}
		staged = append(staged, s)
	}
	if err := p.finish(); err != nil {
		return Manifest{}, nil, err
	}
	if err := o.Staging.Dir.Sync(); err != nil {
		return Manifest{}, nil, err
	}
	return m, staged, nil
}

// writeStaged writes one member into staging (0600, exclusive create),
// verifies its SHA-256 and FullSyncs it.
func writeStaged(ctx context.Context, dir *fsx.Dir, src io.Reader, e Entry) (Staged, error) {
	f, rel, err := dir.CreateTemp("", stagedName(e.Name))
	if err != nil {
		return Staged{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), ctxReader{ctx, io.LimitReader(src, e.Size)})
	if err != nil {
		if ctx.Err() != nil {
			return Staged{}, ctx.Err()
		}
		if fsx.Classify(err) == fsx.ClassOther {
			err = fmt.Errorf("%w: %w", ErrFormat, err)
		}
		return Staged{}, err
	}
	if n != e.Size {
		return Staged{}, fmt.Errorf("%w: member %s is short", ErrFormat, e.Name)
	}
	if hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
		return Staged{}, fmt.Errorf("%w: member %s does not match its sha256", ErrVerify, e.Name)
	}
	if err := fsx.FullSync(f); err != nil {
		return Staged{}, err
	}
	st, err := fsx.Fstat(f)
	if err != nil {
		return Staged{}, err
	}
	if err := f.Close(); err != nil {
		return Staged{}, err
	}
	return Staged{Entry: e, StagedRel: rel, Stat: st}, nil
}
