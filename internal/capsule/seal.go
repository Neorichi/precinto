package capsule

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/fsx/failpoint"
)

// familyX25519 is the only recipient family of v0.1 (D2); it prefixes the
// canonical recipient set (vault.Family).
const familyX25519 = "x25519"

// zstdWindow is the encoder window; readers accept up to MaxZstdWindow.
const zstdWindow = 8 << 20

// newEphemeral generates the in-memory verify identity of one Seal (a seam
// for tests that must reach the header check).
var newEphemeral = age.GenerateX25519Identity

// memberName is the tar member of the n-th regular entry (1-based).
func memberName(n int) string { return fmt.Sprintf("f/%06d", n) }

// stagedName is the flat staging file name of a member ("f/000001" →
// "f000001").
func stagedName(member string) string { return "f" + strings.TrimPrefix(member, "f/") }

// checkRecipients requires exactly {vault, recovery}: two distinct X25519
// recipients (D2, D5). Seal adds the ephemeral one.
func checkRecipients(rs []age.Recipient) (vault, recovery *age.X25519Recipient, err error) {
	if len(rs) != 2 {
		return nil, nil, fmt.Errorf("%w: %d recipients, want vault and recovery", ErrRecipients, len(rs))
	}
	a, ok1 := rs[0].(*age.X25519Recipient)
	b, ok2 := rs[1].(*age.X25519Recipient)
	if !ok1 || !ok2 || a == nil || b == nil {
		return nil, nil, fmt.Errorf("%w: only X25519 recipients are allowed", ErrRecipients)
	}
	if a.String() == b.String() {
		return nil, nil, fmt.Errorf("%w: vault and recovery recipients are the same", ErrRecipients)
	}
	return a, b, nil
}

// validBase accepts the fixed bases and "generic:<name>" (D33).
func validBase(b BaseID) bool {
	switch b {
	case BaseClaudeConfig, BaseClaudeTmp, BaseClaudeCache, BaseCodexHome, BaseRoot:
		return true
	}
	name, ok := strings.CutPrefix(string(b), string(BaseGeneric)+":")
	if !ok || name == "" || len(name) > 64 || name[0] == '.' {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// validRel: local, clean, non-empty (SPEC §5 rule 4).
func validRel(rel string) bool {
	return rel != "" && rel != "." && strings.IndexByte(rel, 0) < 0 && filepath.IsLocal(rel) && filepath.Clean(rel) == rel
}

func validFileName(name string) bool {
	return name != "" && name != "." && name != ".." && name[0] != '.' && !strings.ContainsAny(name, "/\x00")
}

// ctxReader returns ctx's error from Read once ctx ends, so long copies stop
// promptly (R8).
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func phase(r *SealRequest, p Phase, s *Sealed) error {
	if r.OnPhase == nil {
		return nil
	}
	return r.OnPhase(p, s)
}

// changedErr marks a source that vanished or changed (exit 4, D13).
func changedErr(rel string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: %s: %w", ErrChanged, rel, cause)
	}
	return fmt.Errorf("%w: %s", ErrChanged, rel)
}

// openInput opens one source for reading. Rescue inputs are read through
// the caller's descriptor, which is never closed here.
func openInput(in Input) (*os.File, fsx.Stat, func(), error) {
	if in.Open != nil {
		st, err := fsx.Fstat(in.Open)
		if err != nil {
			return nil, fsx.Stat{}, func() {}, err
		}
		return in.Open, st, func() {}, nil
	}
	if in.Dir == nil {
		return nil, fsx.Stat{}, func() {}, fmt.Errorf("capsule: input %s has no directory handle", in.Rel)
	}
	f, st, err := in.Dir.Open(in.Rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			err = changedErr(in.Rel, err)
		}
		return nil, fsx.Stat{}, func() {}, err
	}
	return f, st, func() { f.Close() }, nil
}

// copyInput streams exactly snap.Size bytes of the opened source into w and
// requires its identity to equal snap before and after (D13).
func copyInput(ctx context.Context, w io.Writer, f *os.File, st fsx.Stat, in Input, snap fsx.Stat) (string, error) {
	if !st.IsRegular() {
		return "", fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, in.Rel)
	}
	if !st.Unchanged(snap) {
		return "", changedErr(in.Rel, nil)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), ctxReader{ctx, io.NewSectionReader(f, 0, snap.Size)})
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	if n != snap.Size {
		return "", changedErr(in.Rel, nil)
	}
	after, err := fsx.Fstat(f)
	if err != nil {
		return "", err
	}
	if !after.Unchanged(snap) {
		return "", changedErr(in.Rel, nil)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashInput is pass 1 for one source: open O_NOFOLLOW, fstat == Snap,
// SHA-256 of exactly Snap.Size bytes, identity unchanged afterwards.
func hashInput(ctx context.Context, in Input) (string, fsx.Stat, error) {
	f, st, release, err := openInput(in)
	if err != nil {
		return "", fsx.Stat{}, err
	}
	defer release()
	sum, err := copyInput(ctx, io.Discard, f, st, in, in.Snap)
	return sum, st, err
}

func memberHeader(name string, size int64) *tar.Header {
	return &tar.Header{Typeflag: tar.TypeReg, Name: name, Size: size, Mode: 0o600, ModTime: time.Unix(0, 0)}
}

func seal(ctx context.Context, r SealRequest) (*Sealed, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	vaultR, recoveryR, err := checkRecipients(r.Recipients)
	if err != nil {
		return nil, err
	}
	if r.Out == nil {
		return nil, errors.New("capsule: Seal needs an output directory")
	}
	if !validFileName(r.Name) {
		return nil, fmt.Errorf("%w: bad capsule name %q", ErrUnsafe, r.Name)
	}
	m := r.Manifest
	if m.Format == 0 {
		m.Format = FormatVersion
	}
	if m.Format != FormatVersion {
		return nil, fmt.Errorf("%w: manifest format %d", ErrFormat, m.Format)
	}
	fpr := RecipientsFingerprint(familyX25519, []string{vaultR.String(), recoveryR.String()})
	if m.RecipientsFpr == "" {
		m.RecipientsFpr = fpr
	} else if m.RecipientsFpr != fpr {
		return nil, fmt.Errorf("%w: manifest recipients_fpr does not match the recipients", ErrRecipients)
	}
	if len(r.Inputs)+len(r.Dirs) > MaxEntries {
		return nil, fmt.Errorf("%w: %d entries", ErrTooLarge, len(r.Inputs)+len(r.Dirs))
	}

	// Pass 1: hash every source and build the manifest.
	entries := make([]Entry, 0, len(r.Inputs)+len(r.Dirs))
	snaps := make([]fsx.Stat, len(r.Inputs))
	for i, in := range r.Inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !validBase(in.Base) || !validRel(in.Rel) {
			return nil, fmt.Errorf("%w: input %q:%q", ErrUnsafe, in.Base, in.Rel)
		}
		sum, st, err := hashInput(ctx, in)
		if err != nil {
			return nil, err
		}
		snaps[i] = st
		entries = append(entries, Entry{
			Name: memberName(i + 1), Base: in.Base, Rel: in.Rel, Path: in.Path,
			Mode: st.Mode & 0o7777, MtimeNS: st.MtimeNS, Size: st.Size, SHA256: sum,
			Group: in.Group, Append: in.Append,
		})
	}
	for _, de := range r.Dirs {
		if !validBase(de.Base) || !validRel(de.Rel) {
			return nil, fmt.Errorf("%w: member-less entry %q:%q", ErrUnsafe, de.Base, de.Rel)
		}
		e, err := memberless(de)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if err := checkConflicts(entries, false); err != nil {
		return nil, err
	}
	m.Files = entries
	mj, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("capsule: manifest: %w", err)
	}
	if len(mj) > MaxManifestBytes {
		return nil, fmt.Errorf("%w: manifest of %d bytes", ErrTooLarge, len(mj))
	}
	s := &Sealed{Name: r.Name, Path: filepath.Join(r.Out.Path(), r.Name), Manifest: m, Snaps: snaps}
	if err := phase(&r, PhaseHashed, s); err != nil {
		return nil, err
	}

	// Pass 2: stream magic+zstd(tar) through age into the temporary.
	tmp := TmpName(r.Name)
	f, _, err := r.Out.CreateTemp("", tmp)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			f.Close()
			_ = r.Out.Remove(tmp)
		}
	}()
	eph, err := newEphemeral() // in memory only, never serialized
	if err != nil {
		return nil, err
	}
	if err := writePayload(ctx, f, mj, r.Inputs, entries, snaps, vaultR, recoveryR, eph.Recipient()); err != nil {
		return nil, err
	}
	if err := fsx.FullSync(f); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := failpoint.Hit("capsule.tmp_written"); err != nil {
		return nil, err
	}
	if err := phase(&r, PhaseTmpWritten, s); err != nil {
		return nil, err
	}

	// Ephemeral round trip and header check (D13, D5).
	sum, size, hdrSum, err := verifyTemp(ctx, r.Out, tmp, eph, mj, entries)
	if err != nil {
		return nil, err
	}
	s.SHA256, s.Size, s.HeaderSHA256 = sum, size, hdrSum
	if err := failpoint.Hit("capsule.verified"); err != nil {
		return nil, err
	}
	if err := phase(&r, PhaseVerified, s); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Commit: no-replace rename (never overwrite a generation, I11).
	if err := r.Out.Rename(tmp, r.Name, fsx.NoReplace); err != nil {
		if !errors.Is(err, fsx.ErrExist) {
			// The rename may have happened with only the directory fsync
			// failing: then the capsule is left for journal recovery.
			if _, lerr := r.Out.Lstat(tmp); errors.Is(lerr, fs.ErrNotExist) {
				if _, ferr := r.Out.Lstat(r.Name); ferr == nil {
					committed = true
				}
			}
		}
		return nil, err
	}
	committed = true
	if err := failpoint.Hit("capsule.renamed"); err != nil {
		return nil, err
	}
	if err := phase(&r, PhaseCommitted, s); err != nil {
		return nil, err
	}
	return s, nil
}

// memberless records one SealRequest.Dirs entry as given: an empty
// directory (Dir) or, for codex-home snapshot manifests, a file whose bytes
// live in a blob capsule (Blob, with Size and SHA256 as recorded). Anything
// else, or an entry that is both, is refused: it would carry no data.
func memberless(de Entry) (Entry, error) {
	switch {
	case de.Dir && de.Blob == "" && de.Size == 0 && de.SHA256 == "":
		return Entry{Base: de.Base, Rel: de.Rel, Path: de.Path, Dir: true, Mode: de.Mode & 0o7777, MtimeNS: de.MtimeNS}, nil
	case !de.Dir && de.Blob != "":
		if !isLowerHex(de.Blob, 32) || !isLowerHex(de.SHA256, 64) || de.Size < 0 {
			return Entry{}, fmt.Errorf("%w: blob entry %q:%q needs a 32-hex unit key, a sha256 and a size", ErrFormat, de.Base, de.Rel)
		}
		return Entry{Base: de.Base, Rel: de.Rel, Path: de.Path, Mode: de.Mode & 0o7777, MtimeNS: de.MtimeNS,
			Size: de.Size, SHA256: de.SHA256, Blob: de.Blob, Group: de.Group, Append: de.Append}, nil
	case de.Dir:
		return Entry{}, fmt.Errorf("%w: directory entry %q:%q carries file data", ErrFormat, de.Base, de.Rel)
	default:
		return Entry{}, fmt.Errorf("%w: entry %q:%q is neither an empty directory nor a blob file", ErrFormat, de.Base, de.Rel)
	}
}

func writePayload(ctx context.Context, f *os.File, mj []byte, inputs []Input, entries []Entry, snaps []fsx.Stat, recipients ...age.Recipient) error {
	bw := bufio.NewWriterSize(f, 1<<20)
	aw, err := age.Encrypt(bw, recipients...)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(aw, Magic); err != nil {
		return err
	}
	zw, err := zstd.NewWriter(aw, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(zstdWindow))
	if err != nil {
		return err
	}
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(memberHeader(ManifestName, int64(len(mj)))); err != nil {
		return err
	}
	if _, err := tw.Write(mj); err != nil {
		return err
	}
	for i, in := range inputs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := streamInput(ctx, tw, in, entries[i], snaps[i]); err != nil {
			return err
		}
		// SEAL-2: a kill here leaves a partial temporary (and only that).
		if err := failpoint.Hit("capsule.streamed"); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := aw.Close(); err != nil {
		return err
	}
	return bw.Flush()
}

// streamInput is pass 2 for one source: reopen, require the pass-1
// identity, stream it while re-hashing, and require the same hash.
func streamInput(ctx context.Context, tw *tar.Writer, in Input, e Entry, snap fsx.Stat) error {
	f, st, release, err := openInput(in)
	if err != nil {
		return err
	}
	defer release()
	if !st.Unchanged(snap) {
		return changedErr(in.Rel, nil)
	}
	if err := tw.WriteHeader(memberHeader(e.Name, e.Size)); err != nil {
		return err
	}
	sum, err := copyInput(ctx, tw, f, st, in, snap)
	if err != nil {
		return err
	}
	if sum != e.SHA256 {
		return changedErr(in.Rel, nil)
	}
	return nil
}

// verifyTemp decrypts the temporary with the ephemeral identity and
// requires the exact manifest bytes, every member hash and a header of
// exactly HeaderStanzas X25519 stanzas. It returns the SHA-256 and size of
// the whole file and the SHA-256 of its header.
func verifyTemp(ctx context.Context, out *fsx.Dir, tmp string, eph *age.X25519Identity, mj []byte, entries []Entry) (string, int64, string, error) {
	f, st, err := out.Open(tmp)
	if err != nil {
		return "", 0, "", fmt.Errorf("%w: %w", ErrVerify, err)
	}
	defer f.Close()
	h := sha256.New()
	counted := &countWriter{w: h}
	if err := verifyPayload(ctx, io.TeeReader(f, counted), eph, mj, entries); err != nil {
		if ctx.Err() != nil {
			return "", 0, "", ctx.Err()
		}
		return "", 0, "", fmt.Errorf("%w: %w", ErrVerify, err)
	}
	if _, err := io.Copy(counted, f); err != nil {
		return "", 0, "", fmt.Errorf("%w: %w", ErrVerify, err)
	}
	if counted.n != st.Size {
		return "", 0, "", fmt.Errorf("%w: temporary changed while verifying", ErrVerify)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", 0, "", err
	}
	hdr, err := age.ExtractHeader(f)
	if err != nil {
		return "", 0, "", fmt.Errorf("%w: %w", ErrVerify, err)
	}
	if err := checkHeaderBytes(hdr, HeaderStanzas); err != nil {
		return "", 0, "", err
	}
	hs := sha256.Sum256(hdr)
	return hex.EncodeToString(h.Sum(nil)), st.Size, hex.EncodeToString(hs[:]), nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func verifyPayload(ctx context.Context, src io.Reader, eph *age.X25519Identity, mj []byte, entries []Entry) error {
	p, err := openPayload(src, eph)
	if err != nil {
		return err
	}
	defer p.close()
	_, raw, err := p.manifest()
	if err != nil {
		return err
	}
	if string(raw) != string(mj) {
		return errors.New("manifest differs from the one written")
	}
	for _, e := range entries {
		if e.Dir || e.Blob != "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := p.next(e.Name, e.Size, 0); err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(h, ctxReader{ctx, p.tr})
		if err != nil {
			return err
		}
		if n != e.Size || hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
			return fmt.Errorf("member %s does not match its manifest entry", e.Name)
		}
	}
	return p.finish()
}
