package capsule

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"

	"github.com/precinto/precinto/internal/fsx"
)

// stanzaRecorder is an age.Identity that unwraps nothing and records the
// header's stanzas, so that headers are parsed by age's own parser.
type stanzaRecorder struct {
	called  bool
	stanzas []*age.Stanza
}

func (s *stanzaRecorder) Unwrap(st []*age.Stanza) ([]byte, error) {
	s.called = true
	s.stanzas = append([]*age.Stanza(nil), st...)
	return nil, age.ErrIncorrectIdentity
}

var stanzaB64 = base64.RawStdEncoding.Strict()

// checkHeaderBytes requires exactly want X25519 stanzas (one 32-byte share
// argument, a 32-byte wrapped key) and nothing else (D2, D5).
func checkHeaderBytes(header []byte, want int) error {
	rec := &stanzaRecorder{}
	_, err := age.DecryptHeader(header, rec)
	if !rec.called {
		return fmt.Errorf("%w: %w", ErrHeader, err)
	}
	if len(rec.stanzas) != want {
		return fmt.Errorf("%w: %d stanzas, want %d", ErrHeader, len(rec.stanzas), want)
	}
	for _, s := range rec.stanzas {
		if s.Type != "X25519" || len(s.Args) != 1 || len(s.Body) != 32 {
			return fmt.Errorf("%w: a %q stanza", ErrHeader, s.Type)
		}
		if share, err := stanzaB64.DecodeString(s.Args[0]); err != nil || len(share) != 32 {
			return fmt.Errorf("%w: malformed X25519 stanza", ErrHeader)
		}
	}
	return nil
}

func checkHeader(r io.Reader, want int) error {
	hdr, err := age.ExtractHeader(r)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHeader, err)
	}
	return checkHeaderBytes(hdr, want)
}

func readHeader(dir *fsx.Dir, name string) ([]byte, string, error) {
	if dir == nil {
		return nil, "", errors.New("capsule: ReadHeader needs a directory")
	}
	f, _, err := dir.Open(name)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	hdr, err := age.ExtractHeader(f)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrFormat, err)
	}
	sum := sha256.Sum256(hdr)
	return hdr, hex.EncodeToString(sum[:]), nil
}

func hashFile(dir *fsx.Dir, name string) (string, int64, error) {
	if dir == nil {
		return "", 0, errors.New("capsule: HashFile needs a directory")
	}
	f, st, err := dir.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	after, err := fsx.Fstat(f)
	if err != nil {
		return "", 0, err
	}
	if n != st.Size || !after.Unchanged(st) {
		return "", 0, fmt.Errorf("%w: %s changed while hashing", ErrChanged, name)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// saltSize is the size of state/name.salt (D45).
const saltSize = 32

func loadSalt(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%w: salt path %q", ErrUnsafe, path)
	}
	dir, name := filepath.Dir(path), filepath.Base(path)
	d, err := fsx.OpenBase(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	for attempt := 0; attempt < 3; attempt++ {
		salt, err := readSalt(d, name)
		if err == nil {
			return salt, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		// Write a temporary, then link it to the final name: link fails if
		// another process created the salt first, so every process agrees
		// on one salt and a torn salt is never visible.
		salt = make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		f, tmp, err := d.CreateTemp("", "."+name+".tmp-*")
		if err != nil {
			return nil, err
		}
		_, werr := f.Write(salt)
		if werr == nil {
			werr = fsx.FullSync(f)
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			_ = d.Remove(tmp)
			return nil, werr
		}
		lerr := d.Link(tmp, name)
		_ = d.Remove(tmp)
		if lerr == nil {
			return salt, nil
		}
		if !errors.Is(lerr, fsx.ErrExist) {
			return nil, lerr
		}
	}
	return nil, fmt.Errorf("capsule: could not load %s", path)
}

// readSaltPath implements ReadSalt: never creates anything.
func readSaltPath(path string) ([]byte, bool, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, false, fmt.Errorf("%w: salt path %q", ErrUnsafe, path)
	}
	d, err := fsx.OpenBase(filepath.Dir(path))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer d.Close()
	salt, err := readSalt(d, filepath.Base(path))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return salt, true, nil
}

// readSalt reads exactly saltSize bytes; any other size is corruption and is
// never repaired silently, since every unit key depends on the salt.
func readSalt(d *fsx.Dir, name string) ([]byte, error) {
	f, st, err := d.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size != saltSize {
		return nil, fmt.Errorf("capsule: %s has %d bytes, want %d (refusing to replace it)", name, st.Size, saltSize)
	}
	salt := make([]byte, saltSize+1)
	n, err := io.ReadFull(f, salt)
	if n != saltSize || err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("capsule: %s changed while reading", name)
	}
	return salt[:saltSize], nil
}

func recipientsFingerprint(family string, recipients []string) string {
	sorted := append([]string(nil), recipients...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(family + "\n" + strings.Join(sorted, "\n")))
	return hex.EncodeToString(sum[:])
}
