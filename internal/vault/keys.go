package vault

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unsafe"

	"filippo.io/age"
	"github.com/awnumar/memguard"
)

// Identity text handling. Vault, recovery and generated identities are
// kept as their age text encoding, "AGE-SECRET-KEY-1" + 58 bech32
// characters, in locked buffers. Encoding and decoding are done here on
// byte slices, so precinto never builds a Go string holding a key; the
// copies age makes while parsing an identity for one operation are the
// residual documented in SPEC §19.

const (
	secretKeyPrefix = "AGE-SECRET-KEY-1"
	secretKeyHRP    = "age-secret-key-"
	secretKeyLen    = len(secretKeyPrefix) + 52 + 6 // 32 bytes in 5-bit groups + checksum
	scalarSize      = 32
	bech32Charset   = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
)

// errBadIdentity never carries any part of the rejected input.
var errBadIdentity = errors.New("vault: malformed identity")

var bech32Gen = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func polymodStep(chk uint32, v byte) uint32 {
	top := chk >> 25
	chk = (chk&0x1ffffff)<<5 ^ uint32(v)
	for i, g := range bech32Gen {
		if (top>>uint(i))&1 == 1 {
			chk ^= g
		}
	}
	return chk
}

func hrpChecksum(hrp string) uint32 {
	chk := uint32(1)
	for i := 0; i < len(hrp); i++ {
		chk = polymodStep(chk, hrp[i]>>5)
	}
	chk = polymodStep(chk, 0)
	for i := 0; i < len(hrp); i++ {
		chk = polymodStep(chk, hrp[i]&31)
	}
	return chk
}

func bech32Value(c byte) int {
	if c >= 'A' && c <= 'Z' {
		c += 'a' - 'A'
	}
	return strings.IndexByte(bech32Charset, c)
}

// encodeSecretKey writes the uppercase age encoding of scalar into dst
// (len secretKeyLen).
func encodeSecretKey(scalar []byte, dst []byte) {
	copy(dst, secretKeyPrefix)
	chk := hrpChecksum(secretKeyHRP)
	j := len(secretKeyPrefix)
	emit := func(v byte) {
		chk = polymodStep(chk, v)
		dst[j] = upperBech32(v)
		j++
	}
	var acc uint32
	bits := 0
	for _, b := range scalar {
		acc = (acc<<8 | uint32(b)) & 0x1fff
		bits += 8
		for bits >= 5 {
			bits -= 5
			emit(byte(acc>>uint(bits)) & 31)
		}
	}
	if bits > 0 {
		emit(byte(acc<<uint(5-bits)) & 31)
	}
	for i := 0; i < 6; i++ {
		chk = polymodStep(chk, 0)
	}
	chk ^= 1
	for i := 0; i < 6; i++ {
		dst[j] = upperBech32(byte(chk>>uint(5*(5-i))) & 31)
		j++
	}
	acc = 0
}

// upperBech32 is the upper-case character of a 5-bit value.
func upperBech32(v byte) byte {
	c := bech32Charset[v]
	if c >= 'a' && c <= 'z' {
		c -= 'a' - 'A'
	}
	return c
}

// decodeSecretKey parses s (exactly the encoding, either case but not
// mixed) into out and wipes its intermediate state.
func decodeSecretKey(s []byte, out []byte) error {
	if len(s) != secretKeyLen || len(out) != scalarSize {
		return errBadIdentity
	}
	upper, lower := false, false
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		}
	}
	if upper && lower {
		return errBadIdentity
	}
	for i := 0; i < len(secretKeyPrefix); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c != secretKeyPrefix[i] {
			return errBadIdentity
		}
	}
	chk := hrpChecksum(secretKeyHRP)
	var acc uint32
	bits, k := 0, 0
	ok := true
	data := s[len(secretKeyPrefix):]
	for i, c := range data {
		v := bech32Value(c)
		if v < 0 {
			ok = false
			break
		}
		chk = polymodStep(chk, byte(v))
		if i >= len(data)-6 {
			continue // checksum characters
		}
		acc = (acc<<5 | uint32(v)) & 0xfff
		bits += 5
		if bits >= 8 {
			bits -= 8
			if k < len(out) {
				out[k] = byte(acc >> uint(bits))
			}
			k++
		}
	}
	padding := acc & (1<<uint(bits) - 1)
	acc = 0
	if !ok || chk != 1 || k != scalarSize || bits >= 5 || padding != 0 {
		memguard.WipeBytes(out)
		return errBadIdentity
	}
	return nil
}

// newIdentity generates a fresh X25519 identity in a locked buffer.
func newIdentity() (*memguard.LockedBuffer, error) {
	scalar := memguard.NewBufferRandom(scalarSize)
	defer scalar.Destroy()
	if scalar.Size() != scalarSize {
		return nil, errors.New("vault: cannot allocate locked memory")
	}
	buf := memguard.NewBuffer(secretKeyLen)
	if buf.Size() != secretKeyLen {
		return nil, errors.New("vault: cannot allocate locked memory")
	}
	encodeSecretKey(scalar.Bytes(), buf.Bytes())
	return buf, nil
}

// view returns b's bytes as a string without copying (for age's parsers,
// which copy what they keep). b must outlive every use of the result.
func view(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}

// checkIdentity validates a canonical identity buffer without letting
// malformed input reach age's error messages.
func checkIdentity(b *memguard.LockedBuffer) error {
	if b == nil || !b.IsAlive() || b.Size() != secretKeyLen {
		return errBadIdentity
	}
	scalar := memguard.NewBuffer(scalarSize)
	defer scalar.Destroy()
	return decodeSecretKey(b.Bytes(), scalar.Bytes())
}

// parseIdentity parses a canonical identity buffer for one operation.
func parseIdentity(b *memguard.LockedBuffer) (*age.X25519Identity, error) {
	if err := checkIdentity(b); err != nil {
		return nil, err
	}
	id, err := age.ParseX25519Identity(view(b.Bytes()))
	if err != nil {
		return nil, errBadIdentity
	}
	return id, nil
}

// recipientOf returns the age1… recipient of an identity buffer.
func recipientOf(b *memguard.LockedBuffer) (string, error) {
	id, err := parseIdentity(b)
	if err != nil {
		return "", err
	}
	return id.Recipient().String(), nil
}

// normalizeIdentity copies the single key line of an identity file's
// plaintext (trailing whitespace allowed) into a canonical buffer.
func normalizeIdentity(raw []byte) (*memguard.LockedBuffer, error) {
	end := len(raw)
	for end > 0 && (raw[end-1] == '\n' || raw[end-1] == '\r' || raw[end-1] == ' ' || raw[end-1] == '\t') {
		end--
	}
	if end != secretKeyLen {
		return nil, errBadIdentity
	}
	out := memguard.NewBuffer(secretKeyLen)
	out.Copy(raw[:end])
	for i, c := range out.Bytes() { // canonical upper case
		if c >= 'a' && c <= 'z' {
			out.Bytes()[i] = c - ('a' - 'A')
		}
	}
	if err := checkIdentity(out); err != nil {
		out.Destroy()
		return nil, err
	}
	return out, nil
}

// readIdentity reads a decrypted identity file into locked memory.
func readIdentity(r io.Reader) (*memguard.LockedBuffer, error) {
	raw, err := memguard.NewBufferFromEntireReader(io.LimitReader(r, 4096))
	if err != nil {
		raw.Destroy()
		return nil, err
	}
	defer raw.Destroy()
	return normalizeIdentity(raw.Bytes())
}

// identityPlaintext is the content of identity.<factor>.age: the key line
// and a newline, in locked memory.
func identityPlaintext(id *memguard.LockedBuffer) *memguard.LockedBuffer {
	buf := memguard.NewBuffer(id.Size() + 1)
	buf.Copy(id.Bytes())
	buf.Bytes()[id.Size()] = '\n'
	return buf
}

// canonicalSet is the authenticated recipient set (D5):
// family "\n" sorted(recipients) joined by "\n".
func canonicalSet(family, recipient, recovery string) []byte {
	rs := []string{recipient, recovery}
	sort.Strings(rs)
	return []byte(family + "\n" + strings.Join(rs, "\n"))
}

// fingerprint is SHA-256 of the canonical set, identical to
// capsule.RecipientsFingerprint (vault may not import capsule).
func fingerprint(family, recipient, recovery string) string {
	sum := sha256.Sum256(canonicalSet(family, recipient, recovery))
	return hex.EncodeToString(sum[:])
}

// macWith computes hex HMAC-SHA256(HKDF-SHA256(scalar, salt=nil, info), data)
// where scalar is the identity's raw 32-byte X25519 key.
func macWith(identity *memguard.LockedBuffer, info string, data []byte) (string, error) {
	if info != InfoRecipients && info != InfoPolicy {
		return "", fmt.Errorf("vault: unknown MAC purpose %q", info)
	}
	if identity == nil || !identity.IsAlive() || identity.Size() != secretKeyLen {
		return "", errBadIdentity
	}
	scalar := memguard.NewBuffer(scalarSize)
	defer scalar.Destroy()
	if err := decodeSecretKey(identity.Bytes(), scalar.Bytes()); err != nil {
		return "", err
	}
	key, err := hkdf.Key(sha256.New, scalar.Bytes(), nil, info, 32)
	if err != nil {
		return "", err
	}
	defer memguard.WipeBytes(key)
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// macEqual compares two hex MACs in constant time.
func macEqual(a, b string) bool {
	return len(a) == len(b) && hmac.Equal([]byte(a), []byte(b))
}

// normalizeRecoveryKey turns a typed recovery key (any case, grouped with
// spaces, tabs, newlines or dashes) into a canonical identity buffer.
func normalizeRecoveryKey(b *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	if b == nil || !b.IsAlive() {
		return nil, errBadIdentity
	}
	const flat = "AGESECRETKEY1"
	compact := memguard.NewBuffer(b.Size() + 1)
	defer compact.Destroy()
	n := 0
	for _, c := range b.Bytes() {
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '-':
			continue
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		if n >= compact.Size() {
			return nil, errBadIdentity
		}
		compact.Bytes()[n] = c
		n++
	}
	c := compact.Bytes()[:n]
	if n != len(flat)+secretKeyLen-len(secretKeyPrefix) || !bytes.Equal(c[:len(flat)], []byte(flat)) {
		return nil, errBadIdentity
	}
	out := memguard.NewBuffer(secretKeyLen)
	copy(out.Bytes(), secretKeyPrefix)
	copy(out.Bytes()[len(secretKeyPrefix):], c[len(flat):])
	if err := checkIdentity(out); err != nil {
		out.Destroy()
		return nil, err
	}
	return out, nil
}
