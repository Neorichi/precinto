package vault

import (
	"crypto/rand"
	_ "embed"
	"errors"
	"math"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/awnumar/memguard"
)

// wordlistText is the Diceware list: 7776 = 6^5 distinct lowercase English
// words of 3–9 letters (12.9 bits per word; 7 words ≈ 90 bits, S9). The
// contract names the EFF large list, which was not available to the build
// offline; this list has the same size and properties (see wordlist.txt
// provenance in the change requests).
//
//go:embed wordlist.txt
var wordlistText string

var (
	wordsOnce sync.Once
	words     []string
	wordSet   map[string]struct{}
)

func wordlist() ([]string, map[string]struct{}) {
	wordsOnce.Do(func() {
		words = strings.Fields(wordlistText)
		wordSet = make(map[string]struct{}, len(words))
		for _, w := range words {
			wordSet[w] = struct{}{}
		}
	})
	return words, wordSet
}

// wordBits is the entropy of one uniformly chosen list word.
func wordBits() float64 {
	w, _ := wordlist()
	return math.Log2(float64(len(w)))
}

func diceware(n int) (*memguard.LockedBuffer, error) {
	list, _ := wordlist()
	if n < 1 || n > 64 {
		return nil, errors.New("vault: Diceware needs 1 to 64 words")
	}
	if len(list) != 7776 {
		return nil, errors.New("vault: embedded word list is damaged")
	}
	tmp := memguard.NewBuffer(n * 10)
	defer tmp.Destroy()
	pos := 0
	var r [2]byte
	defer memguard.WipeBytes(r[:])
	const bound = 7776 * 8 // 62208 ≤ 65535: rejection sampling keeps it uniform
	for i := 0; i < n; i++ {
		var v int
		for {
			if _, err := rand.Read(r[:]); err != nil {
				return nil, err
			}
			if v = int(r[0])<<8 | int(r[1]); v < bound {
				break
			}
		}
		if i > 0 {
			tmp.Bytes()[pos] = '-'
			pos++
		}
		pos += copy(tmp.Bytes()[pos:], list[v%7776])
		v = 0
	}
	out := memguard.NewBuffer(pos)
	out.Copy(tmp.Bytes()[:pos])
	return out, nil
}

// isSeparator splits a passphrase into words.
func isSeparator(c byte) bool { return c == ' ' || c == '-' || c == '_' || c == '.' || c == ',' }

// estimateBits is a conservative strength estimate (D3, S9). Tokens that
// are list words count log2(7776) bits each (a Diceware passphrase is no
// stronger than its word count); every other character counts the
// log2 of its character-class pool, with repeats and ±1 runs ("aaaa",
// "1234", "dcba") worth only one bit each.
func estimateBits(p *memguard.LockedBuffer) float64 {
	if p == nil || !p.IsAlive() {
		return 0
	}
	b := p.Bytes()
	if !utf8.Valid(b) {
		return 0
	}
	_, set := wordlist()
	pool := charPool(b)
	if pool < 2 {
		return 0
	}
	perChar := math.Log2(float64(pool))
	var lower [16]byte
	defer memguard.WipeBytes(lower[:])
	bits := 0.0
	for i := 0; i < len(b); {
		if isSeparator(b[i]) {
			bits += 1 // the separator choice adds little
			i++
			continue
		}
		j := i
		for j < len(b) && !isSeparator(b[j]) {
			j++
		}
		tok := b[i:j]
		if isWord(tok, set, lower[:]) {
			bits += wordBits()
		} else {
			bits += charBits(tok, perChar)
		}
		i = j
	}
	return bits
}

// isWord reports whether tok (ASCII letters only) lowercased is a list
// word. The lookup builds no string: m[string(b)] does not allocate.
func isWord(tok []byte, set map[string]struct{}, buf []byte) bool {
	if len(tok) < 3 || len(tok) > len(buf) {
		return false
	}
	for i, c := range tok {
		switch {
		case c >= 'a' && c <= 'z':
			buf[i] = c
		case c >= 'A' && c <= 'Z':
			buf[i] = c + ('a' - 'A')
		default:
			return false
		}
	}
	_, ok := set[string(buf[:len(tok)])]
	return ok
}

func charPool(b []byte) int {
	var lower, upper, digit, symbol, other bool
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		case c >= 0x80:
			other = true
		default:
			symbol = true
		}
	}
	pool := 0
	for _, c := range []struct {
		on bool
		n  int
	}{{lower, 26}, {upper, 26}, {digit, 10}, {symbol, 33}, {other, 100}} {
		if c.on {
			pool += c.n
		}
	}
	return pool
}

func charBits(tok []byte, perChar float64) float64 {
	bits := 0.0
	var prev rune = -1
	var step rune
	for i := 0; i < len(tok); {
		r, n := utf8.DecodeRune(tok[i:])
		i += n
		d := r - prev
		switch {
		case prev >= 0 && d == 0:
			bits++ // repeat
		case prev >= 0 && (d == 1 || d == -1) && (step == 0 || d == step):
			bits++ // sequence
			step = d
			prev = r
			continue
		default:
			bits += perChar
		}
		step = 0
		prev = r
	}
	return bits
}

func calibrateScrypt(target time.Duration) int {
	if target <= 0 {
		return minScryptLogN
	}
	const probe = 14
	r, err := age.NewScryptRecipient("precinto scrypt calibration")
	if err != nil {
		return 20
	}
	r.SetWorkFactor(probe)
	key := make([]byte, 16)
	start := time.Now()
	if _, err := r.Wrap(key); err != nil {
		return 20
	}
	d := time.Since(start)
	if d <= 0 {
		return maxScryptLogN
	}
	n := probe + int(math.Round(math.Log2(float64(target)/float64(d))))
	if n < minScryptLogN {
		n = minScryptLogN
	}
	if n > maxScryptLogN {
		n = maxScryptLogN
	}
	return n
}

func parseRecoveryKey(b *memguard.LockedBuffer) (age.Identity, error) {
	canon, err := normalizeRecoveryKey(b)
	if err != nil {
		return nil, errors.New("vault: malformed recovery key")
	}
	defer canon.Destroy()
	id, err := parseIdentity(canon)
	if err != nil {
		return nil, errors.New("vault: malformed recovery key")
	}
	return id, nil
}

// formatRecoveryKey renders "AGE-SECRET-KEY-1 XXXXXX XXXXXX … XXXX": the
// 58 data characters in groups of 6 (the last group, 4 characters, is
// what the user types back, D7).
func formatRecoveryKey(b *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	canon, err := normalizeRecoveryKey(b)
	if err != nil {
		return nil, errors.New("vault: malformed recovery key")
	}
	defer canon.Destroy()
	data := canon.Bytes()[len(secretKeyPrefix):]
	groups := (len(data) + 5) / 6
	out := memguard.NewBuffer(len(secretKeyPrefix) + len(data) + groups)
	o := out.Bytes()
	n := copy(o, secretKeyPrefix)
	for i := 0; i < len(data); i += 6 {
		o[n] = ' '
		n++
		end := i + 6
		if end > len(data) {
			end = len(data)
		}
		n += copy(o[n:], data[i:end])
	}
	return out, nil
}

func verifyRecovery(recovery *memguard.LockedBuffer, header []byte) error {
	id, err := parseRecoveryKey(recovery)
	if err != nil {
		return err
	}
	key, err := age.DecryptHeader(header, id)
	if err != nil {
		return ErrWrongIdentity
	}
	memguard.WipeBytes(key)
	return nil
}
