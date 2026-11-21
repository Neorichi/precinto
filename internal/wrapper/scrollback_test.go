package wrapper_test

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/precinto/precinto/internal/wrapper"
)

const sgr0 = "\x1b[0m"

func write(t *testing.T, s *wrapper.Scrollback, parts ...string) {
	t.Helper()
	for _, p := range parts {
		n, err := s.Write([]byte(p))
		if err != nil || n != len(p) {
			t.Fatalf("Write(%q) = %d, %v", p, n, err)
		}
	}
}

func TestScrollbackKeepsEverythingBeforeWrap(t *testing.T) {
	s := wrapper.NewScrollback(64)
	write(t, s, "\x1b[31mred", "\r\nline two\r\n", "half\x1b[")
	got := string(s.Bytes())
	if want := "\x1b[31mred\r\nline two\r\nhalf\x1b["; got != want {
		t.Fatalf("Bytes = %q, want every byte since start %q", got, want)
	}
	if s.Wrapped() {
		t.Fatal("Wrapped before the bound was reached")
	}
	// Exactly at the bound: still everything.
	s = wrapper.NewScrollback(8)
	write(t, s, "12345678")
	if got := string(s.Bytes()); got != "12345678" || s.Wrapped() {
		t.Fatalf("at the bound: %q wrapped=%v", got, s.Wrapped())
	}
}

func TestScrollbackBoundAndWrapped(t *testing.T) {
	s := wrapper.NewScrollback(32)
	for i := 0; i < 20; i++ {
		write(t, s, "line-"+strings.Repeat("x", i%7)+"\n")
	}
	if !s.Wrapped() {
		t.Fatal("Wrapped = false after more than max bytes")
	}
	got := s.Bytes()
	if !bytes.HasPrefix(got, []byte(sgr0)) {
		t.Fatalf("wrapped replay %q does not start with an SGR reset", got)
	}
	if body := got[len(sgr0):]; len(body) > 32 {
		t.Fatalf("replay body is %d bytes, more than the 32-byte ring", len(body))
	}
}

func TestScrollbackSafeBoundaryIsALineStart(t *testing.T) {
	s := wrapper.NewScrollback(20)
	write(t, s, "aaaaaaaaaa\nbbbbbbbbbb\ncccccccccc\n")
	// Kept: the last 20 bytes "bbbbbbbbb\ncccccccccc\n" minus... the
	// oldest kept byte is inside the b line, so the replay starts at c.
	if got, want := string(s.Bytes()), sgr0+"cccccccccc\n"; got != want {
		t.Fatalf("Bytes = %q, want %q", got, want)
	}
}

func TestScrollbackBoundaryAtOldestKeptByte(t *testing.T) {
	s := wrapper.NewScrollback(11)
	write(t, s, "aaaaaaaaaa\nbbbbbbbbbb\n")
	// Exactly the b line is kept and it starts a line.
	if got, want := string(s.Bytes()), sgr0+"bbbbbbbbbb\n"; got != want {
		t.Fatalf("Bytes = %q, want %q", got, want)
	}
}

func TestScrollbackNeverStartsInsideASequence(t *testing.T) {
	// A '\n' inside an OSC string or executed inside a CSI is no line
	// start: the replay must begin after the sequence.
	osc := "\x1b]0;title\nwith newline\x07"
	csi := "\x1b[1\n;2H"
	s := wrapper.NewScrollback(40)
	write(t, s, strings.Repeat("z", 30), osc, csi, "after\nEND\n")
	got := string(s.Bytes())
	if got != sgr0+"END\n" {
		t.Fatalf("Bytes = %q, want the replay to start at the first safe line (END)", got)
	}
}

func TestScrollbackSequenceSplitAcrossWrites(t *testing.T) {
	s := wrapper.NewScrollback(16)
	write(t, s, strings.Repeat("p", 10), "\x1b]2;a", "\nb", "\x07tail\nX\n")
	if got := string(s.Bytes()); got != sgr0+"X\n" {
		t.Fatalf("Bytes = %q: an OSC split over writes was taken as a line start", got)
	}
}

func TestScrollbackNeverSplitsARune(t *testing.T) {
	// Line starts only follow '\n', so no replay begins inside a rune.
	s := wrapper.NewScrollback(25)
	write(t, s, "ñññññññññññññññ\n", "ééééé\n", "ok\n")
	got := s.Bytes()
	if !utf8.Valid(got) {
		t.Fatalf("replay %q is not valid UTF-8", got)
	}
	if string(got) != sgr0+"ééééé\nok\n" {
		t.Fatalf("Bytes = %q", got)
	}
}

func TestScrollbackNoLineStartReplaysOnlyTheReset(t *testing.T) {
	s := wrapper.NewScrollback(10)
	write(t, s, strings.Repeat("\x1b[H0123456789", 5))
	if got := string(s.Bytes()); got != sgr0 {
		t.Fatalf("Bytes = %q, want only the SGR reset when no safe line start is kept", got)
	}
}

func TestScrollbackOneWriteLargerThanTheRing(t *testing.T) {
	s := wrapper.NewScrollback(8)
	write(t, s, "0123456789\nabcdefg\n")
	if !s.Wrapped() {
		t.Fatal("Wrapped = false")
	}
	if got := string(s.Bytes()); got != sgr0+"abcdefg\n" {
		t.Fatalf("Bytes = %q", got)
	}
}

func TestScrollbackZeroBound(t *testing.T) {
	s := wrapper.NewScrollback(0)
	write(t, s, "hello\n")
	if !s.Wrapped() || string(s.Bytes()) != sgr0 {
		t.Fatalf("zero ring: wrapped=%v bytes=%q", s.Wrapped(), s.Bytes())
	}
	s = wrapper.NewScrollback(-5)
	write(t, s, "x")
	if string(s.Bytes()) != sgr0 {
		t.Fatalf("negative bound: %q", s.Bytes())
	}
}

func TestScrollbackWipe(t *testing.T) {
	s := wrapper.NewScrollback(16)
	write(t, s, "secret-ish output\nmore\n")
	s.Wipe()
	if b := s.Bytes(); len(b) != 0 || s.Wrapped() {
		t.Fatalf("after Wipe: %q wrapped=%v", b, s.Wrapped())
	}
	write(t, s, "again\n")
	if got := string(s.Bytes()); got != "again\n" {
		t.Fatalf("after Wipe and Write: %q", got)
	}
}

// TestScrollbackRandomized checks the invariants against the full stream
// for random writes: before wrapping, the replay is the stream; after, it
// is an SGR reset plus a suffix of the kept tail that starts right after a
// '\n' (the generated stream has no escape sequences, so every '\n' is a
// safe line start, and the first one in the kept range must be chosen).
func TestScrollbackRandomized(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for round := 0; round < 200; round++ {
		max := 1 + rng.Intn(300)
		s := wrapper.NewScrollback(max)
		var all []byte
		for w := rng.Intn(40); w > 0; w-- {
			n := rng.Intn(80)
			chunk := make([]byte, n)
			for i := range chunk {
				if rng.Intn(9) == 0 {
					chunk[i] = '\n'
				} else {
					chunk[i] = byte('a' + rng.Intn(26))
				}
			}
			all = append(all, chunk...)
			write(t, s, string(chunk))
		}
		got := s.Bytes()
		if len(all) <= max {
			if !bytes.Equal(got, all) || s.Wrapped() {
				t.Fatalf("round %d: unwrapped replay %q != stream %q", round, got, all)
			}
			continue
		}
		if !s.Wrapped() {
			t.Fatalf("round %d: not wrapped after %d > %d bytes", round, len(all), max)
		}
		kept := all[len(all)-max:]
		want := []byte(sgr0)
		oldest := len(all) - max
		for i := oldest; i < len(all); i++ {
			if i > 0 && all[i-1] == '\n' {
				want = append(want, all[i:]...)
				break
			}
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round %d (max %d): replay %q, want %q (kept %q)", round, max, got, want, kept)
		}
	}
}
