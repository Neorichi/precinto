package wrapper

// defaultScrollbackBytes is the replay ring size of D30/D60 (8 MiB).
const defaultScrollbackBytes = 8 << 20

// sgrReset precedes a replay that starts after dropped output: the dropped
// part may have left colours or attributes on (SPEC §15.2).
const sgrReset = "\x1b[0m"

// maxLineStarts bounds the safe-boundary index. Each entry is one line start
// in the ring; past the bound every other entry is dropped, so the boundary
// found may lie a few lines after the exact first one (only for output made
// of about a million tiny lines).
const maxLineStarts = 1 << 20

// oldest returns the stream offset of the oldest kept byte.
func (s *Scrollback) oldest() int64 { return s.total - int64(s.n) }

func (s *Scrollback) write(b []byte) {
	if len(b) == 0 {
		return
	}
	base := s.total
	s.sc.feed(b, func(t *token) {
		// A line start is safe only in ground state: a '\n' executed in
		// the middle of a control sequence is not one.
		if t.kind == tokCtl && t.b == '\n' && !t.inSeq {
			s.addLineStart(base + int64(t.end))
		}
	})
	s.total += int64(len(b))
	s.store(b)
	s.pruneLineStarts()
}

func (s *Scrollback) addLineStart(off int64) {
	if len(s.lines) >= maxLineStarts {
		kept := s.lines[:0]
		for i := 0; i < len(s.lines); i += 2 {
			kept = append(kept, s.lines[i])
		}
		clear(s.lines[len(kept):])
		s.lines = kept
	}
	s.lines = append(s.lines, off)
}

func (s *Scrollback) pruneLineStarts() {
	old := s.oldest()
	i := 0
	for i < len(s.lines) && s.lines[i] < old {
		i++
	}
	if i > 0 {
		n := copy(s.lines, s.lines[i:])
		clear(s.lines[n:])
		s.lines = s.lines[:n]
	}
}

// store appends b to the ring, dropping the oldest bytes beyond max.
func (s *Scrollback) store(b []byte) {
	switch {
	case s.max <= 0:
		s.wrapped = true
		return
	case len(b) >= s.max:
		// Only the tail of b survives and becomes the whole ring.
		if s.n > 0 || len(b) > s.max {
			s.wrapped = true
		}
		s.ensureRing()
		copy(s.buf, b[len(b)-s.max:])
		s.start, s.n = 0, s.max
		return
	case s.start == 0 && len(s.buf) == s.n && s.n+len(b) <= s.max:
		// Still growing: the slice holds exactly the content.
		if cap(s.buf)-len(s.buf) < len(b) {
			grown := make([]byte, len(s.buf), growCap(cap(s.buf), len(s.buf)+len(b), s.max))
			copy(grown, s.buf)
			clear(s.buf)
			s.buf = grown
		}
		s.buf = append(s.buf, b...)
		s.n += len(b)
		return
	}
	s.ensureRing()
	w := (s.start + s.n) % s.max
	k := copy(s.buf[w:], b)
	copy(s.buf, b[k:])
	if total := s.n + len(b); total > s.max {
		s.start = (s.start + total - s.max) % s.max
		s.n = s.max
		s.wrapped = true
	} else {
		s.n = total
	}
}

// ensureRing gives the buffer its full size, keeping the content in order.
func (s *Scrollback) ensureRing() {
	if len(s.buf) == s.max {
		return
	}
	ring := make([]byte, s.max)
	old := s.content(s.oldest())
	copy(ring, old)
	clear(old)
	clear(s.buf[:cap(s.buf)])
	s.buf = ring
	s.start = 0
}

func growCap(have, need, max int) int {
	c := have * 2
	if c < 4096 {
		c = 4096
	}
	if c < need {
		c = need
	}
	if c > max {
		c = max
	}
	return c
}

// content returns a copy of the kept bytes from stream offset off on.
func (s *Scrollback) content(off int64) []byte {
	skip := int(off - s.oldest())
	if skip < 0 {
		skip = 0
	}
	if skip >= s.n {
		return nil
	}
	out := make([]byte, 0, s.n-skip+len(sgrReset))
	first := (s.start + skip) % len(s.buf)
	for left := s.n - skip; left > 0; {
		k := len(s.buf) - first
		if k > left {
			k = left
		}
		out = append(out, s.buf[first:first+k]...)
		left -= k
		first = (first + k) % len(s.buf)
	}
	return out
}

func (s *Scrollback) bytes() []byte {
	if !s.wrapped {
		return s.content(s.oldest())
	}
	out := []byte(sgrReset)
	old := s.oldest()
	for _, off := range s.lines {
		if off >= old {
			if off < s.total {
				tail := s.content(off)
				out = append(out, tail...)
				clear(tail)
			}
			break
		}
	}
	return out
}

func (s *Scrollback) wipe() {
	clear(s.buf[:cap(s.buf)])
	s.buf = nil
	clear(s.lines)
	s.lines = nil
	s.start, s.n, s.total, s.wrapped = 0, 0, 0, false
	s.sc.reset()
}
