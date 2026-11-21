package ui

import "unicode/utf8"

// sanitizeTerminal implements SanitizeTerminal. It returns a new slice and
// leaves b unchanged. Valid UTF-8 is decoded so that C1 controls encoded as
// U+0080–U+009F are removed while multi-byte text survives; a byte that is
// not part of valid UTF-8 is removed when it is an 8-bit C1 control
// (0x80–0x9F, e.g. a raw CSI 0x9B) and kept otherwise. DEL (0x7F) counts as
// a control character too.
func sanitizeTerminal(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		c := b[i]
		if c < utf8.RuneSelf {
			if (c >= 0x20 && c != 0x7f) || c == '\n' || c == '\t' {
				out = append(out, c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(b[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			if c >= 0xa0 {
				out = append(out, c)
			}
		case r >= 0x80 && r <= 0x9f:
		default:
			out = append(out, b[i:i+size]...)
		}
		i += size
	}
	return out
}
