package agent

import (
	"errors"
	"strings"
	"testing"
)

// TestAssuanExchange drives the pinentry response parser with scripted
// streams (no pinentry program is run).
func TestAssuanExchange(t *testing.T) {
	a := &assuan{r: strings.NewReader("OK Pleased to meet you\n# comment\nS PASSWORD_FROM_CACHE\nD p%25ss%0Aword\nOK\n")}
	if b, err := a.expectOK(); err != nil || b.Size() != 0 {
		t.Fatalf("greeting = %v %v", b, err)
	}
	b, err := a.expectOK()
	if err != nil || string(b.Bytes()) != "p%ss\nword" {
		t.Fatalf("pin = %q %v", b.Bytes(), err)
	}
	b.Destroy()
	a = &assuan{r: strings.NewReader("ERR 83886179 Operation cancelled <Pinentry>\n")}
	if _, err := a.expectOK(); !errors.Is(err, errPinentryCancelled) {
		t.Fatalf("cancel = %v", err)
	}
	a = &assuan{r: strings.NewReader("D unterminated")}
	if _, err := a.expectOK(); err == nil {
		t.Fatal("truncated stream accepted")
	}
	if got := assuanEscape("50% off\r\nnow"); got != "50%25 off%0D%0Anow" {
		t.Fatalf("escape = %q", got)
	}
	if u := assuanUnescape([]byte("%zz%4")); string(u.Bytes()) != "%zz%4" {
		t.Fatalf("bad escapes must stay literal: %q", u.Bytes())
	}
	for i := range a.line {
		if a.line[i] != 0 {
			a.wipe()
			break
		}
	}
	a.wipe()
	for _, c := range a.line {
		if c != 0 {
			t.Fatal("line buffer not wiped")
		}
	}
}
