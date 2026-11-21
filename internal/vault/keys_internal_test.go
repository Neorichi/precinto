package vault

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/awnumar/memguard"
)

func TestSecretKeyEncodingMatchesAge(t *testing.T) {
	for i := 0; i < 200; i++ {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		text := id.String()
		scalar := make([]byte, scalarSize)
		if err := decodeSecretKey([]byte(text), scalar); err != nil {
			t.Fatalf("decode %d: %v", i, err)
		}
		out := make([]byte, secretKeyLen)
		encodeSecretKey(scalar, out)
		if string(out) != text {
			t.Fatalf("re-encoding differs from age's encoding")
		}
		if err := decodeSecretKey([]byte(strings.ToLower(text)), scalar); err != nil {
			t.Fatalf("lower case: %v", err)
		}
		buf := memguard.NewBufferFromBytes([]byte(text))
		r, err := recipientOf(buf)
		buf.Destroy()
		if err != nil || r != id.Recipient().String() {
			t.Fatalf("recipientOf: %v", err)
		}
	}
	gen, err := newIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer gen.Destroy()
	if _, err := age.ParseX25519Identity(gen.String()); err != nil {
		t.Fatal("generated identity is not an age identity")
	}
	id, _ := age.GenerateX25519Identity()
	text := id.String()
	for _, bad := range []string{
		"", text[:73], text + "Q", strings.ToLower(text[:20]) + text[20:],
		"AGE-SECRET-KEY-2" + text[16:], text[:40] + "B" + text[41:], // 'b' is not a bech32 character
	} {
		if decodeSecretKey([]byte(bad), make([]byte, scalarSize)) == nil {
			t.Errorf("decoded %q", bad)
		}
	}
}

func TestNormalizeIdentity(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	for _, raw := range []string{id.String(), id.String() + "\n", id.String() + "\r\n", strings.ToLower(id.String()) + "\n"} {
		b, err := normalizeIdentity([]byte(raw))
		if err != nil || b.String() != id.String() {
			t.Fatalf("normalize %d bytes: %v", len(raw), err)
		}
		b.Destroy()
	}
	for _, raw := range []string{"# comment\n" + id.String(), " " + id.String(), id.String() + "\n" + id.String()} {
		if _, err := normalizeIdentity([]byte(raw)); err == nil {
			t.Errorf("accepted %d bytes", len(raw))
		}
	}
}

func TestMACDerivation(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	b := memguard.NewBufferFromBytes([]byte(id.String()))
	defer b.Destroy()
	m1, err := macWith(b, InfoRecipients, []byte("x"))
	m2, _ := macWith(b, InfoRecipients, []byte("x"))
	m3, _ := macWith(b, InfoPolicy, []byte("x"))
	m4, _ := macWith(b, InfoRecipients, []byte("y"))
	if err != nil || m1 != m2 || m1 == m3 || m1 == m4 || len(m1) != 64 {
		t.Fatalf("MACs %s %s %s %s %v", m1, m2, m3, m4, err)
	}
	if _, err := macWith(b, "other", nil); err == nil {
		t.Error("unknown info accepted")
	}
	if !macEqual(m1, m2) || macEqual(m1, m3) || macEqual(m1, m1[:63]) {
		t.Error("macEqual")
	}
	if got := string(canonicalSet("x25519", "age1b", "age1a")); got != "x25519\nage1a\nage1b" {
		t.Errorf("canonical set %q", got)
	}
}

// TestScryptFloor (D3): outside test binaries an explicit work factor
// below 2^19 is refused at enrollment, and 0 calibrates within [19, 22].
func TestScryptFloor(t *testing.T) {
	restore := SetFastScryptForTest(false)
	defer restore()
	strong := "Q8#zN4!pW7^rT2&mK-floor-test"
	for _, c := range []struct {
		logN int
		ok   bool
	}{{10, false}, {18, false}, {19, true}, {22, true}, {23, false}} {
		p := memguard.NewBufferFromBytes([]byte(strong))
		plan, err := planFactor(FactorSpec{Kind: FactorPassphrase, Passphrase: p, ScryptLogN: c.logN}, time.Now())
		if c.ok != (err == nil) {
			t.Errorf("logN %d: %v", c.logN, err)
		}
		if err != nil && !errors.Is(err, ErrWeakPassphrase) {
			t.Errorf("logN %d: %v, want ErrWeakPassphrase", c.logN, err)
		}
		if err != nil && p.IsAlive() {
			t.Errorf("logN %d: passphrase not consumed on error", c.logN)
		}
		plan.destroy()
	}
	p := memguard.NewBufferFromBytes([]byte(strong))
	plan, err := planFactor(FactorSpec{Kind: FactorPassphrase, Passphrase: p}, time.Now())
	if err != nil || plan.factor.ScryptLogN < 19 || plan.factor.ScryptLogN > 22 {
		t.Fatalf("calibrated: %+v %v", plan, err)
	}
	plan.destroy()
	// An identity file whose work factor is below the floor is refused.
	r, _ := age.NewScryptRecipient(strong)
	r.SetWorkFactor(10)
	var b bytes.Buffer
	w, _ := age.Encrypt(&b, r)
	w.Write([]byte("x"))
	w.Close()
	if err := checkScryptFile(b.Bytes(), 10); !errors.Is(err, ErrWrongIdentity) {
		t.Errorf("logN-10 file in production = %v", err)
	}
}

func TestPluginFraming(t *testing.T) {
	for _, n := range []int{0, 1, 47, 48, 49, 95, 96, 97, 1000} {
		body := bytes.Repeat([]byte{0xa5}, n)
		var buf bytes.Buffer
		c := &pluginConn{in: nopCloser{&buf}}
		if err := c.write("msg", []string{"a", "b"}, body); err != nil {
			t.Fatal(err)
		}
		// Every body line is 64 columns except the last, which is shorter.
		lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
		for i, l := range lines[1:] {
			last := i == len(lines)-2
			if !last && len(l) != 64 || last && len(l) >= 64 {
				t.Fatalf("n=%d: line %d has %d columns", n, i, len(l))
			}
		}
		r := &pluginConn{out: bufio.NewReaderSize(&buf, maxPluginLine)}
		typ, args, got, err := r.read()
		if err != nil || typ != "msg" || len(args) != 2 || !bytes.Equal(got, body) {
			t.Fatalf("n=%d: %q %v %d %v", n, typ, args, len(got), err)
		}
	}
	for _, bad := range []string{"no arrow\n\n", "-> \n\n", "-> ok\n" + strings.Repeat("A", 65) + "\n", "-> ok\n!!!!\n", "-> ok"} {
		r := &pluginConn{out: bufio.NewReaderSize(strings.NewReader(bad), maxPluginLine)}
		if _, _, _, err := r.read(); !errors.Is(err, errPluginProtocol) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	c := &pluginConn{in: nopCloser{io.Discard}}
	if err := c.write("x", []string{"has space"}, nil); err == nil {
		t.Error("argument with a space written")
	}
	if got := sanitizeUI([]byte("touch\x1b[2J the\x00 key\n")); got != "touch[2J the key" {
		t.Errorf("sanitize %q", got)
	}
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
