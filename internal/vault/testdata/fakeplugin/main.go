// Command fakeplugin is a fake age plugin for internal/vault tests. It is
// built by the tests and installed as age-plugin-test (an X25519 plugin
// with recipient-v1 and identity-v1) and age-plugin-se (identity-v1 for
// age1tag1 P-256 tag recipients, like age-plugin-se). Its keys are derived
// from fixed seeds at run time; it never touches a real key, a keychain or
// the Secure Enclave, and never shows a dialog.
//
// The identity stub data selects a behaviour: "ok", "msg" (display a
// message first), "pin" (request a secret that must be 123456), "confirm"
// (request a confirmation that must be yes), "error" (fail), "hang"
// (never answer), "envcheck" (refuse unless the environment is exactly
// PATH=<the plugin's own directory>). Run with --keygen it prints its
// recipient. If a file named EVIL sits next to the binary it records that
// it ran (file RAN) and fails: tests use such a copy to prove that only
// the pinned binary ever runs.
//
// Lifeline (TESTPLAN §1 rule 8): stdin belongs to the plugin protocol, so
// the plugin watches its parent instead and exits as soon as it has been
// reparented (the test process that ran it is gone); "hang" is bounded too.
package main

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
)

const p256Label = "age-encryption.org/p256tag"

func main() {
	go lifeline(os.Getppid())
	self, _ := os.Executable()
	dir := filepath.Dir(self)
	if _, err := os.Stat(filepath.Join(dir, "EVIL")); err == nil {
		os.WriteFile(filepath.Join(dir, "RAN"), []byte("ran\n"), 0o600)
		os.Exit(1)
	}
	name := strings.TrimPrefix(filepath.Base(os.Args[0]), "age-plugin-")
	if len(os.Args) == 2 && os.Args[1] == "--keygen" {
		fmt.Println(recipientOf(name))
		return
	}
	p, err := plugin.New(name)
	if err != nil {
		os.Exit(2)
	}
	switch name {
	case "test":
		p.HandleRecipient(func(data []byte) (age.Recipient, error) { return x25519Identity().Recipient(), nil })
	case "se":
	default:
		os.Exit(2)
	}
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		return &modeIdentity{p: p, name: name, mode: string(data), dir: dir}, nil
	})
	os.Exit(p.Main())
}

// lifeline exits the plugin once its parent changed (reparented to
// launchd or init after the test process died).
func lifeline(parent int) {
	for {
		time.Sleep(100 * time.Millisecond)
		if os.Getppid() != parent {
			os.Exit(3)
		}
	}
}

func recipientOf(name string) string {
	if name == "se" {
		r, err := tag.NewClassicRecipient(compressed(p256Key().PublicKey().Bytes()))
		if err != nil {
			panic(err)
		}
		return r.String()
	}
	return plugin.EncodeRecipient(name, []byte("fake"))
}

type modeIdentity struct {
	p    *plugin.Plugin
	name string
	mode string
	dir  string
}

func (m *modeIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	switch m.mode {
	case "ok":
	case "msg":
		if err := m.p.DisplayMessage("touch the fake key"); err != nil {
			return nil, err
		}
	case "pin":
		pin, err := m.p.RequestValue("enter the fake PIN", true)
		if err != nil {
			return nil, err
		}
		if pin != "123456" {
			return nil, errors.New("wrong PIN")
		}
	case "confirm":
		yes, err := m.p.Confirm("use the fake key?", "yes", "no")
		if err != nil {
			return nil, err
		}
		if !yes {
			return nil, errors.New("declined")
		}
	case "error":
		return nil, errors.New("fake plugin failure")
	case "hang":
		time.Sleep(2 * time.Minute) // the caller cancels long before; the lifeline covers a dead caller
	case "envcheck":
		if env := os.Environ(); !slices.Equal(env, []string{"PATH=" + m.dir}) {
			return nil, fmt.Errorf("environment not limited: %d variables", len(env))
		}
	default:
		return nil, fmt.Errorf("unknown mode %q", m.mode)
	}
	if m.name == "se" {
		return unwrapTag(stanzas)
	}
	return x25519Identity().Unwrap(stanzas)
}

// x25519Identity is the fixed X25519 key of age-plugin-test, built from a
// seed (bech32 encoded here so that no key text sits in the source).
func x25519Identity() *age.X25519Identity {
	scalar := sha256.Sum256([]byte("precinto fake age plugin x25519 seed v1"))
	id, err := age.ParseX25519Identity(bech32("AGE-SECRET-KEY-", scalar[:]))
	if err != nil {
		panic(err)
	}
	return id
}

func p256Key() hpke.PrivateKey {
	k, err := hpke.DHKEM(ecdh.P256()).DeriveKeyPair([]byte("precinto fake age-plugin-se seed v1"))
	if err != nil {
		panic(err)
	}
	return k
}

// compressed converts an uncompressed P-256 point (0x04 || X || Y).
func compressed(p []byte) []byte {
	out := append([]byte{0x02 | p[64]&1}, p[1:33]...)
	return out
}

// unwrapTag opens a p256tag stanza (filippo.io/age/tag) with the fixed key.
func unwrapTag(stanzas []*age.Stanza) ([]byte, error) {
	k := p256Key()
	rcpt := compressed(k.PublicKey().Bytes())
	rh := sha256.Sum256(rcpt)
	b64 := base64.RawStdEncoding.Strict()
	for _, s := range stanzas {
		if s.Type != "p256tag" || len(s.Args) != 2 || len(s.Body) != 32 {
			continue
		}
		tg, err1 := b64.DecodeString(s.Args[0])
		enc, err2 := b64.DecodeString(s.Args[1])
		if err1 != nil || err2 != nil || len(tg) != 4 || len(enc) != 65 {
			continue
		}
		want, err := hkdf.Extract(sha256.New, append(slices.Clip(enc), rh[:4]...), []byte(p256Label))
		if err != nil || subtle.ConstantTimeCompare(tg, want[:4]) != 1 {
			continue
		}
		r, err := hpke.NewRecipient(enc, k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(p256Label))
		if err != nil {
			continue
		}
		if key, err := r.Open(nil, s.Body); err == nil {
			return key, nil
		}
	}
	return nil, age.ErrIncorrectIdentity
}

// bech32 encodes data with an upper-case HRP (BIP 173 checksum).
func bech32(hrp string, data []byte) string {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	polymod := func(values []byte) uint32 {
		chk := uint32(1)
		for _, v := range values {
			top := chk >> 25
			chk = (chk&0x1ffffff)<<5 ^ uint32(v)
			for i := 0; i < 5; i++ {
				if (top>>uint(i))&1 == 1 {
					chk ^= gen[i]
				}
			}
		}
		return chk
	}
	lower := strings.ToLower(hrp)
	var values []byte
	for i := 0; i < len(lower); i++ {
		values = append(values, lower[i]>>5)
	}
	values = append(values, 0)
	for i := 0; i < len(lower); i++ {
		values = append(values, lower[i]&31)
	}
	var conv []byte
	acc, bits := uint32(0), 0
	for _, b := range data {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			conv = append(conv, byte(acc>>uint(bits))&31)
		}
	}
	if bits > 0 {
		conv = append(conv, byte(acc<<uint(5-bits))&31)
	}
	mod := polymod(append(append(values, conv...), 0, 0, 0, 0, 0, 0)) ^ 1
	var sb strings.Builder
	sb.WriteString(lower + "1")
	for _, v := range conv {
		sb.WriteByte(charset[v])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(charset[(mod>>uint(5*(5-i)))&31])
	}
	return strings.ToUpper(sb.String())
}
