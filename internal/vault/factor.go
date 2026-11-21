package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
	"github.com/awnumar/memguard"
)

const (
	defaultSEAccess = "any-biometry-or-passcode"
	minScryptLogN   = 19 // D3 floor
	maxScryptLogN   = 22 // also the unwrap ceiling (no work-factor DoS)
	testScryptLogN  = 10 // vaulttest fixtures
	maxIdentityFile = 64 << 10
	// Prompt labels for relayed secrets. The daemon replaces them with
	// catalog texts built from verified data (D27); they are short, plain
	// and never include a path or id.
	promptPassphrase = "precinto passphrase"
	promptRecovery   = "precinto recovery key"
	presenceAcked    = "unknown (acknowledged)"
)

// fastScrypt allows explicit scrypt work factors below 2^19 (down to 2^10)
// only in test binaries and -tags testing builds, for vaulttest fixtures;
// every production enrollment uses at least 2^19 (D3).
var fastScrypt = testing.Testing() || testingBuild

func minLogN() int {
	if fastScrypt {
		return testScryptLogN
	}
	return minScryptLogN
}

// errNoPresence: a plugin factor without a known presence policy (S10).
var errNoPresence = errors.New("vault: plugin factor without a known presence policy (pass --no-presence-ack to accept it)")

var (
	seAccessAllowed = map[string]bool{"passcode": true, "any-biometry-or-passcode": true, "any-biometry-and-passcode": true, "current-biometry-and-passcode": true}
	knownPresence   = map[string]bool{"touch-always": true, "touch-cached": true, "pin-always": true, "pin-once": true, "tpm-pin": true}
)

func identityFileName(factor string) string { return "identity." + factor + ".age" }

// validFactorName: identity.<name>.age must be a plain file name.
func validFactorName(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '-' || c == '_' || c == '.')) {
			return false
		}
	}
	return true
}

// factorPlan is a validated factor about to be enrolled.
type factorPlan struct {
	factor     Factor
	passphrase *memguard.LockedBuffer // passphrase factors (owned, destroyed after wrapping)
}

func (p *factorPlan) destroy() {
	if p != nil && p.passphrase != nil {
		p.passphrase.Destroy()
	}
}

// planFactor validates spec (D3, S10) and pins plugin binaries (S2). The
// spec's passphrase is consumed, on error too.
func planFactor(spec FactorSpec, now time.Time) (plan *factorPlan, err error) {
	defer func() {
		if err != nil && spec.Passphrase != nil {
			spec.Passphrase.Destroy()
		}
	}()
	switch spec.Kind {
	case FactorPassphrase:
		return planPassphrase(spec, now)
	case FactorSE, FactorPlugin:
		return planPlugin(spec, now)
	case FactorRecovery:
		return nil, errors.New("vault: the recovery factor is created by Init, not enrolled")
	default:
		return nil, fmt.Errorf("vault: unknown factor kind %q", spec.Kind)
	}
}

func planPassphrase(spec FactorSpec, now time.Time) (*factorPlan, error) {
	p := spec.Passphrase
	if p == nil || !p.IsAlive() || !utf8.Valid(p.Bytes()) {
		return nil, ErrWeakPassphrase
	}
	if utf8.RuneCount(p.Bytes()) < 12 || EstimateBits(p) < 80 {
		return nil, ErrWeakPassphrase
	}
	logN := spec.ScryptLogN
	if logN == 0 {
		logN = CalibrateScrypt(time.Second)
	}
	if logN < minLogN() || logN > maxScryptLogN {
		return nil, fmt.Errorf("%w: scrypt work factor 2^%d outside [2^%d, 2^%d]", ErrWeakPassphrase, logN, minLogN(), maxScryptLogN)
	}
	name := spec.Name
	if name == "" {
		name = string(FactorPassphrase)
	}
	if !validFactorName(name) {
		return nil, fmt.Errorf("vault: bad factor name %q", name)
	}
	return &factorPlan{factor: Factor{Name: name, Kind: FactorPassphrase, ScryptLogN: logN, AddedAt: now}, passphrase: p}, nil
}

func planPlugin(spec FactorSpec, now time.Time) (*factorPlan, error) {
	stubName, _, err := plugin.ParseIdentity(spec.IdentityStub)
	if err != nil {
		return nil, errors.New("vault: malformed plugin identity stub")
	}
	if spec.Kind == FactorSE && stubName != "se" {
		return nil, fmt.Errorf("vault: the se factor needs an AGE-PLUGIN-SE-1 identity, got plugin %q", stubName)
	}
	if spec.Kind == FactorPlugin && stubName == "se" {
		return nil, errors.New("vault: enroll age-plugin-se as the se factor")
	}
	if tr, err := tag.ParseRecipient(spec.Recipient); err == nil {
		if tr.Hybrid() {
			return nil, errors.New("vault: post-quantum tag recipients are not supported in v0.2 (D2)")
		}
	} else if name, _, err := plugin.ParseRecipient(spec.Recipient); err != nil || name != stubName {
		// Plain X25519 recipients have no plugin name and are refused: a
		// factor must be backed by its plugin's key (S10).
		return nil, fmt.Errorf("vault: recipient is not a %s plugin or tag recipient", stubName)
	}
	var policy string
	if spec.Kind == FactorSE {
		if spec.PresencePolicy != "" {
			return nil, errors.New("vault: the se factor takes SEAccessControl, not a plugin presence policy")
		}
		policy = spec.SEAccessControl
		if policy == "" {
			policy = defaultSEAccess
		}
		if !seAccessAllowed[policy] {
			return nil, fmt.Errorf("vault: Secure Enclave access control %q refused (biometry-only and none are not allowed, D3)", policy)
		}
	} else {
		if spec.SEAccessControl != "" {
			return nil, errors.New("vault: plugin factors take a presence policy, not a Secure Enclave access control")
		}
		policy = spec.PresencePolicy
		switch {
		case knownPresence[policy]:
		case policy != "":
			return nil, fmt.Errorf("vault: unknown presence policy %q (touch-always, touch-cached, pin-always, pin-once or tpm-pin)", policy)
		case !spec.NoPresenceAck:
			return nil, errNoPresence
		default:
			policy = presenceAcked
		}
	}
	want := "age-plugin-" + stubName
	if !filepath.IsAbs(spec.PluginPath) || filepath.Base(spec.PluginPath) != want {
		return nil, fmt.Errorf("vault: plugin path must be an absolute path to %s", want)
	}
	real, err := filepath.EvalSymlinks(spec.PluginPath)
	if err != nil {
		return nil, err
	}
	real = filepath.Clean(real)
	if unsafeShownPath(spec.PluginPath) || unsafeShownPath(real) {
		return nil, fmt.Errorf("vault: the plugin path holds control or invisible characters")
	}
	if filepath.Base(real) != want {
		return nil, fmt.Errorf("vault: %q resolves to %q", spec.PluginPath, real)
	}
	sum, err := pinHash(real)
	if err != nil {
		return nil, err
	}
	name := spec.Name
	if name == "" {
		name = stubName
	}
	if !validFactorName(name) {
		return nil, fmt.Errorf("vault: bad factor name %q", name)
	}
	return &factorPlan{factor: Factor{
		Name: name, Kind: spec.Kind, Recipient: spec.Recipient, IdentityStub: spec.IdentityStub,
		PluginPath: real, PluginLink: filepath.Clean(spec.PluginPath), PluginSHA256: sum, PresencePolicy: policy,
		GUI: spec.Kind == FactorSE, AddedAt: now,
	}}, nil
}

// recipientFor returns the age recipient that wraps an identity file for f.
func recipientFor(ctx context.Context, f Factor, passphrase *memguard.LockedBuffer, ui UI) (age.Recipient, error) {
	switch f.Kind {
	case FactorPassphrase:
		if passphrase == nil || !passphrase.IsAlive() || passphrase.Size() == 0 {
			return nil, ErrWeakPassphrase
		}
		r, err := age.NewScryptRecipient(view(passphrase.Bytes()))
		if err != nil {
			return nil, ErrWeakPassphrase
		}
		r.SetWorkFactor(f.ScryptLogN)
		return r, nil
	case FactorRecovery:
		return age.ParseX25519Recipient(f.Recipient)
	case FactorSE, FactorPlugin:
		if r, err := tag.ParseRecipient(f.Recipient); err == nil {
			return r, nil // tag recipients are wrapped natively (age ≥ 1.3)
		}
		name, _, err := plugin.ParseRecipient(f.Recipient)
		if err != nil {
			return nil, fmt.Errorf("vault: factor %s has a malformed recipient", f.Name)
		}
		return &pluginRecipient{ctx: ctx, f: f, ui: ui, name: name, recipient: f.Recipient}, nil
	}
	return nil, fmt.Errorf("vault: unknown factor kind %q", f.Kind)
}

// wrapIdentity encrypts the identity file content for factor f.
func wrapIdentity(ctx context.Context, f Factor, identity, passphrase *memguard.LockedBuffer, ui UI) ([]byte, error) {
	r, err := recipientFor(ctx, f, passphrase, ui)
	if err != nil {
		return nil, err
	}
	plain := identityPlaintext(identity)
	defer plain.Destroy()
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain.Bytes()); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// headerStanzas parses an age header with age's own parser.
func headerStanzas(ct []byte) ([]*age.Stanza, error) {
	hdr, err := age.ExtractHeader(bytes.NewReader(ct))
	if err != nil {
		return nil, err
	}
	rec := &stanzaRecorder{}
	_, err = age.DecryptHeader(hdr, rec)
	if !rec.called {
		return nil, err
	}
	return rec.stanzas, nil
}

type stanzaRecorder struct {
	called  bool
	stanzas []*age.Stanza
}

func (s *stanzaRecorder) Unwrap(st []*age.Stanza) ([]byte, error) {
	s.called = true
	s.stanzas = append([]*age.Stanza(nil), st...)
	return nil, age.ErrIncorrectIdentity
}

// checkScryptFile requires a passphrase identity file to hold exactly one
// scrypt stanza with the enrolled work factor (a replaced file with a lower
// or absurd work factor is refused before any prompt).
func checkScryptFile(ct []byte, logN int) error {
	st, err := headerStanzas(ct)
	if err != nil || len(st) != 1 || st[0].Type != "scrypt" || len(st[0].Args) != 2 ||
		st[0].Args[1] != strconv.Itoa(logN) || logN < minLogN() || logN > maxScryptLogN {
		return fmt.Errorf("%w: unexpected passphrase identity file", ErrWrongIdentity)
	}
	return nil
}

// usable reports whether f can prompt with the given capabilities: tty
// means Secret/Confirm reach a human (terminal or pinentry), gui that a
// dialog such as the Secure Enclave's can appear (D27).
func usable(f Factor, tty, gui bool) bool {
	switch f.Kind {
	case FactorSE:
		return gui
	case FactorPlugin:
		return tty || f.GUI && gui
	case FactorPassphrase, FactorRecovery:
		return tty
	}
	return false
}

func (v *Vault) factor(name string) (Factor, int, bool) {
	for i, f := range v.Meta.Factors {
		if f.Name == name {
			return f, i, true
		}
	}
	return Factor{}, -1, false
}

func (v *Vault) usableFactors(tty, gui bool) []Factor {
	var out []Factor
	for _, f := range v.Meta.Factors {
		if usable(f, tty, gui) {
			out = append(out, f)
		}
	}
	return out
}

// pick chooses the factor of one unwrap: the named one, or the best one the
// UI can drive (Secure Enclave, plugin, passphrase; recovery only by name).
func (v *Vault) pick(name string, ui UI) (Factor, error) {
	tty, gui := ui.Interactive(), ui.GUI()
	if name != "" {
		f, _, ok := v.factor(name)
		if !ok {
			return Factor{}, fmt.Errorf("%w: factor %q", ErrNotFound, name)
		}
		if !usable(f, tty, gui) {
			return Factor{}, ErrNoUI
		}
		return f, nil
	}
	for _, kind := range []FactorKind{FactorSE, FactorPlugin, FactorPassphrase} {
		for _, f := range v.Meta.Factors {
			if f.Kind == kind && usable(f, tty, gui) {
				return f, nil
			}
		}
	}
	return Factor{}, ErrNoUI
}

func (v *Vault) unwrap(ctx context.Context, name string, ui UI) (*memguard.LockedBuffer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ui == nil {
		return nil, ErrNoUI
	}
	f, err := v.pick(name, ui)
	if err != nil {
		return nil, err
	}
	return unwrapFile(ctx, v.Dir, f, ui)
}

// unwrapFile performs one user-presence unwrap of identity.<f>.age in dir.
func unwrapFile(ctx context.Context, dir string, f Factor, ui UI) (*memguard.LockedBuffer, error) {
	ct, err := readVaultFile(dir, identityFileName(f.Name), maxIdentityFile)
	if err != nil {
		return nil, err
	}
	var id age.Identity
	switch f.Kind {
	case FactorSE, FactorPlugin:
		if err := verifyPin(f); err != nil {
			return nil, err
		}
		id = &pluginIdentity{ctx: ctx, f: f, ui: ui}
	case FactorPassphrase:
		if err := checkScryptFile(ct, f.ScryptLogN); err != nil {
			return nil, err
		}
		pass, err := ui.Secret(promptPassphrase)
		if err != nil {
			return nil, err
		}
		defer pass.Destroy()
		if pass.Size() == 0 {
			return nil, ErrCancelled
		}
		sid, err := age.NewScryptIdentity(view(pass.Bytes()))
		if err != nil {
			return nil, ErrBadSecret
		}
		sid.SetMaxWorkFactor(f.ScryptLogN)
		id = sid
	case FactorRecovery:
		key, err := ui.Secret(promptRecovery)
		if err != nil {
			return nil, err
		}
		defer key.Destroy()
		rid, err := ParseRecoveryKey(key)
		if err != nil {
			return nil, ErrBadSecret
		}
		id = rid
	default:
		return nil, fmt.Errorf("vault: unknown factor kind %q", f.Kind)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(ct), id)
	if err != nil {
		return nil, unwrapError(ctx, err, f.Kind)
	}
	out, err := readIdentity(r)
	if err != nil {
		return nil, fmt.Errorf("%w: identity file content", ErrWrongIdentity)
	}
	return out, nil
}

// unwrapError maps age's errors; it never includes secret input.
func unwrapError(ctx context.Context, err error, kind FactorKind) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for _, s := range []error{ErrNoUI, ErrCancelled, ErrPluginPin, ErrWrongIdentity, errPluginFailed, errPluginProtocol} {
		if errors.Is(err, s) {
			return err
		}
	}
	var nomatch *age.NoIdentityMatchError
	if errors.As(err, &nomatch) {
		if kind == FactorPassphrase || kind == FactorRecovery {
			return ErrBadSecret
		}
		return fmt.Errorf("%w: the %s factor did not open the identity file", ErrWrongIdentity, kind)
	}
	// Anything else (bad header MAC, a payload that fails authentication)
	// means the identity file itself is wrong or tampered.
	return fmt.Errorf("%w: identity file did not decrypt", ErrWrongIdentity)
}

func (v *Vault) addFactor(ctx context.Context, identity *memguard.LockedBuffer, spec FactorSpec, ui UI) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := v.checkIdentity(identity); err != nil {
		if spec.Passphrase != nil {
			spec.Passphrase.Destroy()
		}
		return err
	}
	plan, err := planFactor(spec, time.Now().UTC())
	if err != nil {
		return err
	}
	defer plan.destroy()
	if _, _, dup := v.factor(plan.factor.Name); dup {
		return fmt.Errorf("vault: factor %q already enrolled: %w", plan.factor.Name, fs.ErrExist)
	}
	ct, err := wrapIdentity(ctx, plan.factor, identity, plan.passphrase, ui)
	if err != nil {
		return err
	}
	m, err := updateMetaAt(v.Dir, func(m *Meta) (bool, error) {
		for _, f := range m.Factors {
			if f.Name == plan.factor.Name {
				return false, fmt.Errorf("vault: factor %q already enrolled: %w", plan.factor.Name, fs.ErrExist)
			}
		}
		if m.Recipient != v.Meta.Recipient {
			return false, ErrWrongIdentity // vault.toml was rewritten meanwhile
		}
		if err := writeVaultFile(v.Dir, identityFileName(plan.factor.Name), ct); err != nil {
			return false, err
		}
		m.Factors = append(append([]Factor(nil), m.Factors...), plan.factor)
		return true, nil
	})
	if err != nil {
		return err
	}
	v.Meta = m
	return nil
}

// checkIdentity requires identity to be this vault's (never wrap another
// key to a factor).
func (v *Vault) checkIdentity(identity *memguard.LockedBuffer) error {
	r, err := recipientOf(identity)
	if err != nil {
		return err
	}
	if r != v.Meta.Recipient {
		return ErrWrongIdentity
	}
	return nil
}

func (v *Vault) removeFactor(name string) error {
	m, err := updateMetaAt(v.Dir, func(m *Meta) (bool, error) {
		cur := &Vault{Dir: v.Dir, Meta: *m}
		f, i, ok := cur.factor(name)
		if !ok {
			return false, fmt.Errorf("%w: factor %q", ErrNotFound, name)
		}
		if f.Kind == FactorRecovery {
			return false, fmt.Errorf("%w: the recovery factor is never removed", ErrLastFactor)
		}
		others := 0
		for _, g := range m.Factors {
			if g.Kind != FactorRecovery && g.Name != name {
				others++
			}
		}
		if others == 0 {
			return false, ErrLastFactor
		}
		m.Factors = append(append([]Factor(nil), m.Factors[:i]...), m.Factors[i+1:]...)
		return true, nil
	})
	if err != nil {
		return err
	}
	v.Meta = m
	if err := removeVaultFile(v.Dir, identityFileName(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
