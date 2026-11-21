package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

// seAccessControl is the only Secure Enclave access control precinto
// creates keys with: biometry-only and "none" are refused (SPEC §4.3, D3).
const seAccessControl = "any-biometry-or-passcode"

// Limits of secrets read from files or stdin.
const maxKeyFile = 4 << 10

// factorArg is one --factor value.
type factorArg struct {
	kind      vault.FactorKind
	recipient string // plugin:<recipient>
	plugin    string // plugin name from the recipient ("yubikey")
	stub      string // plugin identity stub (factor add --identity-stub)
}

// parseFactorArgs validates --factor values; none means the OS default
// (darwin: se; linux: passphrase, D3).
func parseFactorArgs(list []string, goos string) ([]factorArg, error) {
	if len(list) == 0 {
		if goos == "darwin" {
			return []factorArg{{kind: vault.FactorSE}}, nil
		}
		return []factorArg{{kind: vault.FactorPassphrase}}, nil
	}
	seen := map[string]bool{}
	var out []factorArg
	for _, v := range list {
		fa, err := parseFactor(v, goos)
		if err != nil {
			return nil, err
		}
		key := string(fa.kind) + ":" + fa.recipient
		if seen[key] {
			return nil, usageErrorf("--factor %s given twice", v)
		}
		seen[key] = true
		out = append(out, fa)
	}
	return out, nil
}

// parseFactor parses se, passphrase or plugin:<recipient>.
func parseFactor(v, goos string) (factorArg, error) {
	switch {
	case v == "se":
		if goos != "darwin" {
			return factorArg{}, usageErrorf("the se factor (Secure Enclave) exists only on macOS")
		}
		return factorArg{kind: vault.FactorSE}, nil
	case v == "passphrase":
		return factorArg{kind: vault.FactorPassphrase}, nil
	case strings.HasPrefix(v, "plugin:"):
		r := strings.TrimPrefix(v, "plugin:")
		name, ok := pluginName(r)
		if !ok {
			return factorArg{}, usageErrorf("plugin:%s is not an age plugin recipient (age1<name>1…)", r)
		}
		return factorArg{kind: vault.FactorPlugin, recipient: r, plugin: name}, nil
	}
	return factorArg{}, usageErrorf("unknown factor %q (want se, passphrase or plugin:<recipient>)", v)
}

// pluginName returns <name> of an age plugin recipient "age1<name>1<data>"
// (Bech32: the separator is the last '1').
func pluginName(r string) (string, bool) {
	lower := strings.ToLower(r)
	if lower != r || !strings.HasPrefix(r, "age1") {
		return "", false
	}
	hrp := r[:strings.LastIndexByte(r, '1')]
	name := strings.TrimPrefix(hrp, "age1")
	if name == "" || hrp == "age" {
		return "", false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return "", false
		}
	}
	return name, true
}

func cmdInit(a *app, args []string) int {
	f := newFlags("init")
	var factors stringList
	f.Var(&factors, "factor", "unlock method: se, passphrase or plugin:<recipient> (repeatable; default se on macOS, passphrase on linux)")
	recoveryOut := f.String("recovery-out", "", "write the recovery key to `FILE` (new file, mode 0600) instead of showing it")
	showRecovery := f.Bool("show-recovery", false, "show the recovery key on screen even with --recovery-out")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageFail(f, "unexpected argument "+pos[0])
	}
	specs, err := parseFactorArgs(factors, a.sys.goos)
	if err != nil {
		return a.usageFail(f, err.Error())
	}
	// D7: the recovery key is shown or written only to a human: no agent
	// context, and stdin and stdout are terminals.
	if err := a.refuseAgent(refusal{init: true}); err != nil {
		return exitLocked
	}
	if !a.sys.interactive() {
		a.line(ui.MsgNeedTerminal, ui.Vars{Command: "precinto init"})
		return exitLocked
	}
	t, err := a.needTerminal("init")
	if err != nil {
		return exitLocked
	}
	defer t.Close()
	if err := a.sys.harden(); err != nil {
		return a.fail("init", err)
	}
	vs, err := a.vaults()
	if err != nil {
		return a.fail("init", err)
	}
	if done, err := vs.Initialized(); err != nil {
		return a.fail("init", err)
	} else if done {
		a.say(textAlreadyInit)
		return exitError
	}
	l, err := a.layout()
	if err != nil {
		return a.fail("init", err)
	}
	var out *os.File
	if *recoveryOut != "" {
		if out, err = a.createRecoveryOut(*recoveryOut); err != nil {
			return a.fail("init", err)
		}
		defer out.Close()
	}
	abandon := func() {
		if out != nil {
			name := out.Name()
			out.Close()
			os.Remove(name)
			out = nil
		}
	}
	if err := l.EnsureDirs(); err != nil {
		abandon()
		return a.fail("init", err)
	}
	ctx := context.Background()
	uictx := a.sys.uiContext(a.env)
	if hasKind(specs, vault.FactorSE) && !hasKind(specs, vault.FactorPassphrase) && (uictx.Tmux || uictx.SSH) {
		// D60: the Secure Enclave dialog cannot appear here; offer a
		// passphrase as a second way to unlock.
		if yes, err := t.YesNo(ui.Format(ui.MsgInitRemote, ui.Vars{}), true); err == nil && yes {
			specs = append(specs, factorArg{kind: vault.FactorPassphrase})
		}
	}
	fspecs, err := a.factorSpecs(ctx, t, specs)
	if err != nil {
		abandon()
		destroySpecs(fspecs)
		return a.fail("init", err)
	}
	recovery, err := vs.Init(ctx, vault.InitOptions{Factors: fspecs, UI: vaultUI{t: t, gui: uictx.GUI}, Now: a.now})
	destroySpecs(fspecs)
	if err != nil {
		abandon()
		return a.fail("init", err)
	}
	defer recovery.Destroy()
	if out != nil {
		if err := writeSecretFile(out, recovery); err != nil {
			abandon()
			return a.fail("init", err)
		}
		a.line(ui.MsgRecoveryWritten, ui.Vars{File: a.display(out.Name())})
	}
	if out == nil || *showRecovery {
		if err := a.showRecovery(t, recovery); err != nil {
			return a.fail("init", err)
		}
	}
	if a.sys.goos == "darwin" {
		if yes, err := t.YesNo(ui.Format(ui.MsgServiceOffer, ui.Vars{}), true); err == nil && yes {
			if code := a.serviceInstall(); code != exitOK {
				return code
			}
		}
	}
	a.say(textInitDone)
	return exitOK
}

// showRecovery shows the recovery key on the alternate screen until the
// user types back its last 4 characters (D7). The key exists only in this
// buffer (Init returns it once), so a cancelled type-back offers to show
// it again instead of losing it.
func (a *app) showRecovery(t terminal, recovery *memguard.LockedBuffer) error {
	header := strings.Split(ui.Format(ui.MsgRecoveryHeader, ui.Vars{}), "\n")
	for {
		err := t.ShowSecretScreen(header, recovery, 4)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ui.ErrCancelled) {
			return err
		}
		again, yerr := t.YesNo(ui.Format(ui.MsgRecoveryAgain, ui.Vars{}), true)
		if yerr != nil || !again {
			a.line(ui.MsgRecoveryLost, ui.Vars{})
			return err
		}
	}
}

func hasKind(specs []factorArg, k vault.FactorKind) bool {
	for _, s := range specs {
		if s.kind == k {
			return true
		}
	}
	return false
}

// destroySpecs wipes passphrases that Init did not consume.
func destroySpecs(specs []vault.FactorSpec) {
	for _, s := range specs {
		if s.Passphrase != nil {
			s.Passphrase.Destroy()
		}
	}
}

// factorSpecs turns --factor values into enrollment specs: Secure Enclave
// keys are generated with age-plugin-se (keygen output: recipient and
// identity stub, neither secret), passphrases are typed twice or generated
// (diceware, D3), plugins are pinned by path.
func (a *app) factorSpecs(ctx context.Context, t terminal, specs []factorArg) ([]vault.FactorSpec, error) {
	var out []vault.FactorSpec
	for _, s := range specs {
		switch s.kind {
		case vault.FactorSE:
			fs, err := a.seKeygen(ctx)
			if err != nil {
				return out, err
			}
			out = append(out, fs)
		case vault.FactorPassphrase:
			p, err := a.choosePassphrase(t)
			if err != nil {
				return out, err
			}
			out = append(out, vault.FactorSpec{Kind: vault.FactorPassphrase, Passphrase: p})
		case vault.FactorPlugin:
			path, err := paths.LookPath(a.env, "age-plugin-"+s.plugin)
			if err != nil {
				return out, fmt.Errorf("age-plugin-%s: %w", s.plugin, err)
			}
			out = append(out, vault.FactorSpec{Kind: vault.FactorPlugin, Name: s.plugin, Recipient: s.recipient, IdentityStub: s.stub, PluginPath: path})
		}
	}
	return out, nil
}

// seKeygen creates a Secure Enclave key with age-plugin-se. The plugin
// runs with PATH limited to its own directory (S2); its keygen output
// carries the recipient and the identity stub, neither of which is secret.
func (a *app) seKeygen(ctx context.Context) (vault.FactorSpec, error) {
	path, err := paths.LookPath(a.env, "age-plugin-se")
	if err != nil {
		a.line(ui.MsgInitNeedSE, ui.Vars{})
		return vault.FactorSpec{}, shownError{reason: "age-plugin-se missing", code: exitError}
	}
	env := []string{"PATH=" + filepath.Dir(path)}
	if h := a.home(); h != "" {
		env = append(env, "HOME="+h)
	}
	outb, err := a.sys.exec(ctx, execSpec{
		Argv:    []string{path, "keygen", "--access-control", seAccessControl},
		Env:     env,
		Timeout: 2 * time.Minute,
	})
	if err != nil {
		return vault.FactorSpec{}, fmt.Errorf(textNoSEPlugin, "keygen failed")
	}
	recipient, stub := parseSEKeygen(outb)
	if recipient == "" || stub == "" {
		return vault.FactorSpec{}, fmt.Errorf(textNoSEPlugin, "unexpected output")
	}
	return vault.FactorSpec{
		Kind:            vault.FactorSE,
		Recipient:       recipient,
		IdentityStub:    stub,
		PluginPath:      path,
		SEAccessControl: seAccessControl,
	}, nil
}

// parseSEKeygen extracts the recipient and the AGE-PLUGIN-SE-1… identity
// stub from age-plugin-se keygen output. A P-256 tag recipient (age1tag1…,
// wrapped natively by age ≥ 1.3) is preferred over the plugin recipient
// (age1se1…), SPEC §4.3.
func parseSEKeygen(out []byte) (recipient, stub string) {
	var tag, se string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "AGE-PLUGIN-SE-1") && stub == "" {
			stub = line
			continue
		}
		for _, w := range strings.Fields(strings.TrimLeft(line, "#")) {
			switch {
			case strings.HasPrefix(w, "age1tag1") && tag == "":
				tag = w
			case strings.HasPrefix(w, "age1se1") && se == "":
				se = w
			}
		}
	}
	if tag != "" {
		return tag, stub
	}
	return se, stub
}

// choosePassphrase reads a new passphrase twice (≥ 12 characters, ≈ 80
// bits, D3) or, on an empty answer, generates a 7-word diceware one and
// shows it on the alternate screen.
func (a *app) choosePassphrase(t terminal) (*memguard.LockedBuffer, error) {
	for i := 0; i < 3; i++ {
		p, err := t.Secret(ui.Format(ui.MsgPassphraseNew, ui.Vars{}))
		if err != nil {
			return nil, err
		}
		if p == nil || p.Size() == 0 {
			if p != nil {
				p.Destroy()
			}
			g, err := vault.Diceware(7)
			if err != nil {
				return nil, err
			}
			if err := t.ShowSecretScreen([]string{ui.Format(ui.MsgPassphraseGen, ui.Vars{})}, g, 4); err != nil {
				g.Destroy()
				return nil, err
			}
			return g, nil
		}
		if p.Size() < 12 || vault.EstimateBits(p) < 80 {
			p.Destroy()
			a.line(ui.MsgPassphraseWeak, ui.Vars{})
			continue
		}
		q, err := t.Secret(ui.Format(ui.MsgPassphraseAgain, ui.Vars{}))
		if err != nil {
			p.Destroy()
			return nil, err
		}
		same := q != nil && p.EqualTo(q.Bytes())
		if q != nil {
			q.Destroy()
		}
		if !same {
			p.Destroy()
			a.line(ui.MsgPassphraseDiff, ui.Vars{})
			continue
		}
		return p, nil
	}
	return nil, refusedError{reason: "no passphrase"}
}

// createRecoveryOut validates --recovery-out and creates the file (O_EXCL,
// O_NOFOLLOW, 0600). It is refused inside protected folders, harness homes,
// precinto's own data folder and cloud-synced folders (SPEC §4.7).
func (a *app) createRecoveryOut(p string) (*os.File, error) {
	abs, err := a.absPath(p)
	if err != nil {
		return nil, err
	}
	dir, err := a.sys.realpath(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	target := filepath.Join(dir, filepath.Base(abs))
	cfg, err := a.config()
	if err != nil {
		return nil, err
	}
	bad := func(why string) error {
		a.say(textRecoveryOutBad, a.display(target), why)
		return refusedError{reason: why}
	}
	if _, ok := cfg.RootFor(target); ok {
		return nil, bad("it is inside a protected folder")
	}
	for _, h := range a.harnessHomes(cfg) {
		if paths.Within(h, target) {
			return nil, bad("it is inside a harness data folder")
		}
	}
	if l, err := a.layout(); err == nil && paths.Within(l.Base, target) {
		return nil, bad("it is inside precinto's data folder")
	}
	if a.sys.cloudSynced(target) {
		return nil, bad("it is inside a cloud-synced folder")
	}
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// harnessHomes lists the harness data folders a secret must never be
// written to: registered homes plus the default Claude and Codex homes of
// this environment.
func (a *app) harnessHomes(cfg config.Config) []string {
	var out []string
	for _, h := range cfg.Harness {
		for _, home := range h.Homes {
			for _, d := range []string{home.Dir, home.Tmp, home.Cache} {
				if d != "" {
					out = append(out, d)
				}
			}
		}
	}
	if l, err := a.layout(); err == nil {
		out = append(out, l.HomesDir)
	}
	home := a.home()
	if d := a.env.Get(paths.EnvClaudeConfigDir); filepath.IsAbs(d) {
		out = append(out, filepath.Clean(d))
	} else if home != "" {
		out = append(out, filepath.Join(home, ".claude"))
	}
	if d := a.env.Get(paths.EnvCodexHome); filepath.IsAbs(d) {
		out = append(out, filepath.Clean(d))
	} else if home != "" {
		out = append(out, filepath.Join(home, ".codex"))
	}
	if d := a.env.Get(paths.EnvClaudeTmpDir); filepath.IsAbs(d) {
		out = append(out, filepath.Clean(d))
	}
	return out
}

// writeSecretFile writes a secret plus a newline and syncs the file.
func writeSecretFile(f *os.File, secret *memguard.LockedBuffer) error {
	if _, err := f.Write(secret.Bytes()); err != nil {
		return err
	}
	if _, err := f.Write([]byte("\n")); err != nil {
		return err
	}
	return f.Sync()
}

func cmdFactor(a *app, args []string) int {
	f := newFlags("factor")
	stub := f.String("identity-stub", "", "plugin identity `STUB` (AGE-PLUGIN-…-1…) for factor add plugin:<recipient>")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) == 0 {
		return a.usageFail(f, "missing subcommand")
	}
	if err := a.refuseAgent(refusal{action: "change the unlock methods of", folder: "your folders", command: "factor " + pos[0]}); err != nil {
		return exitLocked
	}
	vs, err := a.vaults()
	if err != nil {
		return a.fail("factor", err)
	}
	switch pos[0] {
	case "list":
		if len(pos) != 1 {
			return a.usageFail(f, "factor list takes no argument")
		}
		return a.factorList(vs)
	case "add":
		if len(pos) != 2 {
			return a.usageFail(f, "factor add needs one factor (se, passphrase or plugin:<recipient>)")
		}
		fa, err := parseFactor(pos[1], a.sys.goos)
		if err != nil {
			return a.usageFail(f, err.Error())
		}
		fa.stub = *stub
		return a.factorAdd(fa)
	case "remove":
		if len(pos) != 2 {
			return a.usageFail(f, "factor remove needs a factor name (see precinto factor list)")
		}
		return a.factorRemove(vs, pos[1])
	case "test":
		if len(pos) != 2 {
			return a.usageFail(f, "factor test needs a factor name (see precinto factor list)")
		}
		return a.factorTest(pos[1])
	}
	return a.usageFail(f, "unknown subcommand "+pos[0])
}

func (a *app) factorList(vs vaultStore) int {
	m, err := vs.Meta(vault.GlobalID)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			a.line(ui.MsgNotInitialized, ui.Vars{})
			return exitError
		}
		return a.fail("factor", err)
	}
	for _, fc := range m.Factors {
		gui := ""
		if fc.GUI {
			gui = "  (works without a terminal)"
		}
		added := ""
		if !fc.AddedAt.IsZero() {
			added = "  added " + fc.AddedAt.In(a.sys.loc).Format("2006-01-02")
		}
		fmt.Fprintf(a.out, "%-12s %-10s%s%s\n", fc.Name, fc.Kind, added, gui)
	}
	return exitOK
}

func (a *app) factorAdd(fa factorArg) int {
	t, err := a.needTerminal("factor add")
	if err != nil {
		return exitLocked
	}
	defer t.Close()
	if err := a.sys.harden(); err != nil {
		return a.fail("factor", err)
	}
	ctx := context.Background()
	req := ipc.FactorAddReq{Kind: string(fa.kind)}
	switch fa.kind {
	case vault.FactorSE:
		fs, err := a.seKeygen(ctx)
		if err != nil {
			return a.fail("factor", err)
		}
		req.Recipient, req.IdentityStub, req.PluginPath = fs.Recipient, fs.IdentityStub, fs.PluginPath
	case vault.FactorPlugin:
		path, err := paths.LookPath(a.env, "age-plugin-"+fa.plugin)
		if err != nil {
			return a.fail("factor", fmt.Errorf("age-plugin-%s: %w", fa.plugin, err))
		}
		req.Recipient, req.IdentityStub, req.PluginPath = fa.recipient, fa.stub, path
	}
	// factor_add needs every vault unlocked: a daemon that is not running
	// has none, so there is nothing to autostart.
	c, err := a.dial(ctx, false)
	if err != nil {
		if errors.Is(err, ipc.ErrNoDaemon) {
			a.say(textFactorNeedOpen)
			return exitLocked
		}
		return a.fail("factor", err)
	}
	defer c.Close()
	if err := c.FactorAdd(ctx, req, t); err != nil {
		return a.fail("factor", err)
	}
	a.say(textFactorAdded, fa.kind)
	return exitOK
}

func (a *app) factorRemove(vs vaultStore, name string) int {
	t, err := a.needTerminal("factor remove")
	if err != nil {
		return exitLocked
	}
	defer t.Close()
	if name == string(vault.FactorRecovery) {
		return a.fail("factor", usageErrorf("the recovery key cannot be removed"))
	}
	ok, err := t.YesNo(fmt.Sprintf(textFactorRemove, name), false)
	if err != nil || !ok {
		a.say(textNotConfirmed)
		return exitLocked
	}
	ids, err := vs.List()
	if err != nil {
		return a.fail("factor", err)
	}
	// The last interactive factor is refused by the vault itself
	// (ErrLastFactor) before any vault is changed: check them all first.
	var errs []error
	for _, id := range ids {
		if err := vs.RemoveFactor(id, name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return a.fail("factor", err)
	}
	a.say(textFactorRemoved, name)
	return exitOK
}

// factorTest unlocks the global vault with one factor for one minute and
// locks it again unless it was already unlocked.
func (a *app) factorTest(name string) int {
	t, err := a.needTerminal("factor test")
	if err != nil {
		return exitLocked
	}
	defer t.Close()
	if err := a.sys.harden(); err != nil {
		return a.fail("factor", err)
	}
	ctx := context.Background()
	c, err := a.dial(ctx, true)
	if err != nil {
		return a.fail("factor", err)
	}
	defer c.Close()
	wasOpen := false
	if st, err := c.Status(ctx); err == nil {
		wasOpen = unlockedVaults(st)[vault.GlobalID]
	}
	_, err = c.Unlock(ctx, ipc.UnlockReq{Global: true, Factor: name, TTL: time.Minute, TTY: true, Deadline: a.now().Add(3 * time.Minute)}, t)
	if err != nil {
		return a.fail("factor", err)
	}
	if !wasOpen {
		_, _ = c.Lock(ctx, ipc.LockReq{RootIDs: []string{vault.GlobalID}})
	}
	a.say(textFactorTested, name)
	return exitOK
}

func cmdRecover(a *app, args []string) int {
	f := newFlags("recover")
	verify := f.Bool("verify", false, "check that the recovery key opens your sealed folders")
	keyFile := f.String("key-file", "", "read the recovery key from `FILE` (needs --insecure-key-file)")
	insecure := f.Bool("insecure-key-file", false, "accept a recovery key stored in a plain file")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageFail(f, "unexpected argument "+pos[0])
	}
	if *keyFile != "" && !*insecure {
		a.say(textRecoveryFile)
		return exitUsage
	}
	if err := a.refuseAgent(refusal{action: "use the recovery key of", folder: "your folders", command: "recover"}); err != nil {
		return exitLocked
	}
	if err := a.sys.harden(); err != nil {
		return a.fail("recover", err)
	}
	key, t, err := a.readRecoveryKey(*keyFile)
	if t != nil {
		defer t.Close()
	}
	if err != nil {
		return a.fail("recover", err)
	}
	defer key.Destroy()
	if _, err := vault.ParseRecoveryKey(key); err != nil {
		return a.fail("recover", err)
	}
	ctx := context.Background()
	if *verify {
		return a.recoverVerify(ctx, key)
	}
	return a.recoverUse(ctx, key, t)
}

// readRecoveryKey reads the key from --key-file, the terminal, or stdin
// (SPEC §4.7). The terminal is returned for relayed prompts.
func (a *app) readRecoveryKey(keyFile string) (*memguard.LockedBuffer, terminal, error) {
	if keyFile != "" {
		abs, err := a.absPath(keyFile)
		if err != nil {
			return nil, nil, err
		}
		fh, err := os.OpenFile(abs, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, nil, err
		}
		defer fh.Close()
		b, err := readSecret(fh)
		return b, nil, err
	}
	if t, err := a.sys.openTTY(); err == nil {
		b, err := t.Secret(ui.Format(ui.MsgRecoveryPrompt, ui.Vars{}))
		return b, t, err
	}
	b, err := readSecret(a.in)
	return b, nil, err
}

// readSecret reads at most maxKeyFile bytes into a locked buffer,
// trimming surrounding whitespace; the transient read buffer is wiped.
func readSecret(r io.Reader) (*memguard.LockedBuffer, error) {
	work := memguard.NewBuffer(maxKeyFile + 1)
	defer work.Destroy()
	n, err := io.ReadFull(r, work.Bytes())
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if n > maxKeyFile {
		return nil, errors.New("recovery key input is too large")
	}
	b := bytes.TrimSpace(work.Bytes()[:n])
	if len(b) == 0 {
		return nil, errors.New("no recovery key given")
	}
	out := memguard.NewBuffer(len(b))
	out.Copy(b)
	return out, nil
}

// recoverVerify checks the key against a header freshly made for the
// install's recovery recipient and, when capsules exist, against the
// newest logged capsule (SPEC §4.7, D7).
func (a *app) recoverVerify(ctx context.Context, key *memguard.LockedBuffer) int {
	vs, err := a.vaults()
	if err != nil {
		return a.fail("recover", err)
	}
	m, err := vs.Meta(vault.GlobalID)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			a.line(ui.MsgNotInitialized, ui.Vars{})
			return exitError
		}
		return a.fail("recover", err)
	}
	header, err := freshHeader(m.RecoveryRecipient)
	if err != nil {
		a.say(textRecoveryUnknown, "the recovery recipient is unreadable")
		return exitVerify
	}
	if err := vault.VerifyRecovery(key, header); err != nil {
		return a.fail("recover", err)
	}
	if eng, err := a.engine(ctx, false); err == nil {
		if h, ok, err := eng.LatestCapsuleHeader(); err == nil && ok {
			if err := vault.VerifyRecovery(key, h); err != nil {
				return a.fail("recover", err)
			}
		}
	}
	// Recorded in every vault.toml, so status stops saying "never tested"
	// (CC-07).
	if err := vs.MarkRecoveryVerified(a.now()); err != nil {
		return a.fail("recover", err)
	}
	a.sayOut(textRecoveryOK)
	return exitOK
}

// freshHeader returns the age header of a new, empty file encrypted to
// recipient.
func freshHeader(recipient string) ([]byte, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return age.ExtractHeader(&buf)
}

// recoverUse unlocks every folder with the recovery factor: the daemon
// asks for the key once per folder and each prompt is answered with it, so
// that a lost factor can be replaced (factor add).
func (a *app) recoverUse(ctx context.Context, key *memguard.LockedBuffer, t terminal) int {
	var next interface {
		Display(string) error
		Confirm(string, string, string) (bool, error)
	} = headlessUI{w: a.err}
	if t != nil {
		next = t
	}
	c, err := a.dial(ctx, true)
	if err != nil {
		return a.fail("recover", err)
	}
	defer c.Close()
	resp, err := c.Unlock(ctx, ipc.UnlockReq{
		All:       true,
		Global:    true,
		Factor:    string(vault.FactorRecovery),
		TTY:       t != nil,
		Confirmed: true,
		Deadline:  a.now().Add(5 * time.Minute),
	}, secretAnswer{secret: key, next: next})
	if err != nil {
		return a.fail("recover", err)
	}
	a.say(textRecovered, len(resp.Unlocked))
	return exitOK
}
