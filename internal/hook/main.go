package hook

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// system is what Main takes from the process besides Deps; tests replace
// it (no hardening, fake dependencies, shorter deadlines).
type system struct {
	harden func() error
	deps   func(env paths.Env) Deps
	getwd  func() (string, error)
	timing func(Host, Event) Timing
}

// productionSystem is the real process: platform hardening first (S15),
// dependencies from the hook-mode layout, the normative timings.
func productionSystem() system {
	return system{
		harden: platform.Harden,
		deps:   productionDeps,
		getwd:  os.Getwd,
		timing: timings,
	}
}

// progress is what handle has learned about the session, read by Main when
// handle panics or overruns the deadline.
type progress struct {
	mu      sync.Mutex
	known   bool
	managed bool
	folder  string
}

// learned records handle's classification (nil-safe).
func (p *progress) learned(managed bool, folder string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.known, p.managed, p.folder = true, managed, folder
}

func (p *progress) get() (known, managed bool, folder string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.known, p.managed, p.folder
}

// invocation is one `precinto hook <label> <event>` run.
type invocation struct {
	label string
	ev    Event
	env   paths.Env
	sys   system
	host  Host
	deps  Deps
	ready bool // deps were built
	prog  progress

	payload *Payload // decoded payload, once known
	pre     bool     // managed by what Main itself can see (payload roots, a ledger file)
	preDir  string   // display folder for pre
}

// run implements Main with an explicit system.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, env paths.Env, sys system) int {
	start := time.Now()
	label, name, ok := parseArgs(args)
	if !ok {
		// Not a hook invocation precinto wrote: the shim's rule decides.
		return ExitFailure
	}
	inv := &invocation{label: label, ev: parseEvent(name), env: env, sys: sys}
	inv.host = detectHost(label, env, nil)
	out := inv.execute(stdin, start)
	if len(out.Stdout) > 0 && stdout != nil {
		_, _ = stdout.Write(out.Stdout)
	}
	if len(out.Stderr) > 0 && stderr != nil {
		_, _ = stderr.Write(out.Stderr)
	}
	return out.Exit
}

// parseArgs accepts "<label> <event>", with or without the leading "hook"
// subcommand name.
func parseArgs(args []string) (label, event string, ok bool) {
	if len(args) == 3 && args[0] == "hook" {
		args = args[1:]
	}
	if len(args) != 2 || args[0] == "" || args[1] == "" {
		return "", "", false
	}
	return args[0], args[1], true
}

// execute runs the hook and always returns a valid answer: a panic or an
// overrun anywhere fails closed for a managed gate event and exits 0
// otherwise (I5).
func (inv *invocation) execute(stdin io.Reader, start time.Time) (out Output) {
	defer func() {
		if recover() != nil {
			out = inv.fallback()
		}
	}()
	if err := inv.sys.harden(); err != nil {
		// Never read a payload into an unhardened process (S15): decide from
		// the environment alone.
		inv.deps, inv.ready = inv.sys.deps(inv.env), true
		return inv.staticAnswer()
	}
	inv.deps, inv.ready = inv.sys.deps(inv.env), true

	ctx, cancel := context.WithDeadline(context.Background(), start.Add(inv.sys.timing(inv.host, inv.ev).Deadline))
	defer cancel()
	raw, err := readPayload(ctx, stdin)
	if err != nil {
		return inv.staticAnswer()
	}
	if host := detectHost(inv.label, inv.env, raw); host != inv.host {
		inv.host = host
		var cancel2 context.CancelFunc
		ctx, cancel2 = context.WithDeadline(ctx, start.Add(inv.sys.timing(host, inv.ev).Deadline))
		defer cancel2()
	}
	if inv.host == HostUnknown {
		return inv.unknownAnswer(raw)
	}
	p, err := decode(inv.host, inv.label, inv.ev, raw, inv.env, inv.deps.Procs)
	if err != nil {
		return inv.staticAnswer()
	}
	inv.payload = &p
	inv.pre, inv.preDir = inv.preclassify(p)

	done := make(chan Decision, 1)
	failed := make(chan struct{})
	go func() {
		defer func() {
			if recover() != nil {
				close(failed)
			}
		}()
		done <- handle(ctx, inv.deps, p, &inv.prog)
	}()
	select {
	case d := <-done:
		return encode(inv.host, inv.ev, d)
	case <-failed:
		return inv.fallback()
	case <-ctx.Done():
		// The deadline: answer now, strictly before the harness timeout.
		select {
		case d := <-done:
			return encode(inv.host, inv.ev, d)
		default:
		}
		return inv.fallback()
	}
}

// fallback is the answer after a panic or an overrun: fail closed when the
// session is (or may be) managed.
func (inv *invocation) fallback() Output {
	if !inv.ready {
		// Not even the configuration could be read: the shim's roots.list
		// rule decides (it blocks gate events inside protected folders).
		if isGate(inv.host, inv.ev) {
			return Output{Exit: ExitFailure}
		}
		return Output{Exit: ExitOK}
	}
	known, managed, folder := inv.prog.get()
	if !known || inv.pre {
		managed = managed || inv.pre
		if folder == "" {
			folder = inv.preDir
		}
	}
	if inv.payload == nil {
		// Nothing decoded yet: what the environment shows.
		m, f := inv.envManaged()
		managed, folder = managed || m, firstNonEmpty(folder, f)
	}
	if !managed {
		return Output{Exit: ExitOK}
	}
	return failClosed(inv.host, inv.ev, folder)
}

// staticAnswer is the answer when the payload cannot be used (oversized,
// unreadable before the deadline, undecodable, or an unhardened process):
// the roots the environment shows decide.
func (inv *invocation) staticAnswer() Output {
	managed, folder := inv.envManaged()
	if !managed {
		return Output{Exit: ExitOK}
	}
	return failClosed(inv.host, inv.ev, folder)
}

// unknownAnswer handles an unrecognised label with no host marker
// (HOOKS-IO §0.7): gate events whose cwd or CLAUDE_PROJECT_DIR lies inside
// a root exit ExitFailure (the shim then blocks), everything else exits 0.
func (inv *invocation) unknownAnswer(raw []byte) Output {
	if !isGate(HostUnknown, inv.ev) {
		return Output{Exit: ExitOK}
	}
	dirs := inv.envDirs()
	if p, err := decode(HostUnknown, inv.label, inv.ev, raw, inv.env, nil); err == nil {
		dirs = append(dirs, p.Cwd)
	}
	if len(inv.deps.Cfg.RootsFor(dirs...)) > 0 {
		return Output{Exit: ExitFailure}
	}
	return Output{Exit: ExitOK}
}

// envDirs are the directories the environment names: the working
// directory and CLAUDE_PROJECT_DIR (the shim compares the same two).
func (inv *invocation) envDirs() []string {
	var dirs []string
	if inv.sys.getwd != nil {
		if wd, err := inv.sys.getwd(); err == nil {
			dirs = append(dirs, absPath(wd))
		}
	}
	dirs = append(dirs, absPath(inv.env.Get("PWD")))
	if inv.host != HostCodex {
		dirs = append(dirs, absPath(inv.env.Get(paths.EnvClaudeProjectDir)))
	}
	return dirs
}

// envManaged reports whether the environment's directories lie in a root,
// and the display folder.
func (inv *invocation) envManaged() (bool, string) {
	roots := inv.deps.Cfg.RootsFor(inv.envDirs()...)
	if len(roots) == 0 {
		return false, ""
	}
	return true, inv.tilde(roots[0].Path)
}

// preclassify is Main's own view of managed-ness, taken before handle runs
// so that a panic or a stalled read inside handle still fails closed: a
// root among the payload's dirs and paths, or an existing session ledger
// (it is created at the first managed event, SPEC §14.3).
func (inv *invocation) preclassify(p Payload) (bool, string) {
	if roots := inv.deps.Cfg.RootsFor(taintCandidates(p)...); len(roots) > 0 {
		return true, inv.tilde(roots[0].Path)
	}
	if ledgerExists(inv.deps.Layout, harnessName(p), p.SID) {
		return true, inv.tilde(firstNonEmpty(p.Cwd, p.ProjectDir))
	}
	return false, ""
}

// ledgerExists reports whether state/sessions/<harness>/<sid>.jsonl exists.
func ledgerExists(l paths.Layout, harness, sid string) bool {
	if l.SessionsDir == "" || !safeName(harness) || !safeName(sid) {
		return false
	}
	_, err := os.Lstat(filepath.Join(l.SessionsDir, harness, sid+".jsonl"))
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

// safeName reports whether s can be one path component.
func safeName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}

func (inv *invocation) tilde(p string) string {
	if p == "" {
		return ""
	}
	home, err := paths.UserHome(inv.env)
	if err != nil {
		return p
	}
	return paths.Tilde(home, p)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// readPayload reads stdin up to MaxPayload+1 bytes, giving up at the
// deadline (a harness that never closes stdin must not stall the answer).
func readPayload(ctx context.Context, stdin io.Reader) ([]byte, error) {
	if stdin == nil {
		return nil, nil
	}
	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		b, err := io.ReadAll(io.LimitReader(stdin, MaxPayload+1))
		ch <- result{b, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if len(r.b) > MaxPayload {
			return nil, errTooLarge
		}
		return r.b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
