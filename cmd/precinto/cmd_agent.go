package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/agent"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/ipc"
)

// shutdownWait bounds how long `agent --stop` and `agent --restart` wait
// for the running daemon to exit.
const shutdownWait = 10 * time.Second

func cmdAgent(a *app, args []string) int {
	f := newFlags("agent")
	foreground := f.Bool("foreground", false, "stay attached to this terminal (logs on stderr)")
	restart := f.Bool("restart", false, "stop the running agent, then start it again in the background (with --foreground: in this terminal)")
	stop := f.Bool("stop", false, "stop the running agent: its keys are wiped, so every folder locks")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageFail(f, "unexpected argument "+pos[0])
	}
	if *stop && (*restart || *foreground) {
		return a.usageFail(f, "--stop takes no other flag")
	}
	if *stop {
		// D129: like `precinto lock` it only locks (the keys are wiped),
		// so an agent context may run it too.
		stopped, err := a.stopAgent()
		if err != nil {
			return a.fail("agent", err)
		}
		if !stopped {
			a.say(textAgentNotRunning)
		}
		return exitOK
	}
	l, err := a.layout()
	if err != nil {
		return a.fail("agent", err)
	}
	if err := l.EnsureDirs(); err != nil {
		return a.fail("agent", err)
	}
	ctx := context.Background()
	if *restart {
		if _, err := a.stopAgent(); err != nil {
			return a.fail("agent", err)
		}
		if !*foreground {
			// D141: the new agent starts detached, as an autostart starts
			// it, and the terminal gets its prompt back.
			c, err := a.dial(ctx, true)
			if err != nil {
				return a.fail("agent", err)
			}
			defer c.Close()
			st, err := c.Status(ctx)
			if err != nil {
				return a.fail("agent", err)
			}
			a.say(textAgentRunning, st.PID)
			return exitOK
		}
	}
	exe, err := a.sys.executable()
	if err != nil {
		return a.fail("agent", err)
	}
	// The daemon runs in this process: `precinto agent` is what ipc.Dial's
	// autostart executes detached. SIGINT/SIGTERM end it (keys wiped).
	ctx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	err = a.sys.agentRun(ctx, agent.Options{
		Layout: l,
		// Started from an agent's shell, the daemon gets no dialog
		// endpoint for its pinentry (D139; CROSS from group a).
		Env:        agent.StartEnv(a.env, a.procs(), a.sys.self().PID),
		Exe:        exe,
		Version:    buildVersion(),
		Foreground: *foreground,
		Clock:      a.sys.clock(),
		Procs:      a.sys.procs(),
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return a.fail("agent", err)
	}
	return exitOK
}

// stopAgent asks a running daemon to wipe its keys and exit, and waits
// until it no longer answers (D129); stopped is false when none ran.
func (a *app) stopAgent() (stopped bool, err error) {
	ctx := context.Background()
	c, err := a.dial(ctx, false)
	if err != nil {
		if errors.Is(err, ipc.ErrNoDaemon) {
			return false, nil
		}
		return false, err
	}
	err = c.Shutdown(ctx)
	c.Close()
	if err != nil {
		return false, err
	}
	// While it exits the agent may still accept a connection and close it
	// at once (the dial then cannot read its credentials): only "no agent"
	// ends the wait.
	const poll = 100 * time.Millisecond
	last := errors.New("it still answers")
	for i := 0; i < int(shutdownWait/poll); i++ {
		c, err := a.dial(ctx, false)
		if errors.Is(err, ipc.ErrNoDaemon) {
			a.say(textAgentStopped)
			return true, nil
		}
		if err == nil {
			c.Close()
		} else {
			last = err
		}
		a.sys.sleep(poll)
	}
	return false, fmt.Errorf("the running agent did not stop in time (%v)", last)
}

func cmdDoctor(a *app, args []string) int {
	f := newFlags("doctor")
	leaks := f.Bool("leaks", false, "also look for residue outside precinto's inventory (slower)")
	asJSON := f.Bool("json", false, "print the findings as one JSON document (v1)")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 1 {
		return a.usageFail(f, "doctor takes at most one harness")
	}
	l, err := a.layout()
	if err != nil {
		return a.fail("doctor", err)
	}
	cfg, cfgErr := a.config()
	if cfgErr != nil {
		// doctor diagnoses a broken config.toml instead of stopping on it
		// (UX-09): its config check reports the error, the other checks
		// run with the settings standing in for it (the settings confirmed
		// last or the defaults, plus every folder whose vault records its
		// path), and doctor never calls a folder check ok then.
		cfg, _ = a.standInConfig(l)
	}
	o := doctor.Options{Cfg: cfg, Layout: l, Env: a.env, Procs: a.procs(), Leaks: *leaks, ConfigErr: cfgErr}
	if len(pos) == 1 {
		o.Harness = pos[0]
		if _, ok := cfg.Harness[o.Harness]; !ok {
			return a.usageFail(f, fmt.Sprintf("unknown harness %q (known: %v)", o.Harness, knownHarnesses(cfg)))
		}
	}
	ctx := context.Background()
	// doctor is read-only: the adapters it inspects are registered, but no
	// engine is built (that would create precinto's directories and salt).
	a.sys.registerAdapters()
	findings, err := a.sys.doctorRun(ctx, o)
	if err != nil {
		return a.fail("doctor", err)
	}
	// doctor.Render is the one renderer (CC-45); exit 1 only when a
	// finding fails, warnings do not change it (SPEC §16.2).
	if err := doctor.Render(a.out, findings, *asJSON); err != nil {
		return a.fail("doctor", err)
	}
	if doctor.Worst(findings) == doctor.Fail {
		return exitError
	}
	return exitOK
}

// cmdHook is the harness hook entry point: it must stay fast and fail
// closed, so it delegates at once to hook.Main (G5), which hardens the
// process, enforces its own deadline, recovers panics and never honours
// PRECINTO_* overrides (D6, D56). Nothing is loaded before it.
func cmdHook(a *app, args []string) int {
	return a.sys.hookMain(args, a.in, a.out, a.err, a.env)
}
