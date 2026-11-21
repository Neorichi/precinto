package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/paths"
)

// serviceLabel is the LaunchAgent label (SPEC §13.1: it runs only
// `precinto sweep --quiet`, every 10 minutes, at background priority, and
// never holds keys).
const (
	serviceLabel    = "com.github.precinto.sweep"
	serviceInterval = 600 // seconds
	launchctlPath   = "/bin/launchctl"
)

func cmdService(a *app, args []string) int {
	f := newFlags("service")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) != 1 {
		return a.usageFail(f, "service needs install, uninstall or status")
	}
	switch pos[0] {
	case "install":
		return a.serviceInstall()
	case "uninstall":
		return a.serviceUninstall()
	case "status":
		return a.serviceStatus()
	}
	return a.usageFail(f, "unknown subcommand "+pos[0])
}

// servicePlist returns the LaunchAgent plist path under the user's HOME.
func (a *app) servicePlist() (string, error) {
	home, err := paths.UserHome(a.env)
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", serviceLabel+".plist"), nil
}

// serviceState is "installed", "not-installed" or "unavailable" (status).
func (a *app) serviceState() string {
	if a.sys.goos != "darwin" {
		return "unavailable"
	}
	p, err := a.servicePlist()
	if err == nil && fileExists(p) {
		return "installed"
	}
	return "not-installed"
}

// serviceInstall writes the LaunchAgent and loads it. On linux the systemd
// user unit is deferred (D49): exit 2 with a notice.
func (a *app) serviceInstall() int {
	if a.sys.goos != "darwin" {
		a.say(textServiceLinux)
		return exitUsage
	}
	plist, err := a.servicePlist()
	if err != nil {
		return a.fail("service install", err)
	}
	exe, err := a.pinnedExe()
	if err != nil {
		return a.fail("service install", err)
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("service install", err)
	}
	if err := os.MkdirAll(filepath.Dir(plist), 0o700); err != nil {
		return a.fail("service install", err)
	}
	if st, err := fsx.Lstat(filepath.Dir(plist)); err != nil || !st.IsDir() {
		return a.fail("service install", fmt.Errorf("%w: %s is not a directory", fsx.ErrUnsafe, a.display(filepath.Dir(plist))))
	}
	body := renderPlist(exe, a.serviceEnv())
	if err := fsx.WriteFileAtomic(plist, body, 0o600); err != nil {
		return a.fail("service install", err)
	}
	ctx := context.Background()
	domain := "gui/" + strconv.Itoa(a.sys.uid())
	// Reload: a previous version may be loaded (an error means it was not).
	_ = a.sys.launchctl(ctx, []string{"bootout", domain + "/" + serviceLabel})
	if err := a.sys.launchctl(ctx, []string{"bootstrap", domain, plist}); err != nil {
		return a.fail("service install", err)
	}
	// SPEC §13.1: the LaunchAgent must be able to read every folder (TCC
	// guards ~/Documents, ~/Downloads, ~/Desktop, §17). This process is
	// the terminal's, not the agent's, so this is a best-effort warning.
	for _, r := range cfg.Roots {
		if _, err := os.ReadDir(r.Path); err != nil && errors.Is(err, fs.ErrPermission) { // EACCES, EPERM
			a.say(textServiceTCC, a.display(r.Path))
		}
	}
	a.say(textServiceOn, a.display(plist))
	return exitOK
}

// serviceUninstall unloads and removes the LaunchAgent.
func (a *app) serviceUninstall() int {
	if a.sys.goos != "darwin" {
		a.say(textServiceLinux)
		return exitUsage
	}
	plist, err := a.servicePlist()
	if err != nil {
		return a.fail("service uninstall", err)
	}
	ctx := context.Background()
	_ = a.sys.launchctl(ctx, []string{"bootout", "gui/" + strconv.Itoa(a.sys.uid()) + "/" + serviceLabel})
	if err := os.Remove(plist); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return a.fail("service uninstall", err)
	}
	a.say(textServiceOff)
	return exitOK
}

// serviceStatus reports whether the LaunchAgent is installed and its
// heartbeat (state/sweep.last).
func (a *app) serviceStatus() int {
	if a.sys.goos != "darwin" {
		a.say(textServiceLinux)
		return exitUsage
	}
	plist, err := a.servicePlist()
	if err != nil {
		return a.fail("service status", err)
	}
	if !fileExists(plist) {
		a.sayOut(textServiceNone)
		return exitOK
	}
	last := "never"
	if l, err := a.layout(); err == nil {
		if fi, err := os.Stat(l.SweepLast); err == nil {
			last = humanAge(a.now().Sub(fi.ModTime())) + " ago"
		}
	}
	a.sayOut(textServiceStatus, a.display(plist), last)
	return exitOK
}

// pinnedExe is the binary the service and the shell functions run: the
// pinned link <base>/bin/precinto when integrate wrote it (D6), else this
// binary.
func (a *app) pinnedExe() (string, error) {
	if l, err := a.layout(); err == nil {
		if st, err := fsx.Lstat(l.BinLink); err == nil && st.Mode&0o170000 == 0o120000 {
			if target, err := filepath.EvalSymlinks(l.BinLink); err == nil {
				if fi, err := os.Stat(target); err == nil && fi.Mode().IsRegular() {
					return l.BinLink, nil
				}
			}
		}
	}
	exe, err := a.sys.executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		return real, nil
	}
	return exe, nil
}

// serviceEnv is the environment of the LaunchAgent: HOME and a system PATH
// (launchd's own defaults), plus the testing/dev layout overrides only when
// this process honours them itself (D6).
func (a *app) serviceEnv() map[string]string {
	env := map[string]string{"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
	if h := a.home(); h != "" {
		env["HOME"] = h
	}
	if paths.OverridesAllowed(a.env) {
		for _, k := range []string{paths.EnvHome, paths.EnvRuntimeDir, paths.EnvDev} {
			if v := a.env.Get(k); v != "" {
				env[k] = v
			}
		}
	}
	return env
}

// renderPlist renders the LaunchAgent: `<exe> sweep --quiet` every 10
// minutes at background priority, output discarded.
func renderPlist(exe string, env map[string]string) []byte {
	var b bytes.Buffer
	esc := func(s string) string {
		var e bytes.Buffer
		_ = xml.EscapeText(&e, []byte(s))
		return e.String()
	}
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + serviceLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + esc(exe) + `</string>
		<string>sweep</string>
		<string>--quiet</string>
	</array>
	<key>StartInterval</key>
	<integer>` + strconv.Itoa(serviceInterval) + `</integer>
	<key>RunAtLoad</key>
	<true/>
	<key>ProcessType</key>
	<string>Background</string>
	<key>LowPriorityIO</key>
	<true/>
	<key>Nice</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>/dev/null</string>
	<key>StandardErrorPath</key>
	<string>/dev/null</string>
`)
	if len(env) > 0 {
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("\t<key>EnvironmentVariables</key>\n\t<dict>\n")
		for _, k := range keys {
			b.WriteString("\t\t<key>" + esc(k) + "</key>\n\t\t<string>" + esc(env[k]) + "</string>\n")
		}
		b.WriteString("\t</dict>\n")
	}
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes()
}

// runLaunchctl runs /bin/launchctl with a minimal environment. Binaries
// built with -tags testing never run it: tests must not install or remove
// a real LaunchAgent (they observe the calls through the seam).
func runLaunchctl(ctx context.Context, args []string) error {
	return launchctlVia(ctx, args, paths.TestingBuild(), runExternal)
}

// launchctlVia is runLaunchctl with the build flavour and the runner
// explicit (tested without running anything).
func launchctlVia(ctx context.Context, args []string, testing bool, run func(context.Context, execSpec) ([]byte, error)) error {
	if testing {
		return nil
	}
	_, err := run(ctx, execSpec{
		Argv:    append([]string{launchctlPath}, args...),
		Env:     []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		Timeout: 30 * time.Second,
	})
	return err
}
