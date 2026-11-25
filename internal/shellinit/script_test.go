package shellinit_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/shellinit"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
)

const goldenExe = "/opt/precinto/bin/precinto"

// TestScriptGolden pins the snippet of every shell (D29, SPEC §15.5).
func TestScriptGolden(t *testing.T) {
	for _, sh := range []string{shellinit.Zsh, shellinit.Bash, shellinit.Fish} {
		s, err := shellinit.Script(shellinit.Options{Shell: sh, Harnesses: []string{"claude", "codex", "claude"}, Exe: goldenExe})
		if err != nil {
			t.Fatal(err)
		}
		testkit.Golden(t, "shell-init."+sh, []byte(s))
	}
}

func TestScriptRejects(t *testing.T) {
	for name, o := range map[string]shellinit.Options{
		"unknown shell":    {Shell: "tcsh", Exe: goldenExe},
		"relative exe":     {Shell: shellinit.Zsh, Exe: "bin/precinto"},
		"unclean exe":      {Shell: shellinit.Zsh, Exe: "/opt/../precinto"},
		"newline exe":      {Shell: shellinit.Bash, Exe: "/opt/pre\ncinto"},
		"bad harness name": {Shell: shellinit.Bash, Exe: goldenExe, Harnesses: []string{"claude; rm -rf ~"}},
		"upper case name":  {Shell: shellinit.Fish, Exe: goldenExe, Harnesses: []string{"Claude"}},
		"empty name":       {Shell: shellinit.Fish, Exe: goldenExe, Harnesses: []string{""}},
	} {
		if _, err := shellinit.Script(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// bashes are the bash binaries to check (macOS ships 3.2).
func bashes() []string {
	var out []string
	for _, b := range []string{"/bin/bash", "/opt/homebrew/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash"} {
		if st, err := os.Stat(b); err == nil && st.Mode().IsRegular() {
			out = append(out, b)
		}
	}
	return out
}

func lookShell(name string) string {
	for _, d := range []string{"/bin", "/usr/bin", "/opt/homebrew/bin", "/usr/local/bin"} {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// TestScriptSyntax: zsh -n and bash -n parse the snippets, with an
// executable path that needs quoting.
func TestScriptSyntax(t *testing.T) {
	exe := "/opt/pre cinto/it's/precinto"
	check := func(shell, bin string, args ...string) {
		t.Helper()
		s, err := shellinit.Script(shellinit.Options{Shell: shell, Harnesses: []string{"claude", "codex", "gemini"}, Exe: exe})
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(t.TempDir(), "init."+shell)
		if err := os.WriteFile(f, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, append(args, f)...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir()}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s -n: %v\n%s", bin, err, out)
		}
	}
	if zsh := lookShell("zsh"); zsh != "" {
		check(shellinit.Zsh, zsh, "-n", "-f")
	} else {
		t.Log("zsh not installed: zsh -n skipped")
	}
	for _, b := range bashes() {
		check(shellinit.Bash, b, "-n")
	}
	switch fish := lookShell("fish"); {
	case fish != "":
		check(shellinit.Fish, fish, "--no-execute")
	case inCI():
		// CI installs fish (.github/scripts/install-shells.sh): a missing
		// one there is a failure, never a skip (TESTPLAN §10).
		t.Error("fish is required in CI (TESTPLAN §10) and is not installed")
	default:
		t.Log("fish not installed: fish --no-execute not run (required in CI)")
	}
}

// inCI reports whether the tests run in CI (GitHub Actions sets CI=true),
// where every shell a test needs is installed.
func inCI() bool {
	v := paths.FromOS().Get("CI")
	return v != "" && v != "0" && v != "false"
}

// shKeyword matches sh-only reserved words used as words.
var shKeyword = regexp.MustCompile(`(^|[\s;])(fi|esac|done|then|do|elif)([\s;]|$)`)

// TestFishScriptStatic checks the fish text without fish: balanced blocks,
// fish syntax only (no ${…}, no [[ ]], no sh function syntax), the PWD
// handler and the first-prompt run.
func TestFishScriptStatic(t *testing.T) {
	s, err := shellinit.Script(shellinit.Options{Shell: shellinit.Fish, Harnesses: []string{"claude", "codex"}, Exe: "/opt/pre cinto/it's/precinto"})
	if err != nil {
		t.Fatal(err)
	}
	depth := 0
	opener := regexp.MustCompile(`^\s*(function|if|for|while|switch|begin)\b`)
	inline := regexp.MustCompile(`\bor begin\s*$`)
	for i, line := range strings.Split(s, "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "#") || code == "" {
			continue
		}
		if opener.MatchString(code) || inline.MatchString(code) {
			depth++
		}
		if code == "end" {
			depth--
		}
		if depth < 0 {
			t.Fatalf("line %d: unbalanced end", i+1)
		}
		for _, bad := range []string{"${", "[[", "]]", "() {", "$(", "local "} {
			if strings.Contains(code, bad) {
				t.Errorf("line %d: %q is not fish: %s", i+1, bad, code)
			}
		}
		if m := shKeyword.FindString(code); m != "" {
			t.Errorf("line %d: sh keyword %q in fish: %s", i+1, strings.TrimSpace(m), code)
		}
	}
	if depth != 0 {
		t.Errorf("unbalanced blocks: depth %d", depth)
	}
	for _, want := range []string{
		"function claude --wraps claude",
		"command '/opt/pre cinto/it\\'s/precinto' run --harness claude-code -- claude $argv",
		"command '/opt/pre cinto/it\\'s/precinto' run --harness codex -- codex $argv",
		"set -q PRECINTO_ACTIVE",
		"function _precinto_on_pwd --on-variable PWD",
		"function _precinto_first_prompt --on-event fish_prompt",
		"status is-interactive; or return 0",
		"set -q VSCODE_RESOLVING_ENVIRONMENT; and return 0",
		"shell-hook $args",
		`set -g _PRECINTO_SKIP "$root:$epoch"`,
		"case 'path=*'",
		`set dir (string replace -- 'path=' '' $line)`,
		`if test -z "$key"; and test -n "$dir"`,
		`command '/opt/pre cinto/it\'s/precinto' unlock --root "$dir"`,
		"if test \"$action\" = prompt; and isatty stdin; and isatty stdout",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("fish script lacks %q", want)
		}
	}
}

func TestInstallLineAndRCFile(t *testing.T) {
	if got := shellinit.InstallLine(shellinit.Zsh); got != `eval "$(precinto shell-init zsh)"` {
		t.Errorf("zsh line %q", got)
	}
	if got := shellinit.InstallLine(shellinit.Bash); got != `eval "$(precinto shell-init bash)"` {
		t.Errorf("bash line %q", got)
	}
	if got := shellinit.InstallLine(shellinit.Fish); got != "precinto shell-init fish | source" {
		t.Errorf("fish line %q", got)
	}
	if shellinit.InstallLine("tcsh") != "" || shellinit.RCFile("tcsh", "/u") != "" || shellinit.RCFile(shellinit.Zsh, "") != "" {
		t.Error("unknown shell or home")
	}
	for sh, want := range map[string]string{shellinit.Zsh: "/u/.zshrc", shellinit.Bash: "/u/.bashrc", shellinit.Fish: "/u/.config/fish/config.fish"} {
		if got := shellinit.RCFile(sh, "/u"); got != want {
			t.Errorf("RCFile(%s) = %q, want %q", sh, got, want)
		}
	}
}

// TestInstall: appends the line once, keeps what the rc file had, follows
// a symlinked rc file and creates fish's config directory.
func TestInstall(t *testing.T) {
	home := t.TempDir()
	rc := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(rc, []byte("export X=1"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := shellinit.Install(shellinit.Zsh, home); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(rc)
	if want := "export X=1\n" + `eval "$(precinto shell-init zsh)"` + "\n"; string(b) != want {
		t.Errorf(".zshrc = %q, want %q", b, want)
	}
	if st, _ := os.Stat(rc); st.Mode().Perm() != 0o644 {
		t.Errorf("mode changed to %v", st.Mode().Perm())
	}
	// A symlinked rc file is appended through the link.
	dotfiles := filepath.Join(home, "dotfiles")
	if err := os.MkdirAll(dotfiles, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dotfiles, "bashrc")
	if err := os.WriteFile(target, []byte("alias l=ls\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".bashrc")); err != nil {
		t.Fatal(err)
	}
	if err := shellinit.Install(shellinit.Bash, home); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(filepath.Join(home, ".bashrc")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the symlink was replaced: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "alias l=ls\n"+`eval "$(precinto shell-init bash)"`+"\n" {
		t.Errorf("bashrc = %q", b)
	}
	// fish: the directory is created, the file is new.
	if err := shellinit.Install(shellinit.Fish, home); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(home, ".config", "fish", "config.fish")); string(b) != "precinto shell-init fish | source\n" {
		t.Errorf("config.fish = %q", b)
	}
	if err := shellinit.Install("tcsh", home); err == nil {
		t.Error("unknown shell installed")
	}
	if err := shellinit.Install(shellinit.Zsh, "relative"); err == nil {
		t.Error("relative home accepted")
	}
}

// fakePrecinto writes an executable that logs its arguments and answers
// shell-hook with the result file's content.
func fakePrecinto(t *testing.T, dir string) (exe, log, result string) {
	t.Helper()
	exe = filepath.Join(dir, "bin", "precinto")
	log = filepath.Join(dir, "calls.log")
	result = filepath.Join(dir, "result.txt")
	if err := os.MkdirAll(filepath.Dir(exe), 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >>'" + log + "'\ncase $1 in shell-hook) cat '" + result + "' ;; esac\n"
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// A fake harness next to it, first on PATH: no test ever reaches a real
	// claude or codex.
	for _, h := range []string{"claude", "codex"} {
		fake := "#!/bin/sh\nprintf 'fake-%s %s\\n' '" + h + "' \"$*\" >>'" + log + "'\n"
		if err := os.WriteFile(filepath.Join(filepath.Dir(exe), h), []byte(fake), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return exe, log, result
}

// runInteractive feeds commands to an interactive shell with no terminal,
// no rc files and a temporary HOME; it returns stdout.
func runInteractive(t *testing.T, argv []string, home, fakeBinDir, commands string, env ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = home
	cmd.Env = append([]string{"HOME=" + home, "ZDOTDIR=" + home, "PATH=" + fakeBinDir + ":/usr/bin:/bin", "TERM=dumb", "PS1=$ ", "PWD=" + home,
		"BASH_SILENCE_DEPRECATION_WARNING=1"}, env...)
	cmd.Stdin = strings.NewReader(commands)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.SysProcAttr = testkit.NewSession() // never the test's terminal
	cmd.WaitDelay = 5 * time.Second        // a background job holding the pipes cannot stall Wait
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v: %v\nstderr:\n%s", argv, err, errb.String())
	}
	return out.String()
}

// TestFolderEntryHookRuns drives the zsh and bash hooks with a fake
// precinto: shell-hook runs on the first prompt and on directory changes
// only, receives --prev and the remembered skip key, and its message is
// printed; without a terminal a prompt never reads a key or unlocks.
func TestFolderEntryHookRuns(t *testing.T) {
	type run struct {
		name  string
		argv  []string
		shell string
	}
	var runs []run
	if zsh := lookShell("zsh"); zsh != "" {
		runs = append(runs, run{"zsh", []string{zsh, "-f", "-i"}, shellinit.Zsh})
	}
	for _, b := range bashes() {
		runs = append(runs, run{b, []string{b, "--norc", "--noprofile", "-i"}, shellinit.Bash})
	}
	if len(runs) == 0 {
		t.Skip("neither zsh nor bash installed")
	}
	for _, r := range runs {
		t.Run(filepath.Base(r.name)+r.name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			home := filepath.Join(dir, "home")
			root := filepath.Join(home, "work", "acme")
			other := filepath.Join(home, "play")
			for _, d := range []string{root, other} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			exe, log, result := fakePrecinto(t, dir)
			msg := ui.Format(ui.MsgEnterPrompt, ui.Vars{Folder: "~/work/acme", Factor: "Mac password"})
			res := shellinit.EnterResult{Action: shellinit.EnterPrompt, RootID: "root-acme", Path: root, Folder: "~/work/acme", Epoch: 42, Message: msg}
			if err := os.WriteFile(result, []byte(res.Lines()), 0o600); err != nil {
				t.Fatal(err)
			}
			s, err := shellinit.Script(shellinit.Options{Shell: r.shell, Harnesses: []string{"claude"}, Exe: exe})
			if err != nil {
				t.Fatal(err)
			}
			init := filepath.Join(dir, "init.sh")
			if err := os.WriteFile(init, []byte(s), 0o600); err != nil {
				t.Fatal(err)
			}
			commands := ". '" + init + "'\n" + // the first prompt after this runs the hook (--first)
				":\n" + // same directory: nothing
				"cd '" + root + "'\n" + // outside → inside
				"cd '" + other + "'\n" +
				"claude --resume x\n" +
				"PRECINTO_ACTIVE=1 claude -p hi\n" +
				"exit 0\n"
			out := runInteractive(t, r.argv, home, filepath.Dir(exe), commands)
			calls, _ := os.ReadFile(log)
			lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
			want := []string{
				"shell-hook --shell " + r.shell + " --pwd " + home + " --prev  --skip  --first",
				"shell-hook --shell " + r.shell + " --pwd " + root + " --prev " + home + " --skip root-acme:42",
				"shell-hook --shell " + r.shell + " --pwd " + other + " --prev " + root + " --skip root-acme:42",
				"run --harness claude-code -- claude --resume x",
				"fake-claude -p hi",
			}
			if strings.Join(lines, "\n") != strings.Join(want, "\n") {
				t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
			}
			if n := strings.Count(out, msg); n != 3 {
				t.Errorf("message printed %d times, want 3:\n%s", n, out)
			}
			if strings.Contains(string(calls), "unlock") {
				t.Errorf("unlocked without a terminal: %s", calls)
			}
		})
	}
}

// TestFolderEntryHookGuards: no shell-hook call in a non-interactive
// shell, while VS Code resolves the environment, or inside a wrapped
// harness.
func TestFolderEntryHookGuards(t *testing.T) {
	zsh := lookShell("zsh")
	bash := "/bin/bash"
	if _, err := os.Stat(bash); err != nil {
		bash = ""
	}
	type c struct {
		argv  []string
		shell string
		env   []string
	}
	var cases []c
	if zsh != "" {
		cases = append(cases,
			c{[]string{zsh, "-f"}, shellinit.Zsh, nil},
			c{[]string{zsh, "-f", "-i"}, shellinit.Zsh, []string{"VSCODE_RESOLVING_ENVIRONMENT=1"}},
			c{[]string{zsh, "-f", "-i"}, shellinit.Zsh, []string{"PRECINTO_ACTIVE=1"}})
	}
	if bash != "" {
		cases = append(cases,
			c{[]string{bash, "--norc", "--noprofile"}, shellinit.Bash, nil},
			c{[]string{bash, "--norc", "--noprofile", "-i"}, shellinit.Bash, []string{"VSCODE_RESOLVING_ENVIRONMENT=1"}},
			c{[]string{bash, "--norc", "--noprofile", "-i"}, shellinit.Bash, []string{"PRECINTO_ACTIVE=1"}})
	}
	if len(cases) == 0 {
		t.Skip("no zsh or bash")
	}
	for i, tc := range cases {
		dir, _ := filepath.EvalSymlinks(t.TempDir())
		exe, log, result := fakePrecinto(t, dir)
		_ = os.WriteFile(result, []byte("action=notify\nroot=r\nepoch=1\nfolder=f\nmessage=m\n"), 0o600)
		s, err := shellinit.Script(shellinit.Options{Shell: tc.shell, Exe: exe})
		if err != nil {
			t.Fatal(err)
		}
		init := filepath.Join(dir, "init.sh")
		_ = os.WriteFile(init, []byte(s), 0o600)
		runInteractive(t, tc.argv, dir, filepath.Dir(exe), ". '"+init+"'\ncd /\n:\nexit 0\n", tc.env...)
		if b, _ := os.ReadFile(log); len(b) != 0 {
			t.Errorf("case %d (%v %v): shell-hook ran: %s", i, tc.argv, tc.env, b)
		}
	}
}

// TestScriptPreservesExitStatus: the bash prompt command keeps $? for the
// prompt commands that follow it.
func TestScriptPreservesExitStatus(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("no bash")
	}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	exe, _, result := fakePrecinto(t, dir)
	_ = os.WriteFile(result, nil, 0o600)
	s, err := shellinit.Script(shellinit.Options{Shell: shellinit.Bash, Exe: exe})
	if err != nil {
		t.Fatal(err)
	}
	init := filepath.Join(dir, "init.sh")
	_ = os.WriteFile(init, []byte(s), 0o600)
	out := runInteractive(t, []string{"/bin/bash", "--norc", "--noprofile", "-i"}, dir, filepath.Dir(exe),
		"PROMPT_COMMAND='echo status=$?'\n. '"+init+"'\nfalse\nexit 0\n")
	if !strings.Contains(out, "status=1") {
		t.Errorf("exit status lost:\n%s", out)
	}
	if strings.Count(s, "_precinto_prompt_command;") != 1 {
		t.Errorf("idempotency guard missing")
	}
}

// TestTestdataHygiene keeps the golden scripts synthetic (S13).
func TestTestdataHygiene(t *testing.T) {
	testkit.Hygiene(t, "testdata")
}
