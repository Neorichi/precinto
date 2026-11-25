package shellinit_test

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/shellinit"
	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/internal/ui"
)

const (
	acme = "/u/work/acme"
	beta = "/u/work/acme/beta" // nested root
)

func enterConfig(onEnter string) config.Config {
	c := config.Default()
	c.Policy.OnEnter = onEnter
	c.Roots = []config.Root{
		{ID: "root-acme", Path: acme, MD: config.MDLedger},
		{ID: "root-beta", Path: beta, MD: config.MDLedger, OnEnter: config.OnEnterNotify},
		{ID: "root-off", Path: "/u/work/quiet", MD: config.MDLedger, OnEnter: config.OnEnterOff},
	}
	return c
}

// defaultLayout is the darwin default base under HOME=/u, so folders are
// shown ~-shortened.
func defaultLayout(t *testing.T) paths.Layout {
	t.Helper()
	l, err := paths.LayoutAt("/u/Library/Application Support/precinto", "/tmp/pt-run")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

var lockedSince = time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)

func status(states map[string]string) shellinit.StatusFunc {
	return func(ctx context.Context) (ipc.StatusResp, error) {
		var st ipc.StatusResp
		for id, s := range states {
			st.Vaults = append(st.Vaults, ipc.VaultStatus{VaultID: id, State: s, Since: lockedSince})
		}
		return st, nil
	}
}

func TestOnEnterTransitions(t *testing.T) {
	l := defaultLayout(t)
	epoch := uint64(lockedSince.Unix())
	// No factor list from the daemon: the plain prompt (CC-40).
	prompt := ui.Format(ui.MsgEnterPromptPlain, ui.Vars{Folder: "~/work/acme"})
	cases := []struct {
		name   string
		req    shellinit.EnterRequest
		states map[string]string
		want   shellinit.EnterResult
	}{
		{"outside every folder", shellinit.EnterRequest{PWD: "/u/play", PrevPWD: acme}, map[string]string{"root-acme": "locked"}, shellinit.EnterResult{}},
		{"outside to inside", shellinit.EnterRequest{PWD: acme + "/src", PrevPWD: "/u/play"}, map[string]string{"root-acme": "locked"},
			shellinit.EnterResult{Action: shellinit.EnterPrompt, RootID: "root-acme", Path: acme, Folder: "~/work/acme", Epoch: epoch, Message: prompt}},
		{"first prompt of a shell started inside", shellinit.EnterRequest{PWD: acme, PrevPWD: acme, FirstRun: true}, map[string]string{"root-acme": "locked"},
			shellinit.EnterResult{Action: shellinit.EnterPrompt, RootID: "root-acme", Path: acme, Folder: "~/work/acme", Epoch: epoch, Message: prompt}},
		{"moving inside the folder", shellinit.EnterRequest{PWD: acme + "/src", PrevPWD: acme}, map[string]string{"root-acme": "locked"}, shellinit.EnterResult{}},
		{"a sibling sharing the prefix is outside", shellinit.EnterRequest{PWD: acme + "/src", PrevPWD: "/u/work/acme-old"}, map[string]string{"root-acme": "locked"},
			shellinit.EnterResult{Action: shellinit.EnterPrompt, RootID: "root-acme", Path: acme, Folder: "~/work/acme", Epoch: epoch, Message: prompt}},
		{"unlocked", shellinit.EnterRequest{PWD: acme, PrevPWD: "/u"}, map[string]string{"root-acme": "unlocked"}, shellinit.EnterResult{}},
		{"skip remembered for this lock epoch", shellinit.EnterRequest{PWD: acme, PrevPWD: "/u", SkipKey: "root-acme:" + strconv.FormatUint(epoch, 10)}, map[string]string{"root-acme": "locked"},
			shellinit.EnterResult{RootID: "root-acme", Path: acme, Folder: "~/work/acme", Epoch: epoch}},
		{"skip of an older epoch asks again", shellinit.EnterRequest{PWD: acme, PrevPWD: "/u", SkipKey: "root-acme:1"}, map[string]string{"root-acme": "locked"},
			shellinit.EnterResult{Action: shellinit.EnterPrompt, RootID: "root-acme", Path: acme, Folder: "~/work/acme", Epoch: epoch, Message: prompt}},
		{"another terminal is unlocking", shellinit.EnterRequest{PWD: acme, PrevPWD: "/u"}, map[string]string{"root-acme": "unlocking"},
			shellinit.EnterResult{Action: shellinit.EnterBusy, RootID: "root-acme", Path: acme, Folder: "~/work/acme", Epoch: epoch, Message: ui.Format(ui.MsgEnterElsewhere, ui.Vars{Folder: "~/work/acme"})}},
		{"deepest folder, its own notify mode", shellinit.EnterRequest{PWD: beta + "/x", PrevPWD: acme}, map[string]string{"root-acme": "locked", "root-beta": "locked"},
			shellinit.EnterResult{Action: shellinit.EnterNotify, RootID: "root-beta", Path: beta, Folder: "~/work/acme/beta", Epoch: epoch, Message: ui.Format(ui.MsgEnterNotify, ui.Vars{Folder: "~/work/acme/beta"})}},
		{"on_enter off", shellinit.EnterRequest{PWD: "/u/work/quiet", PrevPWD: "/u"}, map[string]string{"root-off": "locked"}, shellinit.EnterResult{}},
		{"vault unknown to a running daemon: locked", shellinit.EnterRequest{PWD: acme, PrevPWD: "/u"}, map[string]string{},
			shellinit.EnterResult{Action: shellinit.EnterPrompt, RootID: "root-acme", Path: acme, Folder: "~/work/acme", Message: prompt}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer shellinit.SetStatus(status(c.states), false)()
			got, err := shellinit.OnEnter(t.Context(), enterConfig(config.OnEnterPrompt), l, c.req)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("OnEnter = %+v\nwant %+v", got, c.want)
			}
		})
	}
}

// TestOnEnterDaemonDown: no daemon (or a failing one) means locked, with
// epoch 0; OnEnter never waits longer than the gate budget.
func TestOnEnterDaemonDown(t *testing.T) {
	l := defaultLayout(t)
	req := shellinit.EnterRequest{PWD: acme, PrevPWD: "/u"}
	for name, restore := range map[string]func() func(){
		"unreachable": func() func() { return shellinit.SetStatus(nil, false) },
		"dial panics": func() func() { return shellinit.SetStatus(nil, true) },
		"status fails": func() func() {
			return shellinit.SetStatus(func(context.Context) (ipc.StatusResp, error) { return ipc.StatusResp{}, errors.New("x") }, false)
		},
		"status hangs": func() func() {
			return shellinit.SetStatus(func(ctx context.Context) (ipc.StatusResp, error) {
				<-ctx.Done()
				return ipc.StatusResp{}, ctx.Err()
			}, false)
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer restore()()
			start := time.Now()
			got, err := shellinit.OnEnter(t.Context(), enterConfig(config.OnEnterPrompt), l, req)
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > time.Second {
				t.Errorf("took %v", time.Since(start))
			}
			if got.Action != shellinit.EnterPrompt || got.Epoch != 0 || got.RootID != "root-acme" {
				t.Errorf("got %+v", got)
			}
		})
	}
}

func TestOnEnterRejectsRelativePWD(t *testing.T) {
	defer shellinit.SetStatus(nil, false)()
	if _, err := shellinit.OnEnter(t.Context(), enterConfig(config.OnEnterPrompt), defaultLayout(t), shellinit.EnterRequest{PWD: "work/acme"}); err == nil {
		t.Error("relative PWD accepted")
	}
}

// TestOnEnterFolderDisplay: a non-default base shows full paths.
func TestOnEnterFolderDisplay(t *testing.T) {
	defer shellinit.SetStatus(nil, false)()
	l, err := paths.LayoutAt("/srv/precinto-base", "/tmp/pt-run")
	if err != nil {
		t.Fatal(err)
	}
	got, err := shellinit.OnEnter(t.Context(), enterConfig(config.OnEnterNotify), l, shellinit.EnterRequest{PWD: acme, PrevPWD: "/u"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Folder != acme || !strings.Contains(got.Message, acme) {
		t.Errorf("got %+v", got)
	}
	// Policy notify applies to folders without their own on_enter.
	if got.Action != shellinit.EnterNotify {
		t.Errorf("action %q", got.Action)
	}
}

func TestResultLines(t *testing.T) {
	if got := (shellinit.EnterResult{RootID: "root-acme"}).Lines(); got != "" {
		t.Errorf("nothing to do printed %q", got)
	}
	got := shellinit.EnterResult{Action: shellinit.EnterPrompt, RootID: "root-acme", Path: "/u/a\nb", Folder: "~/a\nb", Epoch: 7, Message: "m\x1b[2J\tx"}.Lines()
	want := "action=prompt\nroot=root-acme\nepoch=7\npath=/u/a b\nfolder=~/a b\nmessage=m[2J x\n"
	if got != want {
		t.Errorf("Lines = %q, want %q", got, want)
	}
	// A hostile folder name stays one value of one line: quotes, $(…),
	// backticks and spaces are data for the scripts, never code (D69).
	hostile := `/u/it's "$(touch /tmp/x)" ` + "`id`" + ` dir`
	got = shellinit.EnterResult{Action: shellinit.EnterNotify, RootID: "root-x", Path: hostile + "\nmessage=forged", Folder: hostile, Message: "m"}.Lines()
	want = "action=notify\nroot=root-x\nepoch=0\npath=" + hostile + " message=forged\nfolder=" + hostile + "\nmessage=m\n"
	if got != want || strings.Count(got, "\n") != 6 {
		t.Errorf("hostile Lines = %q, want %q", got, want)
	}
}

// C1.prompt names the folder's first usable factor; the Mac password only
// with a GUI (never on linux or over SSH, where no dialog can appear);
// C1.prompt.plain when no reported factor is usable; a caller's HOME
// shortens the folder (CC-31, CC-40).
func TestOnEnterPromptFactorAndHome(t *testing.T) {
	l, err := paths.LayoutAt("/custom/base", "/tmp/pt-run")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		factors []string
		gui     bool
		factor  string // "" = the plain prompt
	}{
		{[]string{"se", "passphrase"}, true, "Mac password"},
		{[]string{"se", "passphrase"}, false, "precinto passphrase"},
		{[]string{"se"}, false, ""},
		{[]string{"se"}, true, "Mac password"},
		{[]string{"passphrase", "se"}, true, "precinto passphrase"},
		{[]string{"plugin", "passphrase"}, false, "security key"},
		{[]string{"recovery"}, true, ""},
		{nil, true, ""},
	} {
		st := func(ctx context.Context) (ipc.StatusResp, error) {
			return ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "locked", Since: lockedSince, Factors: c.factors}}}, nil
		}
		restore := shellinit.SetStatus(st, false)
		got, err := shellinit.OnEnter(t.Context(), enterConfig(config.OnEnterPrompt), l, shellinit.EnterRequest{PWD: acme, PrevPWD: "/u", Home: "/u", GUI: c.gui})
		restore()
		if err != nil {
			t.Fatal(err)
		}
		want := ui.Format(ui.MsgEnterPromptPlain, ui.Vars{Folder: "~/work/acme"})
		if c.factor != "" {
			want = ui.Format(ui.MsgEnterPrompt, ui.Vars{Folder: "~/work/acme", Factor: c.factor})
		}
		if got.Action != shellinit.EnterPrompt || got.Message != want || got.Folder != "~/work/acme" || got.Path != acme {
			t.Errorf("factors %v, gui=%v: %+v, want message %q", c.factors, c.gui, got, want)
		}
		if !c.gui && strings.Contains(got.Message, "Mac password") {
			t.Errorf("factors %v without a GUI names the Mac password: %q", c.factors, got.Message)
		}
	}
	// A HOME given by the caller wins over the one recovered from the base;
	// a relative one is ignored.
	defer shellinit.SetStatus(status(map[string]string{"root-acme": "locked"}), false)()
	for home, want := range map[string]string{"/u/work": "~/acme", "relative": acme, "": acme} {
		got, err := shellinit.OnEnter(t.Context(), enterConfig(config.OnEnterNotify), l, shellinit.EnterRequest{PWD: acme, PrevPWD: "/u", Home: home})
		if err != nil {
			t.Fatal(err)
		}
		if got.Folder != want || got.Path != acme {
			t.Errorf("Home %q: folder %q path %q, want %q and %q", home, got.Folder, got.Path, want, acme)
		}
	}
}

// TestLinesGolden pins the shell-hook output format (D69, CC-31) for
// folder names made of shell syntax and terminal controls: one key=value
// line per field, in a fixed order, every value on its line with C0/C1
// controls stripped and newlines and tabs turned into spaces, nothing at
// all when there is nothing to do. The scripts read these lines as data.
func TestLinesGolden(t *testing.T) {
	hostile := `/u/work/it's "$(touch pwned)" ` + "`id`" + ` $HOME;rm -rf ~|cat&*?[x]{a,b} \t `
	cases := []struct {
		name string
		r    shellinit.EnterResult
	}{
		{"prompt, a folder made of shell syntax", shellinit.EnterResult{Action: shellinit.EnterPrompt, RootID: "root-acme", Path: hostile,
			Folder: "~" + strings.TrimPrefix(hostile, "/u"), Epoch: uint64(lockedSince.Unix()),
			Message: ui.Format(ui.MsgEnterPromptPlain, ui.Vars{Folder: "~" + strings.TrimPrefix(hostile, "/u")})}},
		{"notify, controls and a forged line in every value", shellinit.EnterResult{Action: shellinit.EnterNotify, RootID: "root-x\nmessage=forged",
			Path: "/u/a\nb\tc\x1b]0;title\x07\u009b2J", Folder: "~/a\nb", Epoch: 1, Message: "m\r\nmessage=forged\x00"}},
		{"busy", shellinit.EnterResult{Action: shellinit.EnterBusy, RootID: "root-acme", Path: acme, Folder: "~/work/acme", Epoch: 2,
			Message: ui.Format(ui.MsgEnterElsewhere, ui.Vars{Folder: "~/work/acme"})}},
		{"nothing to do", shellinit.EnterResult{RootID: "root-acme", Path: hostile, Folder: "~/x", Epoch: 3}},
	}
	var b strings.Builder
	for _, c := range cases {
		lines := c.r.Lines()
		b.WriteString("--- " + c.name + "\n" + lines)
		if c.r.Action == shellinit.EnterNothing {
			if lines != "" {
				t.Errorf("%s: printed %q", c.name, lines)
			}
			continue
		}
		got := strings.Split(strings.TrimSuffix(lines, "\n"), "\n")
		keys := []string{"action=", "root=", "epoch=", "path=", "folder=", "message="}
		if len(got) != len(keys) {
			t.Fatalf("%s: %d lines, want %d: %q", c.name, len(got), len(keys), lines)
		}
		for i, k := range keys {
			if !strings.HasPrefix(got[i], k) {
				t.Errorf("%s: line %d is %q, want the %s line", c.name, i+1, got[i], k)
			}
			if strings.ContainsFunc(got[i], func(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) }) {
				t.Errorf("%s: line %d keeps a control character: %q", c.name, i+1, got[i])
			}
		}
	}
	testkit.Golden(t, "shell-hook.lines", []byte(b.String()))
}

// TestScriptsParseWithoutEval: the snippets read the shell-hook lines as
// data (D69): no eval anywhere, the path line is kept in dir (zsh's path is
// PATH) and only Enter runs `command <precinto> unlock --root "$dir"`.
func TestScriptsParseWithoutEval(t *testing.T) {
	for _, sh := range []string{shellinit.Zsh, shellinit.Bash, shellinit.Fish} {
		s, err := shellinit.Script(shellinit.Options{Shell: sh, Harnesses: []string{"claude", "codex"}, Exe: goldenExe})
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(s, "\n") {
			if regexp.MustCompile(`\beval\b`).MatchString(line) {
				t.Errorf("%s line %d evaluates text: %s", sh, i+1, line)
			}
		}
		unlock := "command '" + goldenExe + `' unlock --root "$dir"`
		if strings.Count(s, unlock) != 1 || strings.Count(s, goldenExe+"' unlock") != 1 {
			t.Errorf("%s: want exactly one %q", sh, unlock)
		}
		parse := map[string]string{
			shellinit.Zsh:  `path=*) dir=${line#path=} ;;`,
			shellinit.Bash: `path=*) dir=${line#path=} ;;`,
			shellinit.Fish: `set dir (string replace -- 'path=' '' $line)`,
		}[sh]
		if !strings.Contains(s, parse) {
			t.Errorf("%s does not read the path line with %q", sh, parse)
		}
		if skip := map[string]string{
			shellinit.Zsh:  `typeset -g _PRECINTO_SKIP="$root:$epoch"`,
			shellinit.Bash: `_PRECINTO_SKIP="$root:$epoch"`,
			shellinit.Fish: `set -g _PRECINTO_SKIP "$root:$epoch"`,
		}[sh]; !strings.Contains(s, skip) {
			t.Errorf("%s does not remember the skip key itself (%q)", sh, skip)
		}
	}
}
