package shellinit_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/shellinit"
	"github.com/precinto/precinto/internal/ui"
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
// with a GUI (never on linux or over SSH); a caller's HOME shortens the
// folder (CC-31, CC-40).
func TestOnEnterPromptFactorAndHome(t *testing.T) {
	l, err := paths.LayoutAt("/custom/base", "/tmp/pt-run")
	if err != nil {
		t.Fatal(err)
	}
	st := func(ctx context.Context) (ipc.StatusResp, error) {
		return ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "locked", Since: lockedSince, Factors: []string{"se", "passphrase"}}}}, nil
	}
	defer shellinit.SetStatus(st, false)()
	for gui, factor := range map[bool]string{true: "Mac password", false: "precinto passphrase"} {
		got, err := shellinit.OnEnter(t.Context(), enterConfig(config.OnEnterPrompt), l, shellinit.EnterRequest{PWD: acme, PrevPWD: "/u", Home: "/u", GUI: gui})
		if err != nil {
			t.Fatal(err)
		}
		want := ui.Format(ui.MsgEnterPrompt, ui.Vars{Folder: "~/work/acme", Factor: factor})
		if got.Message != want || got.Folder != "~/work/acme" || got.Path != acme {
			t.Errorf("gui=%v: %+v, want message %q", gui, got, want)
		}
	}
}
