//go:build testing

package hooks_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/ui"
)

// TestAnswererRepliesToCatalogPrompts runs without PRECINTO_E2E: a fake CLI
// on a pseudo-terminal prints, one at a time, the prompts init, protect
// and unlock show (rendered from the catalog, as the real commands do)
// and records each line it reads. The answerer must recognise every one by
// its catalog text and type the right reply: the passphrase, yes to the
// Codex consent, never yes to the LaunchAgent offer, and the policy
// confirmation as its options say (CC-38, FX-G5-06).
func TestAnswererRepliesToCatalogPrompts(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "fake-cli")
	script := "#!/bin/sh\nout=$1; shift\nfor p in \"$@\"; do\n  printf '%s ' \"$p\"\n  IFS= read -r a || exit 3\n  printf '%s\\n' \"$a\" >>\"$out\"\ndone\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	folder := "~/work/acme"
	prompts := []string{
		ui.Format(ui.MsgPassphraseNew, ui.Vars{}),
		ui.Format(ui.MsgPassphraseAgain, ui.Vars{}),
		ui.Format(ui.MsgServiceOffer, ui.Vars{}),
		ui.Format(ui.MsgCodexConsent, ui.Vars{Folder: folder}),
		ui.Format(ui.MsgUnlockPassphrase, ui.Vars{Folder: folder}),
		"precinto: " + folder + ": precinto passphrase", // the daemon's relay of the factor's own prompt
		ui.Format(ui.MsgPolicyPending, ui.Vars{N: 1}) + "\n  policy.unlock_on_prompt: false -> true\nConfirm these changes? [y/N]",
	}
	for _, accept := range []bool{false, true} {
		out := filepath.Join(dir, "answers.txt")
		_ = os.Remove(out)
		s := &sandbox{t: t, home: dir, env: []string{"HOME=" + dir, "PATH=/usr/bin:/bin", "TERM=dumb"}}
		s.answer(answerOptions{acceptPolicy: accept}, dir, 30*time.Second, append([]string{fake, out}, prompts...)...)
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		policy := "n"
		if accept {
			policy = "y"
		}
		want := strings.Join([]string{e2ePassphrase, e2ePassphrase, "n", "y", e2ePassphrase, e2ePassphrase, policy}, "\n") + "\n"
		if string(b) != want {
			t.Errorf("acceptPolicy=%v: the fake CLI read\n%q\nwant\n%q", accept, b, want)
		}
	}
}
