//go:build testing

package hooks_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/internal/ui"
)

// codexHome prepares a synthetic CODEX_HOME (never ~/.codex) with
// precinto's Codex plugin installed from this checkout's marketplace
// (.agents/plugins/marketplace.json → ./plugins/codex), through Codex's own
// plugin CLI.
func codexHome(t *testing.T, s *sandbox) (home string, env []string) {
	t.Helper()
	if os.Getenv("OPENAI_API_KEY") == "" {
		t.Skip("Codex needs OPENAI_API_KEY in the environment to start in a synthetic CODEX_HOME")
	}
	home = filepath.Join(s.home, "codex-home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte("[features]\nhooks = true\nplugins = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repo, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	env = []string{"CODEX_HOME=" + home}
	codex := filepath.Join(s.fakeBin, "codex")
	if out, code := s.run(s.home, 2*time.Minute, env, codex, "plugin", "marketplace", "add", repo); code != 0 {
		t.Fatalf("codex plugin marketplace add: %d\n%s", code, out)
	}
	if out, code := s.run(s.home, 2*time.Minute, env, codex, "plugin", "add", "precinto@precinto"); code != 0 {
		t.Fatalf("codex plugin add precinto@precinto: %d\n%s", code, out)
	}
	return home, env
}

// e2eShells are the login shells Codex may run hooks under ($SHELL -lc).
func e2eShells() []string {
	var out []string
	for _, sh := range []string{"/bin/sh", "/bin/bash", "/bin/zsh", "/opt/homebrew/bin/fish", "/usr/local/bin/fish", "/usr/bin/fish"} {
		if st, err := os.Stat(sh); err == nil && st.Mode().IsRegular() {
			out = append(out, sh)
		}
	}
	return out
}

// TestE2E9CodexHooksFile (E2E-9, D61): real Codex 0.154 loads
// plugins/codex/hooks/codex.json from the installed plugin and, under every
// login shell (sh, bash, zsh and fish), the UserPromptSubmit gate blocks a
// prompt in a protected folder (no daemon runs, so precinto fails closed).
// A variant with "onFailure" on a handler records whether 0.154 accepts the
// key; it never fails the test. plugins/codex/ is frozen only after this
// passes.
func TestE2E9CodexHooksFile(t *testing.T) {
	s := newSandbox(t, "codex")
	_, env := codexHome(t, s)
	codex := filepath.Join(s.fakeBin, "codex")
	agentDown := ui.Format(ui.MsgAgentDown, ui.Vars{Folder: "~/work/acme"})
	var fish bool
	for _, sh := range e2eShells() {
		fish = fish || strings.HasSuffix(sh, "/fish")
		m := testkit.Marker(t)
		out, _ := s.run(s.root, 5*time.Minute, append(env, "SHELL="+sh), codex, "exec", "--ephemeral", "--skip-git-repo-check",
			"--dangerously-bypass-hook-trust", m+" Reply with the single word PINEAPPLE.")
		if !strings.Contains(out, agentDown) || strings.Contains(out, "PINEAPPLE") {
			t.Errorf("SHELL=%s: the UserPromptSubmit block did not fire:\n%s", sh, out)
		}
		s.leakCheck(m)
	}
	if !fish {
		t.Error("fish is not installed: E2E-9 must run under fish too before plugins/codex is frozen")
	}

	// Variant: an onFailure key on the UserPromptSubmit handler of the
	// installed copy (never of the shipped file).
	installed, err := filepath.Glob(filepath.Join(s.home, "codex-home", "plugins", "cache", "*", "precinto", "*", "hooks", "codex.json"))
	if err != nil || len(installed) != 1 {
		t.Logf("installed hooks file not found (%v): onFailure variant skipped", installed)
		return
	}
	b, err := os.ReadFile(installed[0])
	if err != nil {
		t.Fatal(err)
	}
	variant := strings.Replace(string(b), `codex UserPromptSubmit", "timeout": 90 }`, `codex UserPromptSubmit", "timeout": 90, "onFailure": "block" }`, 1)
	if err := os.WriteFile(installed[0], []byte(variant), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := s.run(s.root, 5*time.Minute, append(env, "SHELL=/bin/sh"), codex, "exec", "--ephemeral", "--skip-git-repo-check",
		"--dangerously-bypass-hook-trust", "Reply with the single word PINEAPPLE.")
	t.Logf("onFailure on a Codex 0.154 handler: hooks still fire = %v (D61 records this; re-add onFailure only if true)", strings.Contains(out, agentDown))
}
