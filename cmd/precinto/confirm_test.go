package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/ui"
	"github.com/Neorichi/precinto/internal/vault"
)

// Without a terminal, relayed prompts are refused (vault.ErrNoUI), so the
// daemon falls back to GUI factors or pinentry (D27); messages are shown
// sanitized.
func TestHeadlessUI(t *testing.T) {
	var b bytes.Buffer
	h := headlessUI{w: &b}
	if err := h.Display("precinto: hello\x1b[2J"); err != nil || b.String() != "precinto: hello[2J\n" {
		t.Fatalf("display %q %v", b.String(), err)
	}
	if _, err := h.Secret("p"); !errors.Is(err, vault.ErrNoUI) {
		t.Fatalf("secret %v", err)
	}
	if _, err := h.Confirm("p", "y", "n"); !errors.Is(err, vault.ErrNoUI) {
		t.Fatalf("confirm %v", err)
	}
}

// A cancel on the terminal reaches the vault as vault.ErrCancelled.
func TestVaultUIMapsCancel(t *testing.T) {
	u := vaultUI{t: &fakeTTY{}, gui: true}
	if _, err := u.Secret("p"); !errors.Is(err, vault.ErrCancelled) {
		t.Fatalf("secret %v", err)
	}
	if !u.Interactive() || !u.GUI() {
		t.Fatal("capabilities")
	}
}

// recover answers every relayed secret prompt with a fresh copy of the key
// (ipc consumes the buffers it sends).
func TestSecretAnswerCopies(t *testing.T) {
	key := memguard.NewBufferFromBytes([]byte("TEST-KEY-PLACEHOLDER"))
	defer key.Destroy()
	s := secretAnswer{secret: key, next: headlessUI{w: &bytes.Buffer{}}}
	a, err := s.Secret("p")
	if err != nil {
		t.Fatal(err)
	}
	a.Destroy()
	b, err := s.Secret("p")
	if err != nil || string(b.Bytes()) != "TEST-KEY-PLACEHOLDER" {
		t.Fatalf("second answer %v", err)
	}
	b.Destroy()
	key.Destroy()
	if _, err := s.Secret("p"); !errors.Is(err, vault.ErrNoUI) {
		t.Fatalf("destroyed key: %v", err)
	}
}

func TestReadSecretBoundedAndTrimmed(t *testing.T) {
	b, err := readSecret(strings.NewReader("  TEST-KEY \n"))
	if err != nil || string(b.Bytes()) != "TEST-KEY" {
		t.Fatalf("%v", err)
	}
	b.Destroy()
	if _, err := readSecret(strings.NewReader(strings.Repeat("A", maxKeyFile+1))); err == nil {
		t.Fatal("oversized input accepted")
	}
	if _, err := readSecret(strings.NewReader(" \n")); err == nil {
		t.Fatal("empty input accepted")
	}
}

func TestTypedConfirm(t *testing.T) {
	e := newEnv(t)
	a := e.app()
	e.tty.lines = []string{" forget "}
	if err := a.typedConfirm(e.tty, "Forgetting x", wordForget); err != nil {
		t.Fatalf("exact word refused: %v", err)
	}
	want := ui.Format(ui.MsgConfirmTyped, ui.Vars{Action: "Forgetting x", Command: wordForget})
	if !strings.Contains(e.tty.allPrompts(), want) {
		t.Fatalf("prompt %q, want C12.typed %q", e.tty.allPrompts(), want)
	}
	e.tty.lines = []string{"FORGET"}
	if err := a.typedConfirm(e.tty, "x", wordForget); err == nil {
		t.Fatal("a different word confirmed")
	}
	e.tty.lineErr = ui.ErrCancelled
	if err := a.typedConfirm(e.tty, "x", wordForget); exitFor(err) != exitLocked {
		t.Fatalf("cancel: %v", err)
	}
}
