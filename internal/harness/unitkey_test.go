package harness_test

import (
	"errors"
	"testing"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
)

func TestUnitKeyForMatchesSpecParts(t *testing.T) {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	got, err := harness.UnitKeyFor(salt, capsule.KindClaudeSession, harness.ClaudeCode, "0123456789abcdef", "root-acme", "11111111-2222-3333-4444-555555555555")
	if err != nil || got != "7c86bcb2589f2f6c00c44229522bb4e1" {
		t.Fatalf("claude-session key = %s, %v", got, err)
	}
	got, err = harness.UnitKeyFor(salt, capsule.KindMarkdown, "", "", "root-acme", "docs/notes.md")
	if err != nil || got != "b6e3dd30b5ea0f974ea7ecbfef058df8" {
		t.Fatalf("md key = %s, %v", got, err)
	}
	got, err = harness.UnitKeyFor(salt, capsule.KindCodexHome, harness.Codex, "", "root-acme", "")
	if err != nil || got != "0db03e41aa3423814ce99acb29c124a8" {
		t.Fatalf("codex-home key = %s, %v", got, err)
	}
}

func TestUnitKeyForRejects(t *testing.T) {
	salt := []byte("salt")
	for name, call := range map[string]func() (string, error){
		"missing sid": func() (string, error) {
			return harness.UnitKeyFor(salt, capsule.KindClaudeSession, harness.ClaudeCode, "h", "", "")
		},
		"wrong harness": func() (string, error) {
			return harness.UnitKeyFor(salt, capsule.KindCodexHome, harness.ClaudeCode, "", "r", "")
		},
		"history unit id": func() (string, error) {
			return harness.UnitKeyFor(salt, capsule.KindClaudeHistory, harness.ClaudeCode, "h", "r", "other")
		},
		"separator in home": func() (string, error) {
			return harness.UnitKeyFor(salt, capsule.KindClaudePlan, harness.ClaudeCode, "h\x1fx", "", "slug")
		},
		"unknown kind": func() (string, error) {
			return harness.UnitKeyFor(salt, capsule.Kind("nope"), harness.ClaudeCode, "h", "r", "u")
		},
	} {
		if _, err := call(); !errors.Is(err, harness.ErrUnitKey) {
			t.Errorf("%s: err = %v, want ErrUnitKey", name, err)
		}
	}
}
