package doctor_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/testkit"
)

// sampleFindings is a fixed list covering every severity, a fix and an
// escape sequence that must never reach the output.
var sampleFindings = []doctor.Finding{
	{Code: doctor.CheckVaultTampered, Severity: doctor.Fail, Message: "WARNING: ~/work/acme's vault file was changed outside precinto", Fix: "precinto vault repair --root ~/work/acme"},
	{Code: doctor.CheckClaudeSettingsEnv, Severity: doctor.Fail, Message: "~/work/acme/.claude/settings.local.json sets PRECINTO_BIN in env\x1b[2J", Fix: `remove PRECINTO_BIN from "env" in ~/work/acme/.claude/settings.local.json`},
	{Code: doctor.CheckCodexWrongHome, Severity: doctor.Warn, Message: "2 Codex conversation(s) from ~/work/acme were saved in your own Codex history", Fix: "precinto run codex"},
	{Code: doctor.CheckClaudeRetention, Severity: doctor.Info, Message: "Claude deletes sessions older than 30 days when it starts"},
	{Code: doctor.CheckDiskEncryption, Severity: doctor.OK, Message: "FileVault is on"},
}

func TestRenderHuman(t *testing.T) {
	var b bytes.Buffer
	if err := doctor.WriteHuman(&b, sampleFindings); err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsRune(b.Bytes(), 0x1b) {
		t.Error("an escape sequence reached the human output")
	}
	testkit.Golden(t, "render.txt", b.Bytes())
}

func TestRenderJSON(t *testing.T) {
	var b bytes.Buffer
	if err := doctor.WriteJSON(&b, sampleFindings); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		V        int    `json:"v"`
		Worst    string `json:"worst"`
		Findings []struct {
			Code, Severity, Message, Fix string
		} `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.V != 1 || doc.Worst != "fail" || len(doc.Findings) != len(sampleFindings) {
		t.Errorf("document %+v", doc)
	}
	if strings.Contains(b.String(), `\u001b`) {
		t.Error("an escape sequence reached the JSON output")
	}
	testkit.Golden(t, "render.json", b.Bytes())

	b.Reset()
	if err := doctor.WriteJSON(&b, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"findings": []`) || !strings.Contains(b.String(), `"worst": "ok"`) {
		t.Errorf("empty report: %s", b.String())
	}

	// Every text of a finding is sanitized, its severity too.
	for _, asJSON := range []bool{true, false} {
		b.Reset()
		odd := []doctor.Finding{{Code: "x\x1b]0;t\x07", Severity: "odd\x1b[2J", Message: "m\x1b[31m", Fix: "f\x9b"}}
		if err := doctor.Render(&b, odd, asJSON); err != nil {
			t.Fatal(err)
		}
		if s := b.String(); strings.ContainsAny(s, "\x1b\x07") || strings.Contains(s, "\x9b") || strings.Contains(s, `\u001b`) || strings.Contains(s, `\u0007`) || strings.Contains(s, `�`) {
			t.Errorf("json=%v: a control character reached the output: %q", asJSON, s)
		}
	}
}

func TestWorst(t *testing.T) {
	if got := doctor.Worst(nil); got != doctor.OK {
		t.Errorf("Worst(nil) = %s", got)
	}
	if got := doctor.Worst(sampleFindings[2:]); got != doctor.Warn {
		t.Errorf("Worst = %s, want warn", got)
	}
}

func TestShellArgAndOneLine(t *testing.T) {
	home := "/u"
	for in, want := range map[string]string{
		"/u/work/acme":       "~/work/acme",
		"/u":                 "~",
		"/srv/data":          "/srv/data",
		"/u/my folder":       `'/u/my folder'`,
		"/u/it's":            `'/u/it'\''s'`,
		"/u/$(touch x)":      `'/u/$(touch x)'`,
		"/u/a\x1b[31mb":      `'/u/a[31mb'`,
		"/u/semi;colon":      `'/u/semi;colon'`,
		"/u/star*":           `'/u/star*'`,
		"/u/~tilde-inside/x": "~/~tilde-inside/x",
	} {
		if got := doctor.ShellArg(home, in); got != want {
			t.Errorf("ShellArg(%q) = %q, want %q", in, got, want)
		}
	}
	if got := doctor.OneLine("a\nb\tc\x1b[2Jd\x07"); got != "a b c[2Jd" {
		t.Errorf("OneLine = %q", got)
	}
}
