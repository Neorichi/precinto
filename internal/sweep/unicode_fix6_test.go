package sweep

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/testkit"
)

// Two spellings of one folder name: NFD (as Finder stores it, getcwd's
// answer) and NFC (as Claude Code reports paths).
const (
	nameNFD = "Diseño"
	nameNFC = "Diseño"
)

// twoSpellings makes the folder and returns its path in both spellings, or
// skips where the file system tells them apart (only APFS-like volumes
// make them one folder).
func twoSpellings(t *testing.T, te *testEnv) (nfd, nfc string) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("one folder in two Unicode normalizations needs a normalization-insensitive file system (APFS)")
	}
	nfd = filepath.Join(te.h.HomeDir, "work", nameNFD)
	nfc = filepath.Join(te.h.HomeDir, "work", nameNFC)
	mustNoErr(t, os.MkdirAll(nfd, 0o700))
	a, err := os.Stat(nfc)
	if err != nil {
		t.Skipf("file system is normalization-sensitive: %v", err)
	}
	if b, _ := os.Stat(nfd); !os.SameFile(a, b) {
		t.Skip("NFC and NFD name different directories here")
	}
	return nfd, nfc
}

func (te *testEnv) protectAt(p string) {
	for i := range te.e.Cfg.Roots {
		if te.e.Cfg.Roots[i].ID == rootID {
			te.e.Cfg.Roots[i].Path = p
		}
	}
	te.e.Harness.Cfg = te.e.Cfg
}

// D136 (H6-3): a note a harness reports under the other spelling of the
// protected folder (Claude's NFC in a folder protected as NFD, Codex's
// getcwd NFD in one protected as NFC) is a note of the folder: a candidate
// at its path under the folder's own spelling, sealed, its marker written.
func TestD136NoteUnderTheOtherSpellingIsSealed(t *testing.T) {
	for _, protected := range []string{"nfd", "nfc"} {
		t.Run(protected, func(t *testing.T) {
			te := newTestEnv(t)
			nfd, nfc := twoSpellings(t, te)
			root, reported := nfd, nfc
			if protected == "nfc" {
				root, reported = nfc, nfd
			}
			te.protectAt(root)
			p := filepath.Join(reported, "docs", "notes.md")
			writeAt(t, p, []byte("# notes\n"+testkit.Marker(t)+"\n"))
			old := testkit.Epoch.Add(-time.Hour)
			mustNoErr(t, os.Chtimes(p, old, old))
			te.ledger.sessions["claude-code"] = append(te.ledger.sessions["claude-code"],
				ledger.Session{Harness: "claude-code", SID: sid1, RootIDs: []string{rootID}, Markdown: []string{p}, Ended: true})
			cands := te.run().noteCandidates(tctx(t), te.root())
			if len(cands) != 1 || cands["docs/notes.md"] == nil {
				t.Fatalf("candidates %v, want docs/notes.md under the folder's own spelling", cands)
			}
			rep := te.sealNotes()
			if res := outcome(t, rep, te.noteKey("docs/notes.md")); res.Outcome != OutSealed {
				t.Fatalf("note %+v", res)
			}
			if exists(filepath.Join(root, "docs", "notes.md")) || !exists(filepath.Join(root, "docs", "notes.md.precinto")) {
				t.Fatal("the note stayed plaintext, or no marker was written")
			}
		})
	}
}

// A Claude session busy in the folder holds back its notes (D17) whichever
// spelling its registry cwd uses.
func TestD136BusySessionInTheOtherSpellingIsBusy(t *testing.T) {
	te := newTestEnv(t)
	nfd, nfc := twoSpellings(t, te)
	for _, tc := range []struct{ cwd, root string }{{nfc, nfd}, {nfd, nfc}} {
		reg := filepath.Join(te.h.ClaudeConfig, "sessions", "4242.json")
		writeAt(t, reg, []byte(`{"pid":4242,"sessionId":"`+sid1+`","cwd":"`+tc.cwd+`","startedAt":1,"kind":"interactive","entrypoint":"cli","status":"busy"}`))
		busy, err := registryBusy{}.RootBusy(tctx(t), te.e, tc.root)
		mustNoErr(t, err)
		if !busy {
			t.Errorf("a session busy at %q is not busy for the folder protected as %q", tc.cwd, tc.root)
		}
	}
}
