//go:build crossgroup

package sweep_test

// SEC-2 with real crypto and the real adapters' Targets, for every kind
// (FX-G4-11): a logged capsule whose manifest names the unit id of another
// unit, disagrees with its log entry on kind, roots or vault, or carries a
// target outside the kind's table is refused (exit 5) with zero writes.
// Each forged capsule is first checked to restore when it is not
// tampered with, so every refusal is the tampering's.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/harness/codex"
	"github.com/Neorichi/precinto/internal/harness/codex/codextest"
	"github.com/Neorichi/precinto/internal/sweep"
	"github.com/Neorichi/precinto/internal/sweep/capslog"
	"github.com/Neorichi/precinto/internal/testkit"
)

// forged is one capsule written with the real capsule.Seal to the vault of
// its log entry, logged under its unit key.
type forged struct {
	store   string            // capsules/<store>/<unit>
	unit    string            // unit key
	rel     string            // capsule name relative to the unit directory ("" = g<gen>.pcap)
	man     capsule.Manifest  // as tampered with
	files   map[string]string // "<base>:<rel>" → content
	members []capsule.Entry   // member-less entries (snapshot manifests)
	log     capslog.Entry     // Kind, Harness, VaultID, RootIDs, Lineage, Blob, Snapshot; Unit when not unit (blobs)
}

func (s *stack) forge(t *testing.T, f forged) {
	t.Helper()
	ctx := testCtx(t)
	src := filepath.Join(s.h.Dir, "forge", f.unit, strconv.FormatUint(f.man.Gen, 10)+f.rel)
	dirs := map[string]*fsx.Dir{}
	var inputs []capsule.Input
	for k, body := range f.files {
		b, rel, _ := strings.Cut(k, ":")
		p := filepath.Join(src, b, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		d := dirs[b]
		if d == nil {
			var err error
			if d, err = fsx.OpenBase(filepath.Join(src, b)); err != nil {
				t.Fatal(err)
			}
			dirs[b] = d
			defer d.Close()
		}
		st, err := d.Lstat(rel)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, capsule.Input{Base: capsule.BaseID(b), Dir: d, Rel: rel, Snap: st})
	}
	recips, fpr, err := s.fx.Store.Recipients(f.log.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	name := capsule.GenName(f.man.Gen)
	rel := name
	if f.rel != "" {
		rel, name = f.rel, filepath.Base(f.rel)
	}
	outDir := filepath.Join(s.h.Layout.CapsulesDir, f.store, f.unit, filepath.Dir(filepath.FromSlash(rel)))
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := fsx.OpenBase(outDir)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	_ = os.Remove(filepath.Join(outDir, name)) // a blob replaced in place
	man := f.man
	man.RecipientsFpr = fpr
	sealed, err := capsule.Seal(ctx, capsule.SealRequest{Manifest: man, Recipients: recips, Out: out, Name: name,
		Inputs: inputs, Dirs: f.members})
	if err != nil {
		t.Fatal(err)
	}
	en := f.log
	en.Path = f.store + "/" + f.unit + "/" + rel
	if en.Unit == "" {
		en.Unit = f.unit
	}
	en.SHA256, en.HeaderSHA256, en.Size = sealed.SHA256, sealed.HeaderSHA256, sealed.Size
	if en.Gen == 0 {
		en.Gen = f.man.Gen
	}
	en.SealedAt, en.RecipientsFpr, en.Files = testkit.Epoch, fpr, len(inputs)
	if err := s.e.Log.Append(en); err != nil {
		t.Fatal(err)
	}
}

// treeHashes maps every regular file under dir, except precinto's own
// state (base) and the forging sources, to its SHA-256.
func treeHashes(t *testing.T, s *stack) map[string]string {
	t.Helper()
	out := map[string]string{}
	skip := map[string]bool{s.h.Base: true, filepath.Join(s.h.Dir, "forge"): true}
	_ = filepath.WalkDir(s.h.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && skip[p] {
			return filepath.SkipDir
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err == nil {
			sum := sha256.Sum256(b)
			out[p] = hex.EncodeToString(sum[:])
		}
		return nil
	})
	return out
}

// refusedWithoutWrites restores ref and requires an exit-5 refusal (a
// unit-key or unsafe failure) that wrote nothing outside precinto's state.
func refusedWithoutWrites(t *testing.T, s *stack, ref harness.UnitRef, what string) {
	t.Helper()
	before := treeHashes(t, s)
	rep, err := sweep.Restore(testCtx(t), s.e, s.keys, sweep.RestoreRequest{Units: []harness.UnitRef{ref}})
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if e := rep.Err(); !errors.Is(e, harness.ErrUnitKey) && !errors.Is(e, capsule.ErrUnsafe) {
		t.Fatalf("%s: Err = %v (%+v), want an exit-5 refusal", what, e, rep.Units)
	}
	after := treeHashes(t, s)
	for p, sum := range after {
		if before[p] != sum {
			t.Fatalf("%s: written: %s", what, strings.TrimPrefix(p, s.h.Dir))
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			t.Fatalf("%s: removed: %s", what, strings.TrimPrefix(p, s.h.Dir))
		}
	}
}

// claudeHomeID is the id of the stack's registered Claude home.
func (s *stack) claudeHomeID(t *testing.T) string {
	t.Helper()
	for _, ad := range s.e.Adapters {
		if ad.ID() != harness.ClaudeCode {
			continue
		}
		homes, err := ad.Homes(testCtx(t), s.e.Harness)
		if err != nil || len(homes) == 0 {
			t.Fatalf("claude homes %v %v", homes, err)
		}
		return homes[0].ID
	}
	t.Fatal("no Claude adapter")
	return ""
}

// sec2Kind is the genuine shape of one layered kind and its tampered
// variants.
type sec2Kind struct {
	kind     capsule.Kind
	harness  harness.ID
	store    string
	unitID   string // authenticates under the key
	otherID  string // another unit's id
	homeID   bool   // the key includes the home id
	vault    string
	roots    []string
	files    map[string]string // genuine targets
	outside  string            // "<base>:<rel>" outside the kind's table
	restored []string          // paths the genuine capsule places
}

func TestCrossgroupSEC2EveryKind(t *testing.T) {
	t.Parallel()
	const sid = "00000000-0000-4000-8000-0000000000e1"
	const sidOther = "00000000-0000-4000-8000-0000000000e2"
	kinds := []func(s *stack) sec2Kind{
		func(s *stack) sec2Kind {
			rel := "projects/-forge/" + sid + ".jsonl"
			return sec2Kind{kind: capsule.KindClaudeSession, harness: harness.ClaudeCode, store: "claude-code", unitID: sid,
				otherID: sidOther, homeID: true, vault: xRoot, roots: []string{xRoot},
				files:   map[string]string{"claude_config:" + rel: "{\"uuid\":\"u1\"}\n"},
				outside: "claude_config:settings.json", restored: []string{filepath.Join(s.h.ClaudeConfig, filepath.FromSlash(rel))}}
		},
		func(s *stack) sec2Kind {
			rel := "projects/-forge/memory/MEMORY.md"
			return sec2Kind{kind: capsule.KindClaudeProject, harness: harness.ClaudeCode, store: "claude-code", unitID: "-forge",
				otherID: "-other", homeID: true, vault: xRoot, roots: []string{xRoot},
				files:   map[string]string{"claude_config:" + rel: "# memory\n"},
				outside: "claude_config:projects/-other/memory/x.md", restored: []string{filepath.Join(s.h.ClaudeConfig, filepath.FromSlash(rel))}}
		},
		func(s *stack) sec2Kind {
			return sec2Kind{kind: capsule.KindClaudePlan, harness: harness.ClaudeCode, store: "claude-code", unitID: "brave-otter",
				otherID: "sly-fox", homeID: true, vault: xRoot, roots: []string{xRoot},
				files:   map[string]string{"claude_config:plans/brave-otter.md": "# plan\n"},
				outside: "claude_config:plans/sly-fox.md", restored: []string{filepath.Join(s.h.ClaudeConfig, "plans", "brave-otter.md")}}
		},
		func(s *stack) sec2Kind {
			return sec2Kind{kind: capsule.KindClaudeHistory, harness: harness.ClaudeCode, store: "claude-code", unitID: xRoot,
				otherID: "root-other", homeID: true, vault: xRoot, roots: []string{xRoot},
				files:   map[string]string{"claude_config:history.jsonl": "{\"display\":\"x\",\"project\":\"/p\",\"timestamp\":1}\n"},
				outside: "claude_config:settings.json", restored: []string{filepath.Join(s.h.ClaudeConfig, "history.jsonl")}}
		},
		func(s *stack) sec2Kind {
			return sec2Kind{kind: capsule.KindGlobalStore, harness: harness.ClaudeCode, store: "claude-code", unitID: "usage-data",
				otherID: "feedback/drafts", homeID: true, vault: "global",
				files:   map[string]string{"claude_config:usage-data/report.json": "{}\n"},
				outside: "claude_config:settings.json", restored: []string{filepath.Join(s.h.ClaudeConfig, "usage-data", "report.json")}}
		},
		func(s *stack) sec2Kind {
			return sec2Kind{kind: capsule.KindMarkdown, harness: "md", store: "md", unitID: "docs/notes.md",
				otherID: "docs/other.md", vault: xRoot, roots: []string{xRoot},
				files:   map[string]string{"root:docs/notes.md": "# notes\n"},
				outside: "root:docs/other.md", restored: []string{filepath.Join(s.h.Root, "docs", "notes.md")}}
		},
	}
	for _, mk := range kinds {
		s := newStack(t)
		k := mk(s)
		t.Run(string(k.kind), func(t *testing.T) {
			home, root := "", ""
			if k.homeID {
				home = s.claudeHomeID(t)
			}
			if len(k.roots) > 0 {
				root = k.roots[0]
			}
			if k.kind == capsule.KindClaudeHistory {
				root = xRoot
			}
			keyID := k.unitID
			if k.kind == capsule.KindClaudeHistory {
				keyID = ""
			}
			key, err := harness.UnitKeyFor(s.e.Harness.Salt, k.kind, k.harness, home, root, keyID)
			if err != nil {
				t.Fatal(err)
			}
			ref := harness.UnitRef{Harness: k.harness, Kind: k.kind, Key: key, VaultID: k.vault, RootIDs: k.roots}
			gen := uint64(0)
			next := func(mut func(m *capsule.Manifest, files map[string]string)) {
				gen++
				files := map[string]string{}
				for p, b := range k.files {
					files[p] = b
				}
				m := capsule.Manifest{Format: capsule.FormatVersion, Kind: k.kind, Harness: string(k.harness), UnitKey: key,
					UnitID: k.unitID, VaultID: k.vault, RootIDs: append([]string(nil), k.roots...), Gen: gen,
					Lineage: capsule.LineageFresh, CreatedAt: testkit.Epoch}
				if mut != nil {
					mut(&m, files)
				}
				s.forge(t, forged{store: k.store, unit: key, man: m, files: files,
					log: capslog.Entry{Kind: string(k.kind), Harness: k.store, VaultID: k.vault, RootIDs: k.roots,
						Gen: gen, Lineage: string(capsule.LineageFresh)}})
			}
			// The untampered capsule restores (control), then goes again.
			next(nil)
			rep, err := sweep.Restore(testCtx(t), s.e, s.keys, sweep.RestoreRequest{Units: []harness.UnitRef{ref}})
			if err != nil || rep.Err() != nil || rep.Count(sweep.OutRestored)+rep.Count(sweep.OutMerged) != 1 {
				t.Fatalf("control restore %+v %v", rep.Units, err)
			}
			for _, p := range k.restored {
				if _, err := os.Lstat(p); err != nil {
					t.Fatalf("control: %s not placed", filepath.Base(p))
				}
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
			}
			_ = os.Remove(filepath.Join(s.h.Layout.ReceiptsDir, key+".json"))
			for _, tc := range []struct {
				what string
				mut  func(m *capsule.Manifest, files map[string]string)
			}{
				{"unit id of another unit", func(m *capsule.Manifest, _ map[string]string) { m.UnitID = k.otherID }},
				{"kind mismatch", func(m *capsule.Manifest, _ map[string]string) {
					m.Kind = capsule.KindClaudePlan
					if k.kind == capsule.KindClaudePlan {
						m.Kind = capsule.KindClaudeProject
					}
				}},
				{"root mismatch", func(m *capsule.Manifest, _ map[string]string) { m.RootIDs = []string{"root-other"} }},
				{"vault mismatch", func(m *capsule.Manifest, _ map[string]string) { m.VaultID = "vault-other" }},
				{"target outside the table", func(_ *capsule.Manifest, files map[string]string) { files[k.outside] = "forged\n" }},
			} {
				next(tc.mut)
				refusedWithoutWrites(t, s, ref, tc.what)
			}
		})
	}
}

// SEC-2 for codex-home and codex-blob: a snapshot generation naming another
// home's id or a never-touch target, and a blob replaced by one whose
// manifest names another blob id, are refused with zero writes.
func TestCrossgroupSEC2CodexKinds(t *testing.T) {
	t.Parallel()
	for _, tc := range []string{"home id of another root", "kind mismatch", "target outside the table", "blob id of another blob"} {
		t.Run(tc, func(t *testing.T) {
			s := newStack(t)
			ctx := testCtx(t)
			home := s.h.Layout.CodexHome(xRoot)
			if err := os.MkdirAll(filepath.Dir(home), 0o700); err != nil {
				t.Fatal(err)
			}
			codextest.New(t, home, codextest.Options{Rollouts: 1})
			units, err := codex.New().Scan(ctx, s.e.Harness, harness.Scope{RootIDs: []string{xRoot}, Kinds: []capsule.Kind{capsule.KindCodexHome}})
			if err != nil || len(units) != 1 {
				t.Fatalf("scan %v %v", units, err)
			}
			if rep, err := sweep.Seal(ctx, s.e, units, sweep.Options{Reason: "codex-exit"}); err != nil || rep.Count(sweep.OutSealed) != 1 {
				t.Fatalf("seal %+v %v", rep, err)
			}
			u := units[0]
			all, err := s.e.Log.All()
			if err != nil {
				t.Fatal(err)
			}
			var snap capslog.Entry
			var blob capslog.Entry
			for _, en := range all {
				switch {
				case en.Unit == u.Key && !en.Blob:
					snap = en
				case en.Blob && blob.Path == "":
					blob = en
				}
			}
			if snap.Path == "" || blob.Path == "" {
				t.Fatalf("log %+v", all)
			}
			ref := u.Ref()
			members := []capsule.Entry{{Base: capsule.BaseCodexHome, Rel: "sessions/forged.jsonl", Size: 1, SHA256: strings.Repeat("0", 64), Blob: blob.Unit}}
			man := capsule.Manifest{Format: capsule.FormatVersion, Kind: capsule.KindCodexHome, Harness: string(harness.Codex),
				UnitKey: u.Key, UnitID: xRoot, VaultID: xRoot, RootIDs: []string{xRoot}, Gen: snap.Gen + 1,
				Parent: snap.Gen, Lineage: capsule.LineageSuccessor, CreatedAt: testkit.Epoch}
			log := capslog.Entry{Kind: string(capsule.KindCodexHome), Harness: string(harness.Codex), VaultID: xRoot,
				RootIDs: []string{xRoot}, Parent: snap.Gen, Lineage: string(capsule.LineageSuccessor), Snapshot: true}
			switch tc {
			case "home id of another root":
				man.UnitID = "root-other"
				s.forge(t, forged{store: "codex", unit: u.Key, man: man, members: members, log: log})
			case "kind mismatch":
				man.Kind = capsule.KindCodexBlob
				s.forge(t, forged{store: "codex", unit: u.Key, man: man, members: members, log: log})
			case "target outside the table":
				members[0].Rel = "auth.json"
				s.forge(t, forged{store: "codex", unit: u.Key, man: man, members: members, log: log})
			case "blob id of another blob":
				// The blob, replaced in place and logged again, names another
				// blob id inside its ciphertext.
				bman := capsule.Manifest{Format: capsule.FormatVersion, Kind: capsule.KindCodexBlob, Harness: string(harness.Codex),
					UnitKey: blob.Unit, UnitID: "another-blob-id", VaultID: xRoot, RootIDs: []string{xRoot}, Gen: 1,
					Lineage: capsule.LineageFresh, CreatedAt: testkit.Epoch}
				store, rest, _ := strings.Cut(blob.Path, "/")
				_, rel, _ := strings.Cut(rest, "/")
				s.forge(t, forged{store: store, unit: u.Key, rel: rel, man: bman,
					files: map[string]string{"codex_home:sessions/forged.jsonl": "{}\n"},
					log: capslog.Entry{Unit: blob.Unit, Kind: string(capsule.KindCodexBlob), Harness: string(harness.Codex),
						VaultID: xRoot, RootIDs: []string{xRoot}, Gen: 1, Lineage: string(capsule.LineageFresh), Blob: true}})
			}
			refusedWithoutWrites(t, s, ref, tc)
		})
	}
}
