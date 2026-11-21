package sweep

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/testkit"
)

// sealedSession writes and seals a session, returning its unit (as
// scanned before the seal) and the original bytes of every file.
func (te *testEnv) sealedSession(sid string, mod func(*claudetest.Session)) (harness.Unit, map[string][]byte) {
	te.t.Helper()
	te.writeSession(sid, "", mod)
	u := te.scanSession(sid)
	orig := map[string][]byte{}
	for _, p := range te.sessionFiles(u) {
		orig[p] = readFile(te.t, p)
	}
	rep, err := te.run().sealCommand(context.Background(), []harness.Unit{u}, Options{})
	mustNoErr(te.t, err)
	if res := outcome(te.t, rep, u.Key); res.Outcome != OutSealed {
		te.t.Fatalf("seal %+v", res)
	}
	return u, orig
}

func refOf(u harness.Unit) harness.UnitRef {
	return harness.UnitRef{Harness: u.Harness, Kind: u.Kind, Key: u.Key, VaultID: u.VaultID, RootIDs: u.RootIDs}
}

func (te *testEnv) restoreUnits(req RestoreRequest) *Report {
	te.t.Helper()
	rep, err := te.run().restore(context.Background(), te.keys, req)
	mustNoErr(te.t, err)
	return rep
}

func transcriptOf(u harness.Unit) string {
	for _, f := range u.Files {
		if f.Last {
			return filepath.Join(u.Home.Bases[f.Base], filepath.FromSlash(f.Rel))
		}
	}
	return ""
}

// I2: exact bytes, original mtime, owner-only modes; receipt; clean state.
func TestRestoreRoundTrip(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, orig := te.sealedSession(sid1, nil)
	rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	res := outcome(t, rep, u.Key)
	if res.Outcome != OutRestored || res.Gen != 1 {
		t.Fatalf("restore %+v", res)
	}
	for _, f := range u.Files {
		p := filepath.Join(u.Home.Bases[f.Base], filepath.FromSlash(f.Rel))
		b := readFile(t, p)
		if !bytes.Equal(b, orig[p]) {
			t.Fatalf("%s: bytes differ", f.Rel)
		}
		st, _ := fsx.Lstat(p)
		if st.MtimeNS != f.Snap.MtimeNS {
			t.Errorf("%s: mtime %d, want %d", f.Rel, st.MtimeNS, f.Snap.MtimeNS)
		}
		if st.Perm() != 0o600 {
			t.Errorf("%s: mode %v", f.Rel, st.Perm())
		}
	}
	rd, ok, err := LoadReceipt(te.e, u.Key)
	if err != nil || !ok || rd.Gen != 1 || len(rd.Files) != len(u.Files) {
		t.Fatalf("receipt %+v %v %v", rd, ok, err)
	}
	if ents, _ := os.ReadDir(te.h.Layout.StagingDir); len(ents) != 0 {
		t.Fatalf("staging left: %v", ents)
	}
	if p, _ := te.e.Journal.Pending(); len(p) != 0 {
		t.Fatalf("journal %+v", p)
	}
	if !te.keys.allDestroyed() {
		t.Fatal("file keys not destroyed after the restore")
	}
	if len(te.keys.purposes) == 0 || te.keys.purposes[0] != "restore" {
		t.Fatalf("purposes %v", te.keys.purposes)
	}
}

// SEC-5: an owner-exec file comes back 0700, everything else 0600.
func TestRestoreMasksModes(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	te.writeSession(sid1, "", nil)
	u := te.scanSession(sid1)
	p := filepath.Join(u.Home.Bases[u.Files[0].Base], u.Files[0].Rel)
	mustNoErr(t, os.Chmod(p, 0o755))
	u = te.scanSession(sid1)
	te.run().sealCommand(context.Background(), []harness.Unit{u}, Options{})
	te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	if st, _ := fsx.Lstat(p); st.Perm() != 0o700 {
		t.Fatalf("mode %v, want 0700", st.Perm())
	}
}

// SEC-1 and I14: only logged capsules restore; a capsule whose header no
// longer matches its log entry is refused (exit 5) and nothing is written.
func TestRestoreRequiresProvenance(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	capsPath := filepath.Join(te.h.Layout.CapsulesDir, "claude-code", u.Key, "g000001.pcap")
	b := readFile(t, capsPath)
	// Same payload, different header: the provenance key no longer matches.
	forged := bytes.Replace(b, []byte(`"nonce":"`), []byte(`"nonce":"ff`), 1)
	mustNoErr(t, os.WriteFile(capsPath, forged, 0o600))
	before := snapshotTree(t, te.h.ClaudeConfig)
	rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	res := outcome(t, rep, u.Key)
	if res.Outcome != OutFailed || !errors.Is(rep.Err(), ErrNotLogged) {
		t.Fatalf("restore of a re-headed capsule: %+v / %v", res, rep.Err())
	}
	if after := snapshotTree(t, te.h.ClaudeConfig); len(after) != len(before) {
		t.Fatal("files written")
	}
	// A unit with no log entry at all is not restorable.
	rep = te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{{Kind: capsule.KindClaudeSession, Key: te.sessionKey(sid2)}}})
	if res := outcome(t, rep, te.sessionKey(sid2)); res.Outcome != OutSkipped {
		t.Fatalf("unlogged unit %+v", res)
	}
}

// forge writes a capsule with the fake codec directly and logs it, so a
// test controls every manifest field (SEC-2).
func (te *testEnv) forge(key string, man capsule.Manifest, files map[string][]byte, gen uint64) {
	te.t.Helper()
	root, caps, err := te.run().openCapsDir("claude-code", key, true)
	mustNoErr(te.t, err)
	defer root.Close()
	dir := filepath.Join(te.h.Dir, "forge-src")
	mustNoErr(te.t, os.MkdirAll(dir, 0o700))
	src, err := te.fs.OpenBase(dir)
	mustNoErr(te.t, err)
	var inputs []sealInput
	for rel, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		mustNoErr(te.t, os.MkdirAll(filepath.Dir(p), 0o700))
		mustNoErr(te.t, os.WriteFile(p, data, 0o600))
		st, _ := fsx.Lstat(p)
		inputs = append(inputs, sealInput{Base: capsule.BaseClaudeConfig, Dir: src, Rel: rel, Snap: st})
	}
	name := capsule.GenName(gen)
	s, err := te.codec.Seal(context.Background(), sealRequest{Manifest: man, Inputs: inputs, Recipients: recipientSet{fpr: "fpr-x"}, Out: caps, Name: name})
	mustNoErr(te.t, err)
	mustNoErr(te.t, te.e.Log.Append(capslog.Entry{Path: logPathOf("claude-code", key, name), SHA256: s.SHA256, HeaderSHA256: s.HeaderSHA256,
		Size: s.Size, Kind: string(capsule.KindClaudeSession), Harness: "claude-code", Unit: key, VaultID: rootID, RootIDs: []string{rootID},
		Gen: gen, Lineage: "fresh", SealedAt: testkit.Epoch}))
}

// SEC-2: the manifest has no authority — its unit id must hash to the
// logged key, its kind/vault/roots must match the log, and every entry
// must fall inside the targets computed from trusted context; any
// mismatch rejects the whole capsule (exit 5) with zero writes.
func TestRestoreManifestHasNoAuthority(t *testing.T) {
	t.Parallel()
	key := func(te *testEnv) string { return te.sessionKey(sid1) }
	base := func(te *testEnv) capsule.Manifest {
		return capsule.Manifest{Format: 1, Kind: capsule.KindClaudeSession, Harness: "claude-code", UnitKey: key(te), UnitID: sid1,
			VaultID: rootID, RootIDs: []string{rootID}, Gen: 1, Lineage: capsule.LineageFresh}
	}
	ok := map[string][]byte{"projects/p/" + sid1 + ".jsonl": []byte("{}\n")}
	for _, tc := range []struct {
		name  string
		man   func(te *testEnv) capsule.Manifest
		files map[string][]byte
		want  error
	}{
		{"unit id of another session", func(te *testEnv) capsule.Manifest { m := base(te); m.UnitID = sid2; return m }, ok, harness.ErrUnitKey},
		{"kind mismatch", func(te *testEnv) capsule.Manifest { m := base(te); m.Kind = capsule.KindClaudeProject; return m }, ok, harness.ErrUnitKey},
		{"root mismatch", func(te *testEnv) capsule.Manifest { m := base(te); m.RootIDs = []string{"root-other"}; return m }, ok, harness.ErrUnitKey},
		{"vault mismatch", func(te *testEnv) capsule.Manifest { m := base(te); m.VaultID = "global"; return m }, ok, harness.ErrUnitKey},
		{"other project memory", base, map[string][]byte{"projects/other/memory/MEMORY.md": []byte("x")}, capsule.ErrUnsafe},
		{"other session env", base, map[string][]byte{"session-env/" + sid2 + "/hook.sh": []byte("x")}, capsule.ErrUnsafe},
		{"settings of the root", base, map[string][]byte{".claude/settings.local.json": []byte("{}")}, capsule.ErrUnsafe},
		{"non-clean path", base, map[string][]byte{"projects/p/../" + sid1 + ".jsonl": []byte("x")}, capsule.ErrUnsafe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestEnv(t)
			te.claude.sids = []string{sid1}
			te.forge(key(te), tc.man(te), tc.files, 1)
			canary := snapshotTree(t, te.h.Dir)
			rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{{Kind: capsule.KindClaudeSession, Key: key(te)}}})
			res := outcome(t, rep, key(te))
			if res.Outcome != OutFailed || !errors.Is(rep.Err(), tc.want) {
				t.Fatalf("result %+v, Err %v, want %v", res, rep.Err(), tc.want)
			}
			after := snapshotTree(t, te.h.Dir)
			for p := range after {
				if _, was := canary[p]; !was && !strings.Contains(p, string(filepath.Separator)+"base"+string(filepath.Separator)) {
					t.Fatalf("written: %s", p)
				}
			}
		})
	}
}

// writeAt replaces a file's content.
func writeAt(t *testing.T, p string, b []byte) {
	t.Helper()
	mustNoErr(t, os.MkdirAll(filepath.Dir(p), 0o700))
	mustNoErr(t, os.WriteFile(p, b, 0o600))
}

// The placement table (D11, REST-4, REST-5, REST-6): what happens when
// plaintext already exists where the transcript restores.
func TestRestorePlacementTable(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("slow (fsync-heavy): skipped with -short")
	}
	for _, tc := range []struct {
		name     string
		noNL     bool
		existing func(te *testEnv, u harness.Unit, orig []byte) []byte // returns F
		want     func(t *testing.T, got, orig, f []byte, conflict []byte)
		outcome  Outcome
	}{
		{"equal (REST-6)", false, func(te *testEnv, u harness.Unit, orig []byte) []byte { return orig },
			func(t *testing.T, got, orig, f, c []byte) {
				if !bytes.Equal(got, orig) || c != nil {
					t.Fatal("not a no-op")
				}
			}, OutRestored},
		{"superset kept", false, func(te *testEnv, u harness.Unit, orig []byte) []byte {
			return append(append([]byte(nil), orig...), []byte(`{"uuid":"00000000-0000-4000-8000-0000000000f1"}`+"\n")...)
		}, func(t *testing.T, got, orig, f, c []byte) {
			if !bytes.Equal(got, f) || c != nil {
				t.Fatal("superset not kept")
			}
		}, OutRestored},
		{"stale prefix replaced", false, func(te *testEnv, u harness.Unit, orig []byte) []byte {
			i := bytes.IndexByte(orig, '\n')
			return append([]byte(nil), orig[:i+1]...)
		}, func(t *testing.T, got, orig, f, c []byte) {
			if !bytes.Equal(got, orig) || c != nil {
				t.Fatal("stale prefix not replaced by the capsule")
			}
		}, OutRestored},
		{"linked fragment merged (REST-4)", false, func(te *testEnv, u harness.Unit, orig []byte) []byte {
			return fragmentAfter(t, orig)
		}, func(t *testing.T, got, orig, f, c []byte) {
			if !bytes.Equal(got, append(append([]byte(nil), orig...), f...)) || c != nil {
				t.Fatalf("merge is not C+F:\n%s", got)
			}
		}, OutMerged},
		{"missing newline inserted (REST-5)", true, func(te *testEnv, u harness.Unit, orig []byte) []byte {
			return fragmentAfter(t, orig)
		}, func(t *testing.T, got, orig, f, c []byte) {
			want := append(append(append([]byte(nil), orig...), '\n'), f...)
			if !bytes.Equal(got, want) || c != nil {
				t.Fatalf("merge %q", got)
			}
			for _, l := range bytes.Split(bytes.TrimSpace(got), []byte("\n")) {
				if !bytes.HasPrefix(l, []byte("{")) || !bytes.HasSuffix(l, []byte("}")) {
					t.Fatalf("a record does not parse: %q", l)
				}
			}
		}, OutMerged},
		{"unrelated plaintext is a conflict", false, func(te *testEnv, u harness.Unit, orig []byte) []byte {
			return []byte(`{"uuid":"00000000-0000-4000-8000-0000000000e9","parentUuid":null}` + "\n")
		}, func(t *testing.T, got, orig, f, c []byte) {
			if !bytes.Equal(got, f) {
				t.Fatal("I13: existing file clobbered")
			}
			if !bytes.Equal(c, orig) {
				t.Fatal("capsule version not written as a conflict copy")
			}
		}, OutConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestEnv(t)
			u, origs := te.sealedSession(sid1, func(s *claudetest.Session) { s.NoNewline = tc.noNL })
			tr := transcriptOf(u)
			orig := origs[tr]
			f := tc.existing(te, u, orig)
			writeAt(t, tr, f)
			rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
			if res := outcome(t, rep, u.Key); res.Outcome != tc.outcome {
				t.Fatalf("outcome %+v, want %s", res, tc.outcome)
			}
			var conflict []byte
			if exists(tr + ".precinto-restored") {
				conflict = readFile(t, tr+".precinto-restored")
			}
			tc.want(t, readFile(t, tr), orig, f, conflict)
			// Every other file is back.
			for p, b := range origs {
				if p != tr && !bytes.Equal(readFile(t, p), b) {
					t.Fatalf("%s differs", p)
				}
			}
		})
	}
}

// fragmentAfter builds a linked one-line fragment whose parentUuid is the
// last uuid of orig (what Claude writes after a move, E8).
func fragmentAfter(t *testing.T, orig []byte) []byte {
	t.Helper()
	l, err := testScanLinks(context.Background(), bytes.NewReader(orig))
	mustNoErr(t, err)
	last := ""
	for _, line := range bytes.Split(bytes.TrimSpace(orig), []byte("\n")) {
		if i := bytes.Index(line, []byte(`"uuid":"`)); i >= 0 {
			rest := line[i+8:]
			last = string(rest[:bytes.IndexByte(rest, '"')])
		}
	}
	if last == "" || !l.UUIDs[last] {
		t.Fatal("no uuid in the original")
	}
	return []byte(`{"parentUuid":"` + last + `","uuid":"00000000-0000-4000-8000-0000000000f7","type":"user"}` + "\n")
}

// SEAL-14 + D42: the sid recreated as a linked fragment after the seal
// seals as a diverged generation, and the layered restore yields C+F.
func TestFragmentAfterSealRestoresMerged(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, origs := te.sealedSession(sid1, nil)
	tr := transcriptOf(u)
	frag := fragmentAfter(t, origs[tr])
	writeAt(t, tr, frag)
	u2 := te.scanSession(sid1)
	rep, _ := te.run().sealCommand(context.Background(), []harness.Unit{u2}, Options{})
	res := outcome(t, rep, u.Key)
	if res.Outcome != OutSealed || res.Gen != 2 || res.Lineage != capsule.LineageDiverged {
		t.Fatalf("fragment seal %+v", res)
	}
	rep = te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	if res := outcome(t, rep, u.Key); res.Outcome != OutMerged && res.Outcome != OutRestored {
		t.Fatalf("restore %+v", res)
	}
	want := append(append([]byte(nil), origs[tr]...), frag...)
	if got := readFile(t, tr); !bytes.Equal(got, want) {
		t.Fatalf("layered restore is not C+F:\n%s", got)
	}
	for p, b := range origs {
		if p != tr && !bytes.Equal(readFile(t, p), b) {
			t.Fatalf("%s from the older generation not restored", p)
		}
	}
	// O2: no duplicate uuid after the restore.
	seen := map[string]int{}
	for _, line := range bytes.Split(bytes.TrimSpace(readFile(t, tr)), []byte("\n")) {
		if i := bytes.Index(line, []byte(`"uuid":"`)); i >= 0 {
			rest := line[i+8:]
			seen[string(rest[:bytes.IndexByte(rest, '"')])]++
		}
	}
	for u, n := range seen {
		if n > 1 {
			t.Fatalf("uuid %s appears %d times", u, n)
		}
	}
}

// D42: an unresolvable pair across generations keeps the newer version at
// the path and the older one as <name>.precinto-g<k><ext>.
func TestLayeredConflictKeepsBothVersions(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, origs := te.sealedSession(sid1, nil)
	tr := transcriptOf(u)
	rel := "file-history/" + sid1 + "/x.txt"
	p := filepath.Join(te.h.ClaudeConfig, rel)
	writeAt(t, p, []byte("one\n"))
	te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	// gen 1 has no x.txt; seal x.txt v1 as gen 2, then change it (not an
	// append) and seal gen 3 (diverged).
	te.run().sealCommand(context.Background(), []harness.Unit{te.scanSession(sid1)}, Options{})
	te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	writeAt(t, p, []byte("two\n"))
	rep, _ := te.run().sealCommand(context.Background(), []harness.Unit{te.scanSession(sid1)}, Options{})
	if res := outcome(t, rep, u.Key); res.Lineage != capsule.LineageDiverged {
		t.Fatalf("lineage %+v", res)
	}
	rep = te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	if res := outcome(t, rep, u.Key); res.Outcome != OutConflict {
		t.Fatalf("restore %+v", res)
	}
	if string(readFile(t, p)) != "two\n" {
		t.Fatal("newer version not at the path")
	}
	older := filepath.Join(te.h.ClaudeConfig, "file-history", sid1, "x.precinto-g2.txt")
	if string(readFile(t, older)) != "one\n" {
		t.Fatal("older version not kept as .precinto-g2")
	}
	if !bytes.Equal(readFile(t, tr), origs[tr]) {
		t.Fatal("transcript from the chain not restored")
	}
}

// D38: newest first within the budget; the rest is reported.
func TestRestoreSelectorsRespectTheBudget(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	var units []harness.Unit
	for i := 0; i < 4; i++ {
		sid := "00000000-0000-4000-8000-0000000000d" + itoa(i)
		u, _ := te.sealedSession(sid, func(s *claudetest.Session) { s.ModTime = testkit.Epoch.Add(time.Duration(i) * time.Hour) })
		units = append(units, u)
	}
	one := te.logged(units[0].Key)[0].Bytes
	rep := te.restoreUnits(RestoreRequest{Select: []harness.Selector{{Kind: capsule.KindClaudeSession, RootID: rootID, Recent: 3, MaxBytes: 2*one + one/2}}})
	if rep.Count(OutRestored) != 2 || rep.Count(OutSkipped) != 1 {
		t.Fatalf("restored %d skipped %d: %+v", rep.Count(OutRestored), rep.Count(OutSkipped), rep.Units)
	}
	// The newest two (by last activity) were restored, the oldest never
	// considered (Recent 3), the third skipped for the budget.
	if outcome(t, rep, units[3].Key).Outcome != OutRestored || outcome(t, rep, units[2].Key).Outcome != OutRestored {
		t.Fatalf("not newest first: %+v", rep.Units)
	}
	if outcome(t, rep, units[1].Key).Outcome != OutSkipped {
		t.Fatalf("budget: %+v", rep.Units)
	}
}

// D14: an explicit resume of an old session clamps mtimes to now − 1 day.
func TestRestoreClampsMtimes(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, func(s *claudetest.Session) { s.ModTime = testkit.Epoch.Add(-40 * 24 * time.Hour) })
	te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}, MtimeNow: true})
	floor := te.h.Clock.Now().Add(-24 * time.Hour)
	for _, f := range u.Files {
		st, _ := fsx.Lstat(filepath.Join(u.Home.Bases[f.Base], f.Rel))
		if time.Unix(0, st.MtimeNS).Before(floor) {
			t.Fatalf("%s mtime not clamped", f.Rel)
		}
	}
	// The manifest keeps the original (the capsule is untouched).
	if len(te.logged(u.Key)) != 1 {
		t.Fatal("restore changed the log")
	}
}

// REST-2: not enough space: the unit is skipped, nothing placed.
func TestRestoreSkipsWithoutSpace(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	te.fs.free = 10
	rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	if res := outcome(t, rep, u.Key); res.Outcome != OutSkipped || res.Class != fsx.ClassNoSpace {
		t.Fatalf("result %+v", res)
	}
	for _, f := range u.Files {
		if exists(filepath.Join(u.Home.Bases[f.Base], f.Rel)) {
			t.Fatal("placed partially")
		}
	}
}

// REST-9: EPERM (TCC) under a target: inaccessible, never "missing".
func TestRestoreInaccessibleTarget(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	tr := transcriptOf(u)
	te.fs.inject("lstat", tr, syscall.EPERM)
	rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	res := outcome(t, rep, u.Key)
	if res.Outcome != OutInaccessible || !errors.Is(rep.Err(), ErrInaccessible) {
		t.Fatalf("result %+v %v", res, rep.Err())
	}
	if exists(tr) {
		t.Fatal("transcript placed through a denied target")
	}
}

func TestRestoreRefusesALiveUnitAndDeniedKeys(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	te.claude.probe[u.Key] = []live.Evidence{{Reason: live.ReasonRegistry}}
	rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	if res := outcome(t, rep, u.Key); res.Outcome != OutLive {
		t.Fatalf("live %+v", res)
	}
	// A lease alone (the restoring wrapper's own) is not liveness here.
	te.claude.probe[u.Key] = []live.Evidence{{Reason: live.ReasonLease}}
	te.keys.deny = true
	rep = te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	if res := outcome(t, rep, u.Key); res.Outcome != OutFailed || !errors.Is(rep.Err(), ErrKeyDenied) {
		t.Fatalf("denied %+v %v", res, rep.Err())
	}
}

// REST-8: a lock during a restore destroys keys at once; (a) before
// staging nothing is placed; (b)/(c) a staged or placing unit rolls
// forward from staging; the restore stops before the next unit.
func TestRestoreAbort(t *testing.T) {
	t.Parallel()
	t.Run("before staging", func(t *testing.T) {
		te := newTestEnv(t)
		u, _ := te.sealedSession(sid1, nil)
		abort := make(chan struct{})
		te.codec.duringExtract = func(n int) {
			if n == 0 {
				close(abort)
				time.Sleep(50 * time.Millisecond)
			}
		}
		rep := te.restoreUnits(RestoreRequest{Units: []harness.UnitRef{refOf(u)}, Abort: abort})
		if res := outcome(t, rep, u.Key); res.Outcome != OutSkipped {
			t.Fatalf("result %+v", res)
		}
		for _, f := range u.Files {
			if exists(filepath.Join(u.Home.Bases[f.Base], f.Rel)) {
				t.Fatal("placed after an abort before staging")
			}
		}
		if !te.keys.allDestroyed() {
			t.Fatal("keys not destroyed")
		}
		if ents, _ := os.ReadDir(te.h.Layout.StagingDir); len(ents) != 0 {
			t.Fatal("staging left")
		}
	})
	t.Run("staged and placing roll forward", func(t *testing.T) {
		te := newTestEnv(t)
		u1, o1 := te.sealedSession(sid1, nil)
		u2, _ := te.sealedSession(sid2, nil)
		abort := make(chan struct{})
		req := RestoreRequest{Units: []harness.UnitRef{refOf(u1), refOf(u2)}, Abort: abort}
		// The lock arrives at the first placement of the first unit (staged
		// is journaled, nothing placed yet): keys go at once.
		var once bool
		te.fs.onRename = func(dst string) {
			if !once && strings.HasPrefix(dst, te.h.ClaudeConfig) || !once && strings.HasPrefix(dst, te.h.ClaudeTmp) {
				once = true
				close(abort)
				for !te.keys.allDestroyed() {
					time.Sleep(time.Millisecond)
				}
			}
		}
		rep := te.restoreUnits(req)
		if res := outcome(t, rep, u1.Key); res.Outcome != OutRestored {
			t.Fatalf("staged unit %+v", res)
		}
		for p, b := range o1 {
			if !bytes.Equal(readFile(t, p), b) {
				t.Fatal("staged unit not complete")
			}
		}
		if res := outcome(t, rep, u2.Key); res.Outcome != OutSkipped {
			t.Fatalf("next unit %+v", res)
		}
		if exists(transcriptOf(u2)) {
			t.Fatal("restore continued after the lock")
		}
	})
}

// REST-4 with a race: the target appears between evaluation and rename.
func TestRestoreReevaluatesWhenTheTargetAppears(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, origs := te.sealedSession(sid1, nil)
	tr := transcriptOf(u)
	frag := fragmentAfter(t, origs[tr])
	req := RestoreRequest{Units: []harness.UnitRef{refOf(u)}}
	req.BeforePlace = func(string) error {
		writeAt(t, tr, frag) // the appender recreated <sid>.jsonl
		return nil
	}
	rep := te.restoreUnits(req)
	if res := outcome(t, rep, u.Key); res.Outcome != OutMerged {
		t.Fatalf("result %+v", res)
	}
	if got := readFile(t, tr); !bytes.Equal(got, append(append([]byte(nil), origs[tr]...), frag...)) {
		t.Fatal("F clobbered or not merged")
	}
	rd, _, _ := LoadReceipt(te.e, u.Key)
	for _, f := range rd.Files {
		if strings.HasSuffix(f.Rel, sid1+".jsonl") && f.Size != int64(len(origs[tr])) {
			t.Fatalf("merged receipt covers %d bytes, want only C (%d)", f.Size, len(origs[tr]))
		}
	}
	// The merge re-seals as a new generation (F was never sealed).
	rep, _ = te.run().sealCommand(context.Background(), []harness.Unit{te.scanSession(sid1)}, Options{})
	if res := outcome(t, rep, u.Key); res.Outcome != OutSealed || res.Gen != 2 {
		t.Fatalf("re-seal after a merge %+v", res)
	}
}

func TestRestorePlacesTheTranscriptLast(t *testing.T) {
	t.Parallel()
	files := []plannedFile{
		{Rel: "projects/p/" + sid1 + ".jsonl", Policy: harness.PlaceJSONLAppend},
		{Rel: "projects/p/" + sid1 + "/subagents/agent-1.jsonl", Policy: harness.PlaceJSONLAppend},
		{Rel: "file-history/" + sid1 + "/a", Policy: harness.PlaceExact},
		{Rel: "projects/p/" + sid1 + "/tool-results", Dir: true},
	}
	sortPlacements(files)
	if !files[0].Dir || files[len(files)-1].Rel != "projects/p/"+sid1+".jsonl" {
		t.Fatalf("order %+v", files)
	}
}

func TestRecoverRollsBackAPreparedRestore(t *testing.T) {
	t.Parallel()
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	rec, err := te.e.Journal.Begin(journal.KindRestore, "claude-code", u.Key)
	mustNoErr(t, err)
	st, err := te.fs.NewStaging(te.h.Layout.StagingDir, te.h.ClaudeConfig, rec.ID)
	mustNoErr(t, err)
	writeAt(t, filepath.Join(st.Path(), "g1", "f-000001"), []byte("partial plaintext"))
	rec.Staging = st.Path()
	mustNoErr(t, te.e.Journal.Save(rec))
	r := te.run()
	mustNoErr(t, r.recoverAll(context.Background()))
	if exists(st.Path()) {
		t.Fatal("REST-1: staging not removed")
	}
	for _, f := range u.Files {
		if exists(filepath.Join(u.Home.Bases[f.Base], f.Rel)) {
			t.Fatal("placed during a rollback")
		}
	}
	if p, _ := te.e.Journal.Pending(); len(p) != 0 {
		t.Fatal("record left")
	}
}
