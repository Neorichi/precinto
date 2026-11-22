package capsule_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
)

func TestSealRoundTrip(t *testing.T) {
	u := newUnit(t)
	k := newKeys(t)
	u.write("projects/P/00000000-0000-4000-8000-000000000001.jsonl", []byte("{\"type\":\"user\"}\n"))
	u.write("projects/P/00000000-0000-4000-8000-000000000001/subagents/a.jsonl", randomBytes(t, 1<<20+17))
	u.write("todos/empty.json", nil)
	if err := os.Chmod(filepath.Join(u.root, "todos", "empty.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	mt := time.Date(2026, 1, 2, 3, 4, 5, 600, time.UTC)
	if err := os.Chtimes(filepath.Join(u.root, "todos", "empty.json"), mt, mt); err != nil {
		t.Fatal(err)
	}
	rels := []string{"projects/P/00000000-0000-4000-8000-000000000001.jsonl", "projects/P/00000000-0000-4000-8000-000000000001/subagents/a.jsonl", "todos/empty.json"}
	in := u.inputs(rels...)
	in[0].Append = true
	dirs := []capsule.Entry{{Base: capsule.BaseClaudeConfig, Rel: "file-history/00000000-0000-4000-8000-000000000001", Dir: true, Mode: 0o755}}
	s, err := seal(t, u, k, "g000001.pcap", in, dirs, nil)
	if err != nil {
		t.Fatal(err)
	}
	u.assertPlaintext() // Seal never deletes plaintext
	if got := u.outNames(); len(got) != 1 || got[0] != "g000001.pcap" {
		t.Fatalf("capsule directory %v", got)
	}
	if s.Name != "g000001.pcap" || s.Path != filepath.Join(u.outP, "g000001.pcap") || len(s.Snaps) != 3 {
		t.Fatalf("Sealed %+v", s)
	}
	m := s.Manifest
	if m.Format != capsule.FormatVersion || len(m.Files) != 4 {
		t.Fatalf("manifest %+v", m)
	}
	wantFpr := capsule.RecipientsFingerprint("x25519", []string{k.vault.Recipient().String(), k.recovery.Recipient().String()})
	if m.RecipientsFpr != wantFpr {
		t.Errorf("recipients_fpr %s, want %s", m.RecipientsFpr, wantFpr)
	}
	for i, rel := range rels {
		e := m.Files[i]
		sum := sha256.Sum256(u.files[rel])
		if e.Name != []string{"f/000001", "f/000002", "f/000003"}[i] || e.Rel != rel || e.Base != capsule.BaseClaudeConfig ||
			e.Size != int64(len(u.files[rel])) || e.SHA256 != hex.EncodeToString(sum[:]) || e.Path != filepath.Join(u.root, rel) {
			t.Errorf("entry %d: %+v", i, e)
		}
	}
	if !m.Files[0].Append || m.Files[2].Mode != 0o755 || m.Files[2].MtimeNS != mt.UnixNano() {
		t.Errorf("entry metadata: %+v / %+v", m.Files[0], m.Files[2])
	}
	if d := m.Files[3]; !d.Dir || d.Name != "" || d.Rel != dirs[0].Rel || d.Mode != 0o755 {
		t.Errorf("directory entry %+v", d)
	}

	// Provenance hashes agree with the file on disk.
	sum, size, err := capsule.HashFile(u.out, s.Name)
	if err != nil || sum != s.SHA256 || size != s.Size {
		t.Fatalf("HashFile = %s %d %v, Sealed %s %d", sum, size, err, s.SHA256, s.Size)
	}
	hdr, hsum, err := capsule.ReadHeader(u.out, s.Name)
	if err != nil || hsum != s.HeaderSHA256 {
		t.Fatalf("ReadHeader = %s %v, Sealed %s", hsum, err, s.HeaderSHA256)
	}
	if err := capsule.CheckHeader(bytes.NewReader(hdr), capsule.HeaderStanzas); err != nil {
		t.Fatal(err)
	}

	// Vault and recovery identities both unwrap it.
	for _, id := range []*age.X25519Identity{k.vault, k.recovery} {
		fk := fileKey(t, u.out, s.Name, id)
		f, _, err := u.out.Open(s.Name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := capsule.OpenManifest(f, fk)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(normalize(got), normalize(m)) {
			t.Fatalf("OpenManifest differs:\n%+v\n%+v", got, m)
		}
	}

	// Extract reproduces exact bytes into 0600 staging files.
	staging := newStaging(t, u.root)
	f, _, err := u.out.Open(s.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var checked []string
	got, staged, err := capsule.Extract(context.Background(), f, capsule.ExtractOptions{
		FileKey: fileKey(t, u.out, s.Name, k.vault), Staging: staging,
		Limits: capsule.Limits{MaxTotal: 1 << 30},
		Check:  func(e capsule.Entry) error { checked = append(checked, e.Rel); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(checked) != 4 || len(staged) != 3 || got.Title != m.Title {
		t.Fatalf("checked %v staged %d", checked, len(staged))
	}
	for i, st := range staged {
		b, err := os.ReadFile(filepath.Join(staging.Path, st.StagedRel))
		if err != nil || !bytes.Equal(b, u.files[rels[i]]) {
			t.Fatalf("staged %s: %v", st.StagedRel, err)
		}
		fi, _ := os.Lstat(filepath.Join(staging.Path, st.StagedRel))
		if fi.Mode() != 0o600 || st.Stat.Size != int64(len(b)) || st.Entry.Rel != rels[i] {
			t.Errorf("staged %s mode %v stat %+v", st.StagedRel, fi.Mode(), st.Stat)
		}
	}
}

// normalize drops the monotonic clock reading and location so manifests
// compare by value after a JSON round trip.
func normalize(m capsule.Manifest) capsule.Manifest {
	m.CreatedAt = m.CreatedAt.UTC().Round(0)
	m.LastActivity = m.LastActivity.UTC().Round(0)
	return m
}

func TestSealRecipientSetRefused(t *testing.T) {
	u := newUnit(t)
	u.write("a", []byte("x"))
	k := newKeys(t)
	other := newKeys(t)
	scrypt, err := age.NewScryptRecipient("not a vault recipient")
	if err != nil {
		t.Fatal(err)
	}
	for name, rs := range map[string][]age.Recipient{
		"none":      nil,
		"one":       {k.vault.Recipient()},
		"three":     {k.vault.Recipient(), k.recovery.Recipient(), other.vault.Recipient()},
		"duplicate": {k.vault.Recipient(), k.vault.Recipient()},
		"scrypt":    {k.vault.Recipient(), scrypt},
	} {
		_, err := capsule.Seal(context.Background(), capsule.SealRequest{
			Manifest: manifest("m"), Inputs: u.inputs("a"), Recipients: rs, Out: u.out, Name: "g000001.pcap",
		})
		if !errors.Is(err, capsule.ErrRecipients) {
			t.Errorf("%s: %v, want ErrRecipients", name, err)
		}
	}
	m := manifest("m")
	m.RecipientsFpr = capsule.RecipientsFingerprint("x25519", []string{other.vault.Recipient().String(), other.recovery.Recipient().String()})
	if _, err := capsule.Seal(context.Background(), capsule.SealRequest{
		Manifest: m, Inputs: u.inputs("a"), Recipients: k.recipients(), Out: u.out, Name: "g000001.pcap",
	}); !errors.Is(err, capsule.ErrRecipients) {
		t.Errorf("fingerprint of another set: %v", err)
	}
	if n := u.outNames(); len(n) != 0 {
		t.Fatalf("left %v", n)
	}
	u.assertPlaintext()
}

func TestSealInputValidation(t *testing.T) {
	u := newUnit(t)
	u.write("a", []byte("x"))
	k := newKeys(t)
	good := u.input("a")
	for name, mut := range map[string]func(*capsule.Input){
		"absolute rel":  func(in *capsule.Input) { in.Rel = "/etc/passwd" },
		"escaping rel":  func(in *capsule.Input) { in.Rel = "../a" },
		"unclean rel":   func(in *capsule.Input) { in.Rel = "x/../a" },
		"unknown base":  func(in *capsule.Input) { in.Base = "home" },
		"bare generic":  func(in *capsule.Input) { in.Base = capsule.BaseGeneric },
		"generic upper": func(in *capsule.Input) { in.Base = "generic:Gemini" },
	} {
		in := good
		mut(&in)
		if _, err := seal(t, u, k, "g000001.pcap", []capsule.Input{in}, nil, nil); !errors.Is(err, capsule.ErrUnsafe) {
			t.Errorf("%s: %v, want ErrUnsafe", name, err)
		}
	}
	gen := good
	gen.Base = "generic:gemini-cli"
	if _, err := seal(t, u, k, "g000001.pcap", []capsule.Input{gen}, nil, nil); err != nil {
		t.Errorf("generic base: %v", err)
	}
	if _, err := seal(t, u, k, "g000002.pcap", []capsule.Input{good, good}, nil, nil); !errors.Is(err, capsule.ErrUnsafe) {
		t.Errorf("duplicate input: %v", err)
	}
	for _, bad := range []string{"", ".hidden", "a/b", ".."} {
		if _, err := seal(t, u, k, bad, []capsule.Input{good}, nil, nil); !errors.Is(err, capsule.ErrUnsafe) {
			t.Errorf("capsule name %q: %v", bad, err)
		}
	}
}

// TestSealChangedBetweenPasses covers TESTPLAN SEAL-5 for capsule: an
// appender writes between the hash pass and the copy pass, a same-size
// in-place rewrite, an inode swap and a deletion all abort with ErrChanged,
// leave no temporary and keep the plaintext.
func TestSealChangedBetweenPasses(t *testing.T) {
	rewriteAt := func(t *testing.T, path string, b []byte) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteAt(b, 0); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for name, change := range map[string]func(t *testing.T, path string){
		"append": func(t *testing.T, path string) {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			f.WriteString("{\"late\":true}\n")
			f.Close()
		},
		"inode swap, same size and mtime": func(t *testing.T, path string) {
			fi, _ := os.Stat(path)
			b, _ := os.ReadFile(path)
			tmp := path + ".new"
			os.WriteFile(tmp, bytes.ToUpper(b), 0o600)
			os.Chtimes(tmp, fi.ModTime(), fi.ModTime())
			if err := os.Rename(tmp, path); err != nil {
				t.Fatal(err)
			}
		},
		"rewrite in place, same size": func(t *testing.T, path string) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			nb := bytes.ToUpper(b)
			if bytes.Equal(nb, b) {
				t.Fatalf("the rewrite of %q changes no byte", b)
			}
			rewriteAt(t, path, nb)
		},
		// The same bytes written back under a new mtime: only the identity
		// (dev, inode, size, mtime, ctime) shows the write. On Linux before
		// multigrain timestamps (6.13) a write in the clock tick of the last
		// change keeps both times, so the mtime is moved explicitly.
		"same bytes, new mtime": func(t *testing.T, path string) {
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			rewriteAt(t, path, b)
			if err := os.Chtimes(path, fi.ModTime(), fi.ModTime().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
		},
		"deleted": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			u := newUnit(t)
			k := newKeys(t)
			u.write("s.jsonl", []byte("{\"a\":1}\n"))
			u.write("t.jsonl", []byte("{\"b\":2}\n"))
			_, err := seal(t, u, k, "g000001.pcap", u.inputs("s.jsonl", "t.jsonl"), nil, func(p capsule.Phase, _ *capsule.Sealed) error {
				if p == capsule.PhaseHashed {
					change(t, filepath.Join(u.root, "t.jsonl"))
				}
				return nil
			})
			if !errors.Is(err, capsule.ErrChanged) {
				t.Fatalf("Seal = %v, want ErrChanged", err)
			}
			if n := u.outNames(); len(n) != 0 {
				t.Fatalf("left %v", n)
			}
			if b, _ := os.ReadFile(filepath.Join(u.root, "s.jsonl")); string(b) != "{\"a\":1}\n" {
				t.Fatal("unrelated plaintext changed")
			}
		})
	}
	// A snapshot that no longer matches at pass 1 is a change too.
	u := newUnit(t)
	u.write("s.jsonl", []byte("x"))
	in := u.input("s.jsonl")
	u.write("s.jsonl", []byte("xy"))
	if _, err := seal(t, u, newKeys(t), "g000001.pcap", []capsule.Input{in}, nil, nil); !errors.Is(err, capsule.ErrChanged) {
		t.Fatalf("stale snapshot: %v", err)
	}
	if _, err := seal(t, u, newKeys(t), "g000001.pcap", []capsule.Input{{Base: capsule.BaseClaudeConfig, Dir: u.base, Rel: "gone"}}, nil, nil); !errors.Is(err, capsule.ErrChanged) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing source: %v", err)
	}
}

// TestSealByteFlip is TESTPLAN SEAL-4 for capsule: one byte flipped in the
// temporary (header or payload) fails the ephemeral round trip; the
// temporary is deleted and the plaintext kept.
func TestSealByteFlip(t *testing.T) {
	for name, at := range map[string]func(size int64) int64{
		"header":  func(int64) int64 { return 30 },
		"payload": func(size int64) int64 { return size - 40 },
		"last":    func(size int64) int64 { return size - 1 },
	} {
		t.Run(name, func(t *testing.T) {
			u := newUnit(t)
			u.write("s.jsonl", randomBytes(t, 100000))
			_, err := seal(t, u, newKeys(t), "g000001.pcap", u.inputs("s.jsonl"), nil, func(p capsule.Phase, _ *capsule.Sealed) error {
				if p != capsule.PhaseTmpWritten {
					return nil
				}
				path := filepath.Join(u.outP, ".g000001.pcap.tmp")
				f, err := os.OpenFile(path, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				fi, _ := f.Stat()
				off := at(fi.Size())
				var b [1]byte
				f.ReadAt(b[:], off)
				b[0] ^= 0x20
				f.WriteAt(b[:], off)
				return nil
			})
			if !errors.Is(err, capsule.ErrVerify) && !errors.Is(err, capsule.ErrHeader) {
				t.Fatalf("Seal = %v, want ErrVerify", err)
			}
			if n := u.outNames(); len(n) != 0 {
				t.Fatalf("left %v", n)
			}
			u.assertPlaintext()
		})
	}
}

func TestOnPhaseOrder(t *testing.T) {
	u := newUnit(t)
	u.write("s.jsonl", []byte("x"))
	var phases []capsule.Phase
	tmp := filepath.Join(u.outP, ".g000001.pcap.tmp")
	final := filepath.Join(u.outP, "g000001.pcap")
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	s, err := seal(t, u, newKeys(t), "g000001.pcap", u.inputs("s.jsonl"), nil, func(p capsule.Phase, s *capsule.Sealed) error {
		phases = append(phases, p)
		switch p {
		case capsule.PhaseHashed:
			if exists(tmp) || exists(final) || len(s.Manifest.Files) != 1 || s.SHA256 != "" {
				t.Errorf("hashed: state wrong (%v %v %+v)", exists(tmp), exists(final), s)
			}
		case capsule.PhaseTmpWritten:
			if !exists(tmp) || exists(final) {
				t.Errorf("tmp_written: tmp %v final %v", exists(tmp), exists(final))
			}
		case capsule.PhaseVerified:
			if !exists(tmp) || exists(final) || s.SHA256 == "" || s.HeaderSHA256 == "" || s.Size == 0 {
				t.Errorf("verified: %+v", s)
			}
		case capsule.PhaseCommitted:
			if exists(tmp) || !exists(final) {
				t.Errorf("committed: tmp %v final %v", exists(tmp), exists(final))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []capsule.Phase{capsule.PhaseHashed, capsule.PhaseTmpWritten, capsule.PhaseVerified, capsule.PhaseCommitted}
	if !reflect.DeepEqual(phases, want) || s == nil {
		t.Fatalf("phases %v", phases)
	}

	// An error before the commit removes the temporary; an error at the
	// commit leaves the renamed capsule for journal recovery.
	stop := errors.New("journal write failed")
	for _, p := range want {
		u := newUnit(t)
		u.write("s.jsonl", []byte("x"))
		_, err := seal(t, u, newKeys(t), "g000001.pcap", u.inputs("s.jsonl"), nil, func(got capsule.Phase, _ *capsule.Sealed) error {
			if got == p {
				return stop
			}
			return nil
		})
		if !errors.Is(err, stop) {
			t.Fatalf("%s: %v", p, err)
		}
		names := u.outNames()
		if p == capsule.PhaseCommitted {
			if len(names) != 1 || names[0] != "g000001.pcap" {
				t.Errorf("%s: %v, want the committed capsule only", p, names)
			}
		} else if len(names) != 0 {
			t.Errorf("%s: %v left", p, names)
		}
		u.assertPlaintext()
	}
}

func TestSealNeverOverwrites(t *testing.T) {
	u := newUnit(t)
	k := newKeys(t)
	u.write("s.jsonl", []byte("first"))
	s1, err := seal(t, u, k, "g000001.pcap", u.inputs("s.jsonl"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	u.write("s.jsonl", []byte("second"))
	_, err = seal(t, u, k, "g000001.pcap", u.inputs("s.jsonl"), nil, nil)
	if !errors.Is(err, fsx.ErrExist) {
		t.Fatalf("Seal over an existing generation = %v", err)
	}
	if sum, _, _ := capsule.HashFile(u.out, "g000001.pcap"); sum != s1.SHA256 {
		t.Fatal("existing generation modified")
	}
	if n := u.outNames(); len(n) != 1 {
		t.Fatalf("left %v", n)
	}
}

func TestSealRescueInput(t *testing.T) {
	u := newUnit(t)
	k := newKeys(t)
	u.write("s.jsonl", []byte("line1\n"))
	f, err := os.OpenFile(filepath.Join(u.root, "s.jsonl"), os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Remove(filepath.Join(u.root, "s.jsonl")); err != nil { // already unlinked by the sweep
		t.Fatal(err)
	}
	f.WriteString("late tail\n")
	st, err := fsx.Fstat(f)
	if err != nil {
		t.Fatal(err)
	}
	s, err := seal(t, u, k, "g000002.pcap", []capsule.Input{{Base: capsule.BaseClaudeConfig, Rel: "s.jsonl", Snap: st, Open: f}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Manifest.Files[0].Size != int64(len("line1\nlate tail\n")) {
		t.Fatalf("rescue size %d", s.Manifest.Files[0].Size)
	}
	if _, err := f.Stat(); err != nil {
		t.Fatal("Seal closed the caller's descriptor")
	}
}

func TestSealContextCancelled(t *testing.T) {
	u := newUnit(t)
	u.write("s.jsonl", []byte("x"))
	ctx, cancel := context.WithCancel(context.Background())
	_, err := capsule.Seal(ctx, capsule.SealRequest{
		Manifest: manifest("m"), Inputs: u.inputs("s.jsonl"), Recipients: newKeys(t).recipients(), Out: u.out, Name: "g000001.pcap",
		OnPhase: func(p capsule.Phase, _ *capsule.Sealed) error {
			if p == capsule.PhaseTmpWritten {
				cancel()
			}
			return nil
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Seal = %v", err)
	}
	if n := u.outNames(); len(n) != 0 {
		t.Fatalf("left %v", n)
	}
}

// encryptTo writes an age file with the given recipients.
func encryptTo(t testing.TB, payload []byte, rs ...age.Recipient) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := age.Encrypt(&b, rs...)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(payload)
	w.Close()
	return b.Bytes()
}

func TestCheckHeaderStanzas(t *testing.T) {
	var ids []age.Recipient
	for i := 0; i < 4; i++ {
		id, _ := age.GenerateX25519Identity()
		ids = append(ids, id.Recipient())
	}
	for n := 1; n <= 4; n++ {
		err := capsule.CheckHeader(bytes.NewReader(encryptTo(t, []byte("x"), ids[:n]...)), capsule.HeaderStanzas)
		if n == 3 && err != nil {
			t.Errorf("3 stanzas: %v", err)
		}
		if n != 3 && !errors.Is(err, capsule.ErrHeader) {
			t.Errorf("%d stanzas: %v, want ErrHeader", n, err)
		}
	}
	sr, _ := age.NewScryptRecipient("pw")
	sr.SetWorkFactor(10)
	if err := capsule.CheckHeader(bytes.NewReader(encryptTo(t, []byte("x"), sr)), 1); !errors.Is(err, capsule.ErrHeader) {
		t.Errorf("scrypt stanza: %v", err)
	}
	if err := capsule.CheckHeader(strings.NewReader("not an age file"), 3); !errors.Is(err, capsule.ErrHeader) {
		t.Errorf("garbage: %v", err)
	}
}

func TestReadTamperTruncationWrongKey(t *testing.T) {
	u := newUnit(t)
	k := newKeys(t)
	u.write("s.jsonl", randomBytes(t, 200000))
	s, err := seal(t, u, k, "g000001.pcap", u.inputs("s.jsonl"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	fk := fileKey(t, u.out, s.Name, k.vault)
	extractBytes := func(b []byte, key []byte) error {
		st, err := fsx.NewStaging(filepath.Join(filepath.Dir(u.root), "staging"), u.root, "op-"+hex.EncodeToString(randomBytes(t, 4)))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Remove()
		_, _, err = capsule.Extract(context.Background(), bytes.NewReader(b), capsule.ExtractOptions{FileKey: key, Staging: st, Limits: capsule.Limits{MaxTotal: 1 << 30}, Check: allowAll})
		return err
	}
	if err := extractBytes(good, fk); err != nil {
		t.Fatalf("untouched capsule: %v", err)
	}
	for _, cut := range []int{0, 10, len(good) / 2, len(good) - 1} {
		if err := extractBytes(good[:cut], fk); err == nil {
			t.Errorf("truncated at %d: accepted", cut)
		}
	}
	for _, off := range []int{len(good) / 3, len(good) - 20} {
		b := append([]byte(nil), good...)
		b[off] ^= 1
		if err := extractBytes(b, fk); err == nil {
			t.Errorf("flipped byte at %d: accepted", off)
		}
	}
	wrong := append([]byte(nil), fk...)
	wrong[0] ^= 1
	if err := extractBytes(good, wrong); !errors.Is(err, capsule.ErrVerify) {
		t.Errorf("wrong file key: %v", err)
	}
	if _, err := capsule.OpenManifest(bytes.NewReader(good), wrong); !errors.Is(err, capsule.ErrVerify) {
		t.Errorf("OpenManifest with a wrong key: %v", err)
	}
	if _, err := capsule.OpenManifest(bytes.NewReader(good), fk[:8]); !errors.Is(err, capsule.ErrFormat) {
		t.Errorf("short key: %v", err)
	}
	// A third identity gets no file key at all.
	stranger, _ := age.GenerateX25519Identity()
	hdr, _, _ := capsule.ReadHeader(u.out, s.Name)
	if _, err := age.DecryptHeader(hdr, stranger); err == nil {
		t.Error("a foreign identity unwrapped the header")
	}
	// A trailing byte after the age stream is refused.
	if err := extractBytes(append(append([]byte(nil), good...), 0), fk); err == nil {
		t.Error("trailing byte accepted")
	}
}

func TestExtractLimitsAndCheck(t *testing.T) {
	u := newUnit(t)
	k := newKeys(t)
	u.write("a", randomBytes(t, 1000))
	u.write("b", randomBytes(t, 1000))
	s, err := seal(t, u, k, "g000001.pcap", u.inputs("a", "b"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fk := fileKey(t, u.out, s.Name, k.vault)
	try := func(o capsule.ExtractOptions) (*fsx.Staging, error) {
		st := newStaging(t, u.root)
		f, _, err := u.out.Open(s.Name)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		o.FileKey, o.Staging = fk, st
		_, _, err = capsule.Extract(context.Background(), f, o)
		return st, err
	}
	empty := func(st *fsx.Staging) bool { ents, _ := os.ReadDir(st.Path); return len(ents) == 0 }
	st, err := try(capsule.ExtractOptions{Limits: capsule.Limits{MaxTotal: 1999}, Check: allowAll})
	if !errors.Is(err, capsule.ErrTooLarge) || !empty(st) {
		t.Errorf("over budget: %v", err)
	}
	st, err = try(capsule.ExtractOptions{Check: allowAll})
	if !errors.Is(err, capsule.ErrTooLarge) || !empty(st) {
		t.Errorf("zero budget: %v", err)
	}
	st, err = try(capsule.ExtractOptions{Limits: capsule.Limits{MaxTotal: 2000, MaxFiles: 1}, Check: allowAll})
	if !errors.Is(err, capsule.ErrTooLarge) || !empty(st) {
		t.Errorf("too many files: %v", err)
	}
	denied := errors.New("not an allowed target")
	st, err = try(capsule.ExtractOptions{Limits: capsule.Limits{MaxTotal: 2000}, Check: func(e capsule.Entry) error {
		if e.Rel == "b" {
			return denied
		}
		return nil
	}})
	if !errors.Is(err, capsule.ErrUnsafe) || !errors.Is(err, denied) || !empty(st) {
		t.Errorf("Check refusal: %v (nothing may be written)", err)
	}
	st, err = try(capsule.ExtractOptions{Limits: capsule.Limits{MaxTotal: 2000}})
	if !errors.Is(err, capsule.ErrUnsafe) || !empty(st) {
		t.Errorf("nil Check: %v", err)
	}
	if _, err := try(capsule.ExtractOptions{Limits: capsule.Limits{MaxTotal: 2000}, Check: allowAll}); err != nil {
		t.Errorf("within limits: %v", err)
	}
}

// TestModeIsRecordedNotApplied (SEC-5, capsule part): the manifest keeps
// the original bits for placement to mask; staging is always 0600.
func TestModeIsRecordedNotApplied(t *testing.T) {
	u := newUnit(t)
	k := newKeys(t)
	u.write("tool.sh", []byte("#!/bin/sh\n"))
	if err := os.Chmod(filepath.Join(u.root, "tool.sh"), 0o4777); err != nil {
		t.Fatal(err)
	}
	s, err := seal(t, u, k, "g000001.pcap", u.inputs("tool.sh"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mode := s.Manifest.Files[0].Mode; mode&0o777 != 0o777 {
		t.Fatalf("recorded mode %o", mode)
	}
	st := newStaging(t, u.root)
	f, _, _ := u.out.Open(s.Name)
	defer f.Close()
	_, staged, err := capsule.Extract(context.Background(), f, capsule.ExtractOptions{FileKey: fileKey(t, u.out, s.Name, k.vault), Staging: st, Limits: capsule.Limits{MaxTotal: 100}, Check: allowAll})
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Lstat(filepath.Join(st.Path, staged[0].StagedRel))
	if fi.Mode() != 0o600 {
		t.Fatalf("staged mode %v", fi.Mode())
	}
	if err := st.Dir.Chmod(staged[0].StagedRel, fs.FileMode(staged[0].Entry.Mode)); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(filepath.Join(st.Path, staged[0].StagedRel)); fi.Mode() != 0o700 {
		t.Fatalf("placed mode %v, want owner bits only", fi.Mode())
	}
}

func TestLoadSalt(t *testing.T) {
	dir, _ := fsx.Realpath(t.TempDir())
	p := filepath.Join(dir, "name.salt")
	s1, err := capsule.LoadSalt(p)
	if err != nil || len(s1) != 32 {
		t.Fatalf("LoadSalt = %x %v", s1, err)
	}
	if fi, _ := os.Lstat(p); fi.Mode() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	s2, err := capsule.LoadSalt(p)
	if err != nil || !bytes.Equal(s1, s2) {
		t.Fatal("salt changed between loads")
	}
	// Concurrent first loads agree on one salt.
	q := filepath.Join(dir, "other.salt")
	got := make(chan []byte, 8)
	for i := 0; i < 8; i++ {
		go func() { s, _ := capsule.LoadSalt(q); got <- s }()
	}
	first := <-got
	for i := 1; i < 8; i++ {
		if s := <-got; !bytes.Equal(s, first) {
			t.Fatal("concurrent loads disagree")
		}
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Errorf("temporaries left: %v", ents)
	}
	// A corrupt salt is refused, never replaced.
	bad := filepath.Join(dir, "bad.salt")
	os.WriteFile(bad, []byte("short"), 0o600)
	if _, err := capsule.LoadSalt(bad); err == nil {
		t.Error("short salt accepted")
	}
	if b, _ := os.ReadFile(bad); string(b) != "short" {
		t.Error("corrupt salt replaced")
	}
	link := filepath.Join(dir, "link.salt")
	os.Symlink(p, link)
	if _, err := capsule.LoadSalt(link); !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("symlinked salt: %v", err)
	}
}

func TestRecipientsFingerprint(t *testing.T) {
	a := capsule.RecipientsFingerprint("x25519", []string{"age1b", "age1a"})
	b := capsule.RecipientsFingerprint("x25519", []string{"age1a", "age1b"})
	sum := sha256.Sum256([]byte("x25519\nage1a\nage1b"))
	if a != b || a != hex.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint %s %s", a, b)
	}
	if capsule.RecipientsFingerprint("other", []string{"age1a", "age1b"}) == a {
		t.Fatal("family not covered")
	}
	in := []string{"z", "a"}
	capsule.RecipientsFingerprint("x25519", in)
	if in[0] != "z" {
		t.Fatal("caller's slice reordered")
	}
}

// Leak check: the marker in the title never appears in plaintext outside
// the ciphertext (the capsule directory holds only ciphertext).
func TestNoPlaintextOutsideCiphertext(t *testing.T) {
	u := newUnit(t)
	k := newKeys(t)
	marker := "precinto-marker-capsule-leak"
	u.write("s.jsonl", []byte(marker))
	m := manifest(marker)
	if _, err := capsule.Seal(context.Background(), capsule.SealRequest{Manifest: m, Inputs: u.inputs("s.jsonl"), Recipients: k.recipients(), Out: u.out, Name: "g000001.pcap"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(u.outP, "g000001.pcap"))
	if bytes.Contains(b, []byte(marker)) {
		t.Fatal("marker visible in the capsule")
	}
}
