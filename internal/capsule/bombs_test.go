package capsule_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"

	"github.com/Neorichi/precinto/internal/capsule"
)

// craft builds a capsule by hand: age(magic || zstd(whatever build writes)).
func craft(t testing.TB, k keys, zopts []zstd.EOption, build func(w io.Writer)) []byte {
	t.Helper()
	eph, _ := age.GenerateX25519Identity()
	var buf bytes.Buffer
	aw, err := age.Encrypt(&buf, k.vault.Recipient(), k.recovery.Recipient(), eph.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(aw, capsule.Magic)
	zw, err := zstd.NewWriter(aw, zopts...)
	if err != nil {
		t.Fatal(err)
	}
	build(zw)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func craftKey(t testing.TB, ct []byte, id age.Identity) []byte {
	t.Helper()
	hdr, err := age.ExtractHeader(bytes.NewReader(ct))
	if err != nil {
		t.Fatal(err)
	}
	fk, err := age.DecryptHeader(hdr, id)
	if err != nil {
		t.Fatal(err)
	}
	return fk
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func reg(name string, size int64) *tar.Header {
	return &tar.Header{Typeflag: tar.TypeReg, Name: name, Size: size, Mode: 0o600, ModTime: time.Unix(0, 0)}
}

// manifestJSON returns a valid manifest for regular entries with contents.
func manifestJSON(t testing.TB, mut func(*capsule.Manifest), contents ...[]byte) []byte {
	t.Helper()
	m := manifest("bomb")
	m.Format = capsule.FormatVersion
	for i, c := range contents {
		m.Files = append(m.Files, capsule.Entry{Name: fmt.Sprintf("f/%06d", i+1), Base: capsule.BaseClaudeConfig, Rel: fmt.Sprintf("projects/P/f%d", i), Size: int64(len(c)), SHA256: sha(c), Mode: 0o600})
	}
	if mut != nil {
		mut(&m)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tarOf writes the manifest and members as a plain archive.
func tarOf(mj []byte, members ...[]byte) func(io.Writer) {
	return func(w io.Writer) {
		tw := tar.NewWriter(w)
		tw.WriteHeader(reg(capsule.ManifestName, int64(len(mj))))
		tw.Write(mj)
		for i, m := range members {
			tw.WriteHeader(reg(fmt.Sprintf("f/%06d", i+1), int64(len(m))))
			tw.Write(m)
		}
		tw.Close()
	}
}

func extractCrafted(t *testing.T, k keys, ct []byte, lim capsule.Limits) (int, error) {
	t.Helper()
	u := newUnit(t)
	st := newStaging(t, u.root)
	_, _, err := capsule.Extract(context.Background(), bytes.NewReader(ct), capsule.ExtractOptions{
		FileKey: craftKey(t, ct, k.vault), Staging: st, Limits: lim, Check: allowAll,
	})
	ents, _ := os.ReadDir(st.Path)
	return len(ents), err
}

// rawHeader builds one ustar header block by hand (tar.Writer refuses to
// emit the malformed members these tests need).
func rawHeader(name string, size int, typ byte) []byte {
	b := make([]byte, 512)
	copy(b[0:100], name)
	copy(b[100:108], fmt.Sprintf("%07o\x00", 0o600))
	copy(b[108:116], "0000000\x00")
	copy(b[116:124], "0000000\x00")
	copy(b[124:136], fmt.Sprintf("%011o\x00", size))
	copy(b[136:148], fmt.Sprintf("%011o\x00", 0))
	b[156] = typ
	copy(b[257:263], "ustar\x00")
	copy(b[263:265], "00")
	for i := 148; i < 156; i++ {
		b[i] = ' '
	}
	sum := 0
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func padBlock(data []byte) []byte {
	n := (len(data) + 511) / 512 * 512
	return append(append([]byte(nil), data...), make([]byte, n-len(data))...)
}

func rawMember(name string, data []byte, typ byte) []byte {
	return append(rawHeader(name, len(data), typ), padBlock(data)...)
}

// rawPAX builds a PAX extended header (typeflag 'x') from key, value pairs.
func rawPAX(kv ...string) []byte {
	var recs string
	for i := 0; i+1 < len(kv); i += 2 {
		rec := " " + kv[i] + "=" + kv[i+1] + "\n"
		n := len(rec)
		for {
			s := strconv.Itoa(n) + rec
			if len(s) == n {
				recs += s
				break
			}
			n = len(s)
		}
	}
	return rawMember("PaxHeaders/f", []byte(recs), 'x')
}

func rawTar(blocks ...[]byte) func(io.Writer) {
	return func(w io.Writer) {
		for _, b := range blocks {
			w.Write(b)
		}
		w.Write(make([]byte, 1024))
	}
}

var big = capsule.Limits{MaxTotal: 1 << 30}

func TestCraftedBaseline(t *testing.T) {
	k := newKeys(t)
	body := []byte("hello")
	ct := craft(t, k, nil, tarOf(manifestJSON(t, nil, body), body))
	if n, err := extractCrafted(t, k, ct, big); err != nil || n != 1 {
		t.Fatalf("well-formed crafted capsule: %d %v", n, err)
	}
	// The hand-made blocks used by the bomb cases are valid on their own.
	mj := manifestJSON(t, nil, body)
	ct = craft(t, k, nil, rawTar(rawMember(capsule.ManifestName, mj, '0'), rawMember("f/000001", body, '0')))
	if n, err := extractCrafted(t, k, ct, big); err != nil || n != 1 {
		t.Fatalf("well-formed raw archive: %d %v", n, err)
	}
}

// TestBombs is TESTPLAN SEC-4: every malformed archive is rejected, nothing
// is left in staging that the caller would place, and memory stays bounded.
func TestBombs(t *testing.T) {
	k := newKeys(t)
	body := []byte("0123456789")
	mj := manifestJSON(t, nil, body)
	cases := map[string]struct {
		build func(io.Writer)
		want  error
	}{
		"PAX path override":               {rawTar(rawMember(capsule.ManifestName, mj, '0'), rawPAX("path", "../../outside"), rawMember("f/000001", body, '0')), capsule.ErrFormat},
		"PAX path naming the same member": {rawTar(rawMember(capsule.ManifestName, mj, '0'), rawPAX("path", "f/000001"), rawMember("f/000001", body, '0')), capsule.ErrFormat},
		"PAX linkpath":                    {rawTar(rawMember(capsule.ManifestName, mj, '0'), rawPAX("linkpath", "/etc/passwd"), rawMember("f/000001", body, '0')), capsule.ErrFormat},
		"PAX record on the manifest": {func(w io.Writer) {
			tw := tar.NewWriter(w)
			h := reg(capsule.ManifestName, int64(len(mj)))
			h.Format, h.PAXRecords = tar.FormatPAX, map[string]string{"comment": "x"}
			tw.WriteHeader(h)
			tw.Write(mj)
			tw.Close()
		}, capsule.ErrFormat},
		"symlink member": {func(w io.Writer) {
			tw := tar.NewWriter(w)
			tw.WriteHeader(reg(capsule.ManifestName, int64(len(mj))))
			tw.Write(mj)
			tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: "f/000001", Linkname: "/etc/passwd", ModTime: time.Unix(0, 0)})
			tw.Close()
		}, capsule.ErrFormat},
		"hard link member": {func(w io.Writer) {
			tw := tar.NewWriter(w)
			tw.WriteHeader(reg(capsule.ManifestName, int64(len(mj))))
			tw.Write(mj)
			tw.WriteHeader(&tar.Header{Typeflag: tar.TypeLink, Name: "f/000001", Linkname: capsule.ManifestName, ModTime: time.Unix(0, 0)})
			tw.Close()
		}, capsule.ErrFormat},
		"directory member": {func(w io.Writer) {
			tw := tar.NewWriter(w)
			tw.WriteHeader(reg(capsule.ManifestName, int64(len(mj))))
			tw.Write(mj)
			tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "f/000001", ModTime: time.Unix(0, 0)})
			tw.Close()
		}, capsule.ErrFormat},
		"sparse member (PAX 1.0)": {rawTar(rawMember(capsule.ManifestName, mj, '0'),
			rawPAX("GNU.sparse.major", "1", "GNU.sparse.minor", "0", "GNU.sparse.name", "f/000001", "GNU.sparse.realsize", "1000000000"),
			rawMember("f/000001", body, '0')), capsule.ErrFormat},
		"sparse member (old GNU)": {rawTar(rawMember(capsule.ManifestName, mj, '0'), rawMember("f/000001", body, 'S')), capsule.ErrFormat},
		"FIFO member":             {rawTar(rawMember(capsule.ManifestName, mj, '0'), rawMember("f/000001", nil, '6')), capsule.ErrFormat},
		"device member":           {rawTar(rawMember(capsule.ManifestName, mj, '0'), rawMember("f/000001", nil, '3')), capsule.ErrFormat},
		"GNU long name": {func(w io.Writer) {
			tw := tar.NewWriter(w)
			h := reg(capsule.ManifestName, int64(len(mj)))
			h.Format = tar.FormatGNU
			tw.WriteHeader(h)
			tw.Write(mj)
			h2 := reg("f/"+strings.Repeat("0", 200)+"1", int64(len(body)))
			h2.Format = tar.FormatGNU
			tw.WriteHeader(h2)
			tw.Write(body)
			tw.Close()
		}, capsule.ErrFormat},
		"size mismatch": {func(w io.Writer) {
			tw := tar.NewWriter(w)
			tw.WriteHeader(reg(capsule.ManifestName, int64(len(mj))))
			tw.Write(mj)
			tw.WriteHeader(reg("f/000001", int64(len(body))+1))
			tw.Write(append(body, 'x'))
			tw.Close()
		}, capsule.ErrFormat},
		"content mismatch": {tarOf(mj, []byte("9876543210")), capsule.ErrVerify},
		"wrong member name": {func(w io.Writer) {
			tw := tar.NewWriter(w)
			tw.WriteHeader(reg(capsule.ManifestName, int64(len(mj))))
			tw.Write(mj)
			tw.WriteHeader(reg("f/000002", int64(len(body))))
			tw.Write(body)
			tw.Close()
		}, capsule.ErrFormat},
		"manifest not first": {func(w io.Writer) {
			tw := tar.NewWriter(w)
			tw.WriteHeader(reg("f/000001", int64(len(body))))
			tw.Write(body)
			tw.Close()
		}, capsule.ErrFormat},
		"missing member":  {tarOf(mj), capsule.ErrFormat},
		"trailing member": {tarOf(mj, body, body), capsule.ErrFormat},
		"trailing data": {func(w io.Writer) {
			tarOf(mj, body)(w)
			w.Write([]byte("junk after the archive"))
		}, capsule.ErrFormat},
		"unknown manifest field": {tarOf([]byte(strings.Replace(string(mj), `"format":1`, `"format":1,"extra":true`, 1)), body), capsule.ErrFormat},
		"manifest format 2":      {tarOf([]byte(strings.Replace(string(mj), `"format":1`, `"format":2`, 1)), body), capsule.ErrFormat},
		"two JSON values":        {tarOf(append(append([]byte(nil), mj...), []byte(" {}")...), body), capsule.ErrFormat},
		"manifest over 16 MiB": {func(w io.Writer) {
			tw := tar.NewWriter(w)
			tw.WriteHeader(reg(capsule.ManifestName, capsule.MaxManifestBytes+1))
			tw.Flush() // the reader must refuse at the header, before reading
		}, capsule.ErrTooLarge},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ct := craft(t, k, nil, c.build)
			n, err := extractCrafted(t, k, ct, big)
			if !errors.Is(err, c.want) {
				t.Fatalf("Extract = %v, want %v", err, c.want)
			}
			if name != "content mismatch" && name != "trailing member" && name != "trailing data" && n != 0 {
				t.Errorf("%d files staged", n)
			}
		})
	}
	t.Run("bad magic", func(t *testing.T) {
		eph, _ := age.GenerateX25519Identity()
		var buf bytes.Buffer
		aw, _ := age.Encrypt(&buf, k.vault.Recipient(), k.recovery.Recipient(), eph.Recipient())
		io.WriteString(aw, "PRECINTO-CAPSULE-9\n")
		aw.Close()
		if _, err := extractCrafted(t, k, buf.Bytes(), big); !errors.Is(err, capsule.ErrFormat) {
			t.Fatalf("Extract = %v", err)
		}
	})
	t.Run("zstd window above the limit", func(t *testing.T) {
		ct := craft(t, k, []zstd.EOption{zstd.WithWindowSize(128 << 20)}, func(w io.Writer) {
			w.Write(bytes.Repeat([]byte("abcdefgh"), 1<<20)) // 8 MiB: enough to need the window
		})
		if _, err := extractCrafted(t, k, ct, big); err == nil {
			t.Fatal("a 128 MiB window was accepted")
		}
	})
}

func TestEntryValidation(t *testing.T) {
	k := newKeys(t)
	body := []byte("x")
	for name, mut := range map[string]func(*capsule.Manifest){
		"escaping rel":       func(m *capsule.Manifest) { m.Files[0].Rel = "../.zshrc" },
		"absolute rel":       func(m *capsule.Manifest) { m.Files[0].Rel = "/etc/passwd" },
		"unclean rel":        func(m *capsule.Manifest) { m.Files[0].Rel = "projects/./P" },
		"empty rel":          func(m *capsule.Manifest) { m.Files[0].Rel = "" },
		"unknown base":       func(m *capsule.Manifest) { m.Files[0].Base = "home" },
		"negative size":      func(m *capsule.Manifest) { m.Files[0].Size = -1 },
		"bad sha":            func(m *capsule.Manifest) { m.Files[0].SHA256 = "XYZ" },
		"misnumbered member": func(m *capsule.Manifest) { m.Files[0].Name = "f/000002" },
		"dir with data": func(m *capsule.Manifest) {
			m.Files = append(m.Files, capsule.Entry{Base: capsule.BaseClaudeConfig, Rel: "d", Dir: true, Size: 3})
		},
		"bad blob": func(m *capsule.Manifest) {
			m.Files = append(m.Files, capsule.Entry{Base: capsule.BaseCodexHome, Rel: "state.sqlite", Blob: "not-a-key", SHA256: sha(nil)})
		},
		"duplicate rel": func(m *capsule.Manifest) {
			m.Files = append(m.Files, capsule.Entry{Base: capsule.BaseClaudeConfig, Rel: m.Files[0].Rel, Dir: true})
		},
		"entry below a file": func(m *capsule.Manifest) {
			m.Files = append(m.Files, capsule.Entry{Base: capsule.BaseClaudeConfig, Rel: m.Files[0].Rel + "/child", Dir: true})
		},
		"dir out of the bases": func(m *capsule.Manifest) {
			m.Files = append(m.Files, capsule.Entry{Base: "", Rel: "x", Dir: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			ct := craft(t, k, nil, tarOf(manifestJSON(t, mut, body), body))
			n, err := extractCrafted(t, k, ct, big)
			if !errors.Is(err, capsule.ErrUnsafe) && !errors.Is(err, capsule.ErrFormat) {
				t.Fatalf("Extract = %v, want ErrUnsafe or ErrFormat", err)
			}
			if n != 0 {
				t.Errorf("%d files staged", n)
			}
		})
	}
	// Blob and directory entries without members are accepted.
	ct := craft(t, k, nil, tarOf(manifestJSON(t, func(m *capsule.Manifest) {
		m.Files = append(m.Files,
			capsule.Entry{Base: capsule.BaseCodexHome, Rel: "state_5.sqlite", Blob: strings.Repeat("ab", 16), SHA256: sha(nil), Group: "state"},
			capsule.Entry{Base: capsule.BaseClaudeConfig, Rel: "empty-dir", Dir: true})
	}, body), body))
	if n, err := extractCrafted(t, k, ct, big); err != nil || n != 1 {
		t.Fatalf("blob/dir entries: %d %v", n, err)
	}
	if runtime.GOOS == "darwin" {
		ct := craft(t, k, nil, tarOf(manifestJSON(t, func(m *capsule.Manifest) {
			m.Files = append(m.Files, capsule.Entry{Base: capsule.BaseClaudeConfig, Rel: strings.ToUpper(m.Files[0].Rel), Dir: true})
		}, body), body))
		if _, err := extractCrafted(t, k, ct, big); !errors.Is(err, capsule.ErrUnsafe) {
			t.Errorf("case-folded duplicate on darwin: %v", err)
		}
	}
}

// TestDecompressionBounds: budgets are enforced from the manifest before
// anything is written, and oversized declarations are refused at the
// header, with bounded memory.
func TestDecompressionBounds(t *testing.T) {
	k := newKeys(t)
	zeros := make([]byte, 10<<20) // compresses to a few KiB
	ct := craft(t, k, nil, tarOf(manifestJSON(t, nil, zeros), zeros))
	if len(ct) > 64<<10 {
		t.Fatalf("bomb not compact: %d bytes", len(ct))
	}
	if n, err := extractCrafted(t, k, ct, capsule.Limits{MaxTotal: 1 << 20}); !errors.Is(err, capsule.ErrTooLarge) || n != 0 {
		t.Fatalf("10 MiB with a 1 MiB budget: %d %v", n, err)
	}
	// A manifest declaring 20 GiB never reaches the data.
	huge := manifestJSON(t, func(m *capsule.Manifest) { m.Files[0].Size = 20 << 30 }, []byte("x"))
	ct = craft(t, k, nil, tarOf(huge, []byte("x")))
	if _, err := extractCrafted(t, k, ct, capsule.Limits{MaxTotal: 1 << 30}); !errors.Is(err, capsule.ErrTooLarge) {
		t.Fatalf("20 GiB declaration: %v", err)
	}
	// Too many entries for the budget of files.
	many := manifestJSON(t, func(m *capsule.Manifest) {
		for i := 0; i < 1001; i++ {
			m.Files = append(m.Files, capsule.Entry{Base: capsule.BaseClaudeConfig, Rel: fmt.Sprintf("d/%d", i), Dir: true})
		}
	})
	ct = craft(t, k, nil, tarOf(many))
	if _, err := extractCrafted(t, k, ct, capsule.Limits{MaxTotal: 1, MaxFiles: 1000}); !errors.Is(err, capsule.ErrTooLarge) {
		t.Fatalf("1001 entries with MaxFiles 1000: %v", err)
	}
}

// TestMillionEntriesBoundedMemory: a manifest of 10^6 entries is larger than
// MaxManifestBytes and is refused at its tar header without being read.
func TestMillionEntriesBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a large crafted capsule")
	}
	k := newKeys(t)
	const n = 1_000_000
	entry := `{"base":"claude_config","rel":"d/%07d","dir":true,"mode":0,"mtime_ns":0,"size":0}`
	head := `{"format":1,"kind":"claude-session","harness":"claude-code","unit_key":"0123456789abcdef0123456789abcdef","unit_id":"u","vault_id":"v","root_ids":["v"],"gen":1,"parent":0,"lineage":"fresh","created_at":"2026-11-21T09:00:00Z","sealer":"t","recipients_fpr":"","files":[`
	size := int64(len(head)) + int64(n)*int64(len(fmt.Sprintf(entry, 0))) + int64(n-1) + 2
	ct := craft(t, k, nil, func(w io.Writer) {
		tw := tar.NewWriter(w)
		tw.WriteHeader(reg(capsule.ManifestName, size))
		io.WriteString(tw, head)
		for i := 0; i < n; i++ {
			if i > 0 {
				io.WriteString(tw, ",")
			}
			fmt.Fprintf(tw, entry, i)
		}
		io.WriteString(tw, "]}")
		tw.Close()
	})
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := extractCrafted(t, k, ct, big)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, capsule.ErrTooLarge) {
		t.Fatalf("10^6 entries: %v", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 48<<20 {
		t.Fatalf("allocated %d MiB while refusing a %d MiB manifest", grew>>20, size>>20)
	}
}
