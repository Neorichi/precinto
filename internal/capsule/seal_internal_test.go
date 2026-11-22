package capsule

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/precinto/precinto/internal/fsx"
)

// TestSealRemovesTheTemporaryOnErrHeader covers the ErrHeader error path of
// Seal (CC-01): the temporary is rewritten, after it was written, with the
// very payload Seal wrote (so the ephemeral round trip succeeds) but with a
// fourth stanza in its header. Seal must fail with ErrHeader, remove the
// temporary and leave the plaintext alone.
func TestSealRemovesTheTemporaryOnErrHeader(t *testing.T) {
	var eph *age.X25519Identity
	old := newEphemeral
	newEphemeral = func() (*age.X25519Identity, error) {
		id, err := age.GenerateX25519Identity()
		eph = id
		return id, err
	}
	t.Cleanup(func() { newEphemeral = old })

	dir, err := fsx.Realpath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, outP := filepath.Join(dir, "claude"), filepath.Join(dir, "capsules")
	for _, d := range []string{root, outP} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	plain := bytes.Repeat([]byte("{\"type\":\"user\"}\n"), 100)
	if err := os.WriteFile(filepath.Join(root, "s.jsonl"), plain, 0o600); err != nil {
		t.Fatal(err)
	}
	base, err := fsx.OpenBase(root)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	out, err := fsx.OpenBase(outP)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	snap, err := base.Lstat("s.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	in := []Input{{Base: BaseClaudeConfig, Dir: base, Rel: "s.jsonl", Snap: snap}}
	var ids [3]*age.X25519Identity
	for i := range ids {
		if ids[i], err = age.GenerateX25519Identity(); err != nil {
			t.Fatal(err)
		}
	}
	vault, recovery, extra := ids[0], ids[1], ids[2]
	rewritten := false
	_, err = Seal(context.Background(), SealRequest{
		Manifest: Manifest{Kind: KindClaudeSession, Harness: "claude-code", UnitKey: "0123456789abcdef0123456789abcdef",
			UnitID: "00000000-0000-4000-8000-000000000001", VaultID: "root-acme", RootIDs: []string{"root-acme"}, Gen: 1, Lineage: LineageFresh},
		Inputs: in, Recipients: []age.Recipient{vault.Recipient(), recovery.Recipient()}, Out: out, Name: "g000001.pcap",
		OnPhase: func(p Phase, s *Sealed) error {
			if p != PhaseTmpWritten {
				return nil
			}
			mj, err := json.Marshal(s.Manifest)
			if err != nil {
				return err
			}
			f, err := os.OpenFile(filepath.Join(outP, TmpName("g000001.pcap")), os.O_WRONLY|os.O_TRUNC, 0)
			if err != nil {
				return err
			}
			defer f.Close()
			rewritten = true
			return writePayload(context.Background(), f, mj, in, s.Manifest.Files, s.Snaps,
				vault.Recipient(), recovery.Recipient(), eph.Recipient(), extra.Recipient())
		},
	})
	if !rewritten {
		t.Fatal("the temporary was never rewritten")
	}
	if !errors.Is(err, ErrHeader) {
		t.Fatalf("Seal = %v, want ErrHeader", err)
	}
	if ents, _ := os.ReadDir(outP); len(ents) != 0 {
		t.Fatalf("capsule directory holds %d entries after ErrHeader, want none", len(ents))
	}
	if b, err := os.ReadFile(filepath.Join(root, "s.jsonl")); err != nil || !bytes.Equal(b, plain) {
		t.Fatalf("plaintext changed or lost: %v", err)
	}
}

// D13: pass 2 re-hashes every source and refuses one whose bytes are not
// pass 1's although its identity did not change: on Linux before
// multigrain timestamps a same-size rewrite in the clock tick of the last
// change keeps mtime and ctime, so only the hash shows it. The pass-1 hash
// is made wrong to reach that check on every platform (on darwin the
// identity check at the reopen catches every real rewrite first).
func TestStreamInputRefusesAnotherHash(t *testing.T) {
	dir, err := fsx.Realpath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("{\"a\":1}\n")
	if err := os.WriteFile(filepath.Join(dir, "s.jsonl"), plain, 0o600); err != nil {
		t.Fatal(err)
	}
	base, err := fsx.OpenBase(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	snap, err := base.Lstat("s.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	in := Input{Base: BaseClaudeConfig, Dir: base, Rel: "s.jsonl", Snap: snap}
	e := Entry{Name: "f/000001", Base: BaseClaudeConfig, Rel: "s.jsonl", Size: snap.Size, SHA256: strings.Repeat("0", 64)}
	if err := streamInput(context.Background(), tar.NewWriter(io.Discard), in, e, snap); !errors.Is(err, ErrChanged) {
		t.Fatalf("streamInput with another pass-1 hash = %v, want ErrChanged", err)
	}
	sum := sha256.Sum256(plain)
	e.SHA256 = hex.EncodeToString(sum[:])
	if err := streamInput(context.Background(), tar.NewWriter(io.Discard), in, e, snap); err != nil {
		t.Fatalf("streamInput with the pass-1 hash = %v", err)
	}
}
