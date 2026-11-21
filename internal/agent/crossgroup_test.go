//go:build crossgroup

package agent_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/agent/agenttest"
	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

type recoveryUI struct{ key string }

func (u recoveryUI) Display(string) error { return nil }
func (u recoveryUI) Secret(string) (*memguard.LockedBuffer, error) {
	return memguard.NewBufferFromBytes([]byte(u.key)), nil
}
func (u recoveryUI) Confirm(string, string, string) (bool, error) { return true, nil }

// sealNote seals h.Root/notes.md to vault rootID and logs it; it returns
// the capsule path relative to CapsulesDir.
func sealNote(t *testing.T, h *testkit.Home, fx *vaulttest.Fixture, rootID string) string {
	t.Helper()
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(h.Root, "notes.md"), []byte(testkit.Marker(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recips, fpr, err := fx.Store.Recipients(rootID)
	if err != nil {
		t.Fatal(err)
	}
	root, err := fsx.OpenBase(h.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	snap, err := root.Lstat("notes.md")
	if err != nil {
		t.Fatal(err)
	}
	caps, err := fsx.OpenBase(h.Layout.CapsulesDir)
	if err != nil {
		t.Fatal(err)
	}
	defer caps.Close()
	unit := "0123456789abcdef0123456789abcdef"
	out, err := caps.OpenDir("md/"+unit, true)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	sealed, err := capsule.Seal(ctx, capsule.SealRequest{
		Manifest: capsule.Manifest{Format: capsule.FormatVersion, Kind: capsule.KindMarkdown, Harness: "md", UnitKey: unit,
			UnitID: "notes.md", VaultID: rootID, RootIDs: []string{rootID}, Gen: 1, Lineage: capsule.LineageFresh,
			CreatedAt: h.Clock.Now(), Sealer: "precinto test", RecipientsFpr: fpr},
		Inputs:     []capsule.Input{{Base: capsule.BaseRoot, Dir: root, Rel: "notes.md", Path: filepath.Join(h.Root, "notes.md"), Snap: snap}},
		Recipients: recips, Out: out, Name: capsule.GenName(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	rel := "md/" + unit + "/" + capsule.GenName(1)
	if err := capslog.Open(h.Layout.CapsuleLog).Append(capslog.Entry{V: capslog.Version, Path: rel, SHA256: sealed.SHA256,
		HeaderSHA256: sealed.HeaderSHA256, Size: sealed.Size, Kind: string(capsule.KindMarkdown), Harness: "md", Unit: unit,
		VaultID: rootID, RootIDs: []string{rootID}, Gen: 1, Lineage: string(capsule.LineageFresh), SealedAt: h.Clock.Now(),
		RecipientsFpr: fpr, Files: 1}); err != nil {
		t.Fatal(err)
	}
	return rel
}

// TestKeyReleaseRealCapsule is D39 end to end with G1/G4 code: a logged
// capsule's file key is released only while its folder is unlocked, and
// it opens the capsule's manifest.
func TestKeyReleaseRealCapsule(t *testing.T) {
	h := testkit.NewHome(t)
	fx := vaulttest.New(t, h.Layout.Base, "root-acme")
	rel := sealNote(t, h, fx, "root-acme")
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	c := a.Dial(t)
	ctx := context.Background()
	refs := []ipc.CapsuleRef{{Path: rel}, {Path: "md/ffffffffffffffffffffffffffffffff/g000001.pcap"}}
	_, resp, err := c.Keys(ctx, ipc.KeysReq{Capsules: refs, Purpose: ipc.PurposeRestore})
	if err != nil || len(resp.Granted) != 0 || resp.Denied[rel] != ipc.CodeLocked {
		t.Fatalf("locked folder: %+v %v", resp, err)
	}
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true, Factor: "recovery"}, recoveryUI{key: fx.Recovery.String()}); err != nil {
		t.Fatal(err)
	}
	ks, resp, err := c.Keys(ctx, ipc.KeysReq{Capsules: refs, Purpose: ipc.PurposeRestore})
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Destroy()
	if len(resp.Granted) != 1 || resp.Denied[refs[1].Path] != ipc.CodeNotLogged {
		t.Fatalf("unlocked: %+v", resp)
	}
	key, ok := ks.Key(rel)
	if !ok {
		t.Fatal("no key")
	}
	f, err := os.Open(filepath.Join(h.Layout.CapsulesDir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := capsule.OpenManifest(f, key.Bytes())
	if err != nil || m.UnitID != "notes.md" || m.VaultID != "root-acme" {
		t.Fatalf("manifest = %+v %v", m, err)
	}
	if _, err := c.Lock(ctx, ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	if _, resp, _ := c.Keys(ctx, ipc.KeysReq{Capsules: refs[:1], Purpose: ipc.PurposeRestore}); len(resp.Granted) != 0 {
		t.Fatal("key released after lock")
	}
}

// TestPinnedPolicyAcrossRestartReal is SEC-23 with the real keyring MACs.
func TestPinnedPolicyAcrossRestartReal(t *testing.T) {
	h := testkit.NewHome(t)
	fx := vaulttest.New(t, h.Layout.Base, "root-acme")
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	c := a.Dial(t)
	ctx := context.Background()
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true, Factor: "recovery"}, recoveryUI{key: fx.Recovery.String()}); err != nil {
		t.Fatal(err)
	}
	pinned, ok, err := config.LoadPinned(h.Layout.PolicyPinned)
	if err != nil || !ok || pinned.MACs["root-acme"] == "" {
		t.Fatalf("pinned = %+v %v %v", pinned, ok, err)
	}
	a.Stop()
	weak := h.Cfg
	weak.Policy.IdleSoft = config.Duration(10 * time.Hour)
	if err := config.Save(h.Layout.ConfigFile, weak); err != nil {
		t.Fatal(err)
	}
	a = agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	c = a.Dial(t)
	st, err := c.Status(ctx)
	if err != nil || len(st.PendingPolicy) == 0 {
		t.Fatalf("pending after restart = %+v %v", st.PendingPolicy, err)
	}
	if slices.ContainsFunc(st.Attention, func(a ipc.Attention) bool { return a.Code == ipc.AttnPolicyTampered }) {
		t.Fatal("genuine pin reported tampered")
	}
}
