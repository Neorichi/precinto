//go:build crossgroup

package capsule_test

import (
	"path/filepath"
	"testing"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/sweep/capslog"
)

// TestSealedProvenanceRoundTrip needs G4's capslog: a committed capsule's
// Sealed fields map onto a capsule-log entry that Lookup finds by the
// header hash ReadHeader computes (I14, D8, D39).
func TestSealedProvenanceRoundTrip(t *testing.T) {
	x := sealWithVault(t)
	rel, err := filepath.Rel(x.home.Layout.CapsulesDir, x.s.Path)
	if err != nil {
		t.Fatal(err)
	}
	log := capslog.Open(x.home.Layout.CapsuleLog)
	m := x.s.Manifest
	e := capslog.Entry{
		V: capslog.Version, Path: filepath.ToSlash(rel), SHA256: x.s.SHA256, HeaderSHA256: x.s.HeaderSHA256, Size: x.s.Size,
		Kind: string(m.Kind), Harness: m.Harness, Unit: m.UnitKey, VaultID: m.VaultID, RootIDs: m.RootIDs,
		Gen: m.Gen, Parent: m.Parent, Lineage: string(m.Lineage), SealedAt: m.CreatedAt, RecipientsFpr: m.RecipientsFpr,
		Files: len(m.Files), Bytes: m.Files[0].Size,
	}
	if err := log.Append(e); err != nil {
		t.Fatal(err)
	}
	_, hsum, err := capsule.ReadHeader(x.out, x.s.Name)
	if err != nil {
		t.Fatal(err)
	}
	got, err := log.Lookup(e.Path, hsum)
	if err != nil || got.SHA256 != x.s.SHA256 || got.Unit != m.UnitKey {
		t.Fatalf("Lookup = %+v %v", got, err)
	}
	if sum, size, err := capsule.HashFile(x.out, x.s.Name); err != nil || sum != got.SHA256 || size != got.Size {
		t.Fatalf("HashFile disagrees with the log: %v", err)
	}
}
