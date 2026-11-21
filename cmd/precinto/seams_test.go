package main

import (
	"testing"

	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/ui"
)

// TestMarkerMirrorsCatalog keeps the marker written by internal/sweep and
// the catalog text of internal/ui byte-identical (SPEC §8.4, §16.3).
func TestMarkerMirrorsCatalog(t *testing.T) {
	const unit = "0123456789abcdef0123456789abcdef"
	got := string(sweep.MarkerText(unit))
	want := ui.Format(ui.MsgNoteMarker, ui.Vars{Unit: unit}) + "\n"
	if got != want {
		t.Fatalf("sweep.MarkerText = %q, ui C11.marker = %q", got, want)
	}
}
