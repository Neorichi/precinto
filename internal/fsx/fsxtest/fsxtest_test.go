//go:build failpoints

package fsxtest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/fsx/failpoint"
	"github.com/Neorichi/precinto/internal/fsx/fsxtest"
)

func realTemp(t *testing.T) string {
	t.Helper()
	d, err := fsx.Realpath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func read(t *testing.T, p string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), true
}

// unsyncedRename renames old to new with the operation reported like fsx
// does, but without the directory fsync fsx always adds.
func unsyncedRename(t *testing.T, old, new string) {
	t.Helper()
	failpoint.NoteFS(failpoint.FSOp{Kind: failpoint.FSRename, Path: old, Target: new})
	if err := os.Rename(old, new); err != nil {
		t.Fatal(err)
	}
	failpoint.NoteFS(failpoint.FSOp{Kind: failpoint.FSRename, Path: old, Target: new, Done: true})
}

func TestSyncedAndUnsyncedOperations(t *testing.T) {
	dir := realTemp(t)
	// State before the recording counts as durable.
	if err := os.WriteFile(filepath.Join(dir, "old.tmp"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gone"), []byte("gone"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := fsxtest.Record(t)
	d, err := fsx.OpenBase(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// A synced rename of synced data: durable (fsx fsyncs the directory).
	f, rel, err := d.CreateTemp("", ".synced-*")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("synced")
	if err := fsx.FullSync(f); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := d.Rename(rel, "synced", fsx.NoReplace); err != nil {
		t.Fatal(err)
	}
	// Data written after the last FullSync.
	g, _, err := d.CreateTemp("", "data")
	if err != nil {
		t.Fatal(err)
	}
	g.WriteString("first")
	if err := fsx.FullSync(g); err != nil {
		t.Fatal(err)
	}
	g.WriteString("+second")
	g.Close()
	if err := d.Sync(); err != nil { // the name "data" is durable
		t.Fatal(err)
	}
	// An unsynced rename (after the last directory fsync).
	unsyncedRename(t, filepath.Join(dir, "old.tmp"), filepath.Join(dir, "renamed"))
	// A file created and never synced, its directory never synced either.
	h, _, err := d.CreateTemp("", "fresh")
	if err != nil {
		t.Fatal(err)
	}
	h.WriteString("fresh")
	h.Close()
	// An unlink without a directory fsync.
	if err := d.Remove("gone"); err != nil {
		t.Fatal(err)
	}

	images := rec.Images(t, dir, 8)
	if len(images) < 2 {
		t.Fatalf("%d images", len(images))
	}
	strict, full := images[0], images[1]
	for _, img := range images {
		if got, ok := read(t, filepath.Join(img, "synced")); !ok || got != "synced" {
			t.Errorf("%s: synced rename missing or wrong (%q, %v)", filepath.Base(img), got, ok)
		}
		if _, ok := read(t, filepath.Join(img, rel)); ok {
			t.Errorf("%s: the synced temporary came back", filepath.Base(img))
		}
		// The synced "first", possibly extended by a (torn) prefix of the
		// unsynced "+second".
		if got, ok := read(t, filepath.Join(img, "data")); !ok || !strings.HasPrefix(got, "first") || !strings.HasPrefix("first+second", got) {
			t.Errorf("%s: data = %q %v", filepath.Base(img), got, ok)
		}
	}
	if _, ok := read(t, filepath.Join(strict, "renamed")); ok {
		t.Error("strict image: the unsynced rename persisted")
	}
	if got, ok := read(t, filepath.Join(strict, "old.tmp")); !ok || got != "old" {
		t.Errorf("strict image: old name %q %v", got, ok)
	}
	if got, _ := read(t, filepath.Join(strict, "data")); got != "first" {
		t.Errorf("strict image: unsynced data kept: %q", got)
	}
	if _, ok := read(t, filepath.Join(strict, "fresh")); ok {
		t.Error("strict image: an unsynced create persisted")
	}
	if got, ok := read(t, filepath.Join(strict, "gone")); !ok || got != "gone" {
		t.Errorf("strict image: the unsynced unlink persisted (%q %v)", got, ok)
	}
	if got, ok := read(t, filepath.Join(full, "renamed")); !ok || got != "old" {
		t.Errorf("full image: renamed %q %v", got, ok)
	}
	if got, _ := read(t, filepath.Join(full, "data")); got != "first+second" {
		t.Errorf("full image: data %q", got)
	}
	if _, ok := read(t, filepath.Join(full, "gone")); ok {
		t.Error("full image: the unlinked file is back")
	}
	// Some image differs from both extremes only by chance; at least the
	// unsynced rename is absent from one image and present in another.
	absent, present := false, false
	for _, img := range images {
		if _, ok := read(t, filepath.Join(img, "renamed")); ok {
			present = true
		} else {
			absent = true
		}
	}
	if !absent || !present {
		t.Fatalf("unsynced rename: absent in some image %v, present in some image %v", absent, present)
	}
}

// A durable operation pulls in the non-durable ones it depends on: a file
// created in a never-synced subdirectory and then renamed into a synced
// directory is present in every image.
func TestDependenciesOfDurableOperations(t *testing.T) {
	dir := realTemp(t)
	rec := fsxtest.Record(t)
	d, err := fsx.OpenBase(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	f, rel, err := d.CreateTemp("work", ".x-*") // creates "work" (not synced)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("payload")
	if err := fsx.FullSync(f); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := d.Rename(rel, "final", fsx.NoReplace); err != nil {
		t.Fatal(err)
	}
	for _, img := range rec.Images(t, dir, 6) {
		if got, ok := read(t, filepath.Join(img, "final")); !ok || got != "payload" {
			t.Errorf("%s: final = %q %v", filepath.Base(img), got, ok)
		}
	}
}

func TestImagesOutsideTheRecording(t *testing.T) {
	dir := realTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "keep"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := fsxtest.Record(t)
	imgs := rec.Images(t, dir, 3)
	if len(imgs) != 1 {
		t.Fatalf("no operations: %d images, want 1 (identical images are merged)", len(imgs))
	}
	if got, ok := read(t, filepath.Join(imgs[0], "keep")); !ok || got != "k" {
		t.Fatalf("keep = %q %v", got, ok)
	}
}

// An append that was never synced may be cut by the power loss: random
// images keep the durable content, the whole append, or a torn prefix of
// it, and the same test always gets the same images.
func TestTornAppendsAndDeterminism(t *testing.T) {
	dir := realTemp(t)
	rec := fsxtest.Record(t)
	d, err := fsx.OpenBase(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	f, _, err := d.CreateTemp("", "capsules.log")
	if err != nil {
		t.Fatal(err)
	}
	const first, second = "first record\n", "second record, written but never synced\n"
	f.WriteString(first)
	if err := fsx.FullSync(f); err != nil {
		t.Fatal(err)
	}
	if err := d.Sync(); err != nil { // the name is durable
		t.Fatal(err)
	}
	f.WriteString(second)
	f.Close()

	images := rec.Images(t, dir, 24)
	if len(images) < 3 {
		t.Fatalf("%d images", len(images))
	}
	if got, _ := read(t, filepath.Join(images[0], "capsules.log")); got != first {
		t.Errorf("strict image: %q", got)
	}
	if got, _ := read(t, filepath.Join(images[1], "capsules.log")); got != first+second {
		t.Errorf("full image: %q", got)
	}
	torn := false
	var contents []string
	for _, img := range images {
		got, ok := read(t, filepath.Join(img, "capsules.log"))
		if !ok || !strings.HasPrefix(got, first) || !strings.HasPrefix(first+second, got) {
			t.Fatalf("%s: %q is neither the durable content nor a prefix of the append", filepath.Base(img), got)
		}
		torn = torn || len(got) > len(first) && len(got) < len(first+second)
		contents = append(contents, got)
	}
	if !torn {
		t.Error("no image keeps a torn prefix of the unsynced append")
	}
	for i, img := range rec.Images(t, dir, 24) {
		if got, _ := read(t, filepath.Join(img, "capsules.log")); i >= len(contents) || got != contents[i] {
			t.Fatalf("image %d differs between two calls in one test: %q", i, got)
		}
	}
}

// A lock file TryLock creates is a create like any other: without a
// directory fsync it is absent from the strict image.
func TestLockFileCreationIsRecorded(t *testing.T) {
	dir := realTemp(t)
	rec := fsxtest.Record(t)
	l, err := fsx.TryLock(filepath.Join(dir, "unit.lock"), false)
	if err != nil {
		t.Fatal(err)
	}
	l.Unlock()
	images := rec.Images(t, dir, 2)
	if len(images) != 2 {
		t.Fatalf("%d images", len(images))
	}
	if _, ok := read(t, filepath.Join(images[0], "unit.lock")); ok {
		t.Error("strict image: an unsynced lock file creation persisted")
	}
	if _, ok := read(t, filepath.Join(images[1], "unit.lock")); !ok {
		t.Error("full image: the lock file is missing")
	}
}

// fsx's own writers open their descriptors write-only (WriteFileAtomic,
// fsx.AppendLine, Dir.AppendLine): their syncs are recorded all the same,
// and what they made durable is in every image.
func TestWriteOnlyWritersAreRecorded(t *testing.T) {
	dir := realTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "journal.json"), []byte(`{"v":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := fsxtest.Record(t)
	if err := fsx.WriteFileAtomic(filepath.Join(dir, "journal.json"), []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fsx.AppendLine(filepath.Join(dir, "capsules.log"), []byte("entry one")); err != nil {
		t.Fatal(err)
	}
	d, err := fsx.OpenBase(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.AppendLine("history.jsonl", []byte(`{"line":1}`)); err != nil {
		t.Fatal(err)
	}
	images := rec.Images(t, dir, 6)
	if len(images) == 0 {
		t.Fatal("no images")
	}
	for _, img := range images {
		for name, want := range map[string]string{"journal.json": `{"v":1}`, "capsules.log": "entry one\n", "history.jsonl": "{\"line\":1}\n"} {
			if got, ok := read(t, filepath.Join(img, name)); !ok || got != want {
				t.Errorf("%s: %s = %q %v, want %q (synced and dir-synced: durable)", filepath.Base(img), name, got, ok, want)
			}
		}
	}
}
