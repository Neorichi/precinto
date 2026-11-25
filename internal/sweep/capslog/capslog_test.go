package capslog_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/sweep/capslog"
)

var t0 = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

func entry(unit string, gen uint64) capslog.Entry {
	return capslog.Entry{
		Path:         fmt.Sprintf("claude-code/%s/g%06d.pcap", unit, gen),
		SHA256:       fmt.Sprintf("%064x", gen),
		HeaderSHA256: fmt.Sprintf("%064x", gen+1000),
		Size:         int64(100 * gen),
		Kind:         "claude-session",
		Harness:      "claude-code",
		Unit:         unit,
		VaultID:      "root-acme",
		RootIDs:      []string{"root-acme"},
		Gen:          gen,
		Lineage:      "fresh",
		SealedAt:     t0.Add(time.Duration(gen) * time.Minute),
		Files:        3,
		Bytes:        42,
	}
}

func newLog(t *testing.T) *capslog.Log {
	t.Helper()
	return capslog.Open(filepath.Join(t.TempDir(), "capsules.log"))
}

func TestAppendAndLookupByHeaderHash(t *testing.T) {
	l := newLog(t)
	e := entry("u1", 1)
	if err := l.Append(e); err != nil {
		t.Fatal(err)
	}
	got, err := l.Lookup(e.Path, e.HeaderSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if got.V != capslog.Version || got.Unit != "u1" || got.Gen != 1 || len(got.RootIDs) != 1 {
		t.Fatalf("entry %+v", got)
	}
	if _, err := l.Lookup(e.Path, strings.Repeat("0", 64)); !errors.Is(err, capslog.ErrNotLogged) {
		t.Fatalf("wrong header: %v", err)
	}
	if _, err := l.Lookup("claude-code/u1/g000002.pcap", e.HeaderSHA256); !errors.Is(err, capslog.ErrNotLogged) {
		t.Fatalf("wrong path: %v", err)
	}
	if _, err := l.Lookup(e.Path, ""); !errors.Is(err, capslog.ErrNotLogged) {
		t.Fatalf("empty header: %v", err)
	}
	if fi, err := os.Stat(l.Path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("log mode %v %v", fi, err)
	}
}

func TestDeletedEntriesAreFolded(t *testing.T) {
	l := newLog(t)
	for g := uint64(1); g <= 3; g++ {
		if err := l.Append(entry("u1", g)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Append(entry("u2", 1)); err != nil {
		t.Fatal(err)
	}
	if err := l.MarkDeleted(entry("u1", 2).Path, t0); err != nil {
		t.Fatal(err)
	}
	u, err := l.Unit("u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(u) != 2 || u[0].Gen != 1 || u[1].Gen != 3 {
		t.Fatalf("unit after delete: %+v", u)
	}
	if _, err := l.Lookup(entry("u1", 2).Path, entry("u1", 2).HeaderSHA256); !errors.Is(err, capslog.ErrNotLogged) {
		t.Fatalf("deleted entry still looked up: %v", err)
	}
	all, _ := l.All()
	if len(all) != 3 {
		t.Fatalf("all: %d entries", len(all))
	}
}

func TestUnitIsOrderedByGen(t *testing.T) {
	l := newLog(t)
	for _, g := range []uint64{5, 2, 9, 1} {
		if err := l.Append(entry("u1", g)); err != nil {
			t.Fatal(err)
		}
	}
	u, _ := l.Unit("u1")
	var gens []uint64
	for _, e := range u {
		gens = append(gens, e.Gen)
	}
	if fmt.Sprint(gens) != "[1 2 5 9]" {
		t.Fatalf("gens %v", gens)
	}
}

func TestTornLastLineIgnoredAndRepairedOnAppend(t *testing.T) {
	l := newLog(t)
	if err := l.Append(entry("u1", 1)); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(l.Path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"v":1,"path":"claude-code/u1/g000002.pcap","header_sha`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	all, err := l.All()
	if err != nil || len(all) != 1 {
		t.Fatalf("torn line not ignored: %v %v", all, err)
	}
	// The next append must not be swallowed by the torn fragment.
	if err := l.Append(entry("u1", 3)); err != nil {
		t.Fatal(err)
	}
	u, _ := l.Unit("u1")
	if len(u) != 2 || u[1].Gen != 3 {
		t.Fatalf("entry after a torn line lost: %+v", u)
	}
}

func TestGarbageLinesAreIgnored(t *testing.T) {
	l := newLog(t)
	if err := os.WriteFile(l.Path, []byte("not json\n\n{\"v\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(entry("u1", 1)); err != nil {
		t.Fatal(err)
	}
	all, err := l.All()
	if err != nil || len(all) != 1 || all[0].Unit != "u1" {
		t.Fatalf("all %+v %v", all, err)
	}
}

func TestDuplicateAppendCountsOnce(t *testing.T) {
	l := newLog(t)
	e := entry("u1", 7)
	for i := 0; i < 2; i++ {
		if err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	u, _ := l.Unit("u1")
	if len(u) != 1 {
		t.Fatalf("re-append produced %d entries (SEAL-7: exactly one)", len(u))
	}
}

func TestCompactDropsDeletedEntries(t *testing.T) {
	l := newLog(t)
	for g := uint64(1); g <= 4; g++ {
		if err := l.Append(entry("u1", g)); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.MarkDeleted(entry("u1", 1).Path, t0)
	_ = l.MarkDeleted(entry("u1", 3).Path, t0)
	before, _ := l.All()
	if err := l.Compact(); err != nil {
		t.Fatal(err)
	}
	after, err := l.All()
	if err != nil || len(after) != len(before) {
		t.Fatalf("compact changed live entries: %v → %v (%v)", before, after, err)
	}
	b, _ := os.ReadFile(l.Path)
	if strings.Contains(string(b), `"deleted":true`) || strings.Count(string(b), "\n") != 2 {
		t.Fatalf("compacted log:\n%s", b)
	}
	if err := l.Append(entry("u1", 5)); err != nil {
		t.Fatal(err)
	}
	if u, _ := l.Unit("u1"); len(u) != 3 {
		t.Fatalf("append after compact: %+v", u)
	}
}

func TestConcurrentAppendsAndCompactLoseNothing(t *testing.T) {
	l := newLog(t)
	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(g uint64) {
			defer wg.Done()
			if err := l.Append(entry("u1", g)); err != nil {
				t.Error(err)
			}
			if g%10 == 0 {
				if err := l.Compact(); err != nil {
					t.Error(err)
				}
			}
		}(uint64(i + 1))
	}
	wg.Wait()
	if u, _ := l.Unit("u1"); len(u) != n {
		t.Fatalf("%d of %d entries survived concurrent appends", len(u), n)
	}
}

func TestSymlinkedLogIsRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.log")
	_ = os.WriteFile(target, nil, 0o600)
	link := filepath.Join(dir, "capsules.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	l := capslog.Open(link)
	if _, err := l.All(); err == nil {
		t.Fatal("read through a symlink")
	}
	if err := l.Append(entry("u1", 1)); err == nil {
		t.Fatal("appended through a symlink")
	}
}

func TestCacheSeesAppendsFromAnotherHandle(t *testing.T) {
	l := newLog(t)
	if err := l.Append(entry("u1", 1)); err != nil {
		t.Fatal(err)
	}
	if u, _ := l.Unit("u1"); len(u) != 1 {
		t.Fatal("first read")
	}
	other := capslog.Open(l.Path)
	if err := other.Append(entry("u1", 2)); err != nil {
		t.Fatal(err)
	}
	u, _ := l.Unit("u1")
	if len(u) != 2 {
		t.Fatalf("stale cache: %+v", u)
	}
	u[0].RootIDs[0] = "mutated"
	again, _ := l.Unit("u1")
	if again[0].RootIDs[0] != "root-acme" {
		t.Fatal("callers can corrupt the cache")
	}
}

func TestMissingLogIsEmptyAndEntryNeedsAPath(t *testing.T) {
	l := newLog(t)
	if all, err := l.All(); err != nil || len(all) != 0 {
		t.Fatalf("missing log: %v %v", all, err)
	}
	if err := l.Append(capslog.Entry{Unit: "u"}); err == nil {
		t.Fatal("entry without a path accepted")
	}
}
