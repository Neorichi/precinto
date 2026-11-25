package platform

import (
	"os"
	"path/filepath"
	"testing"
)

// Boot ids as the kernel prints them (fixture form).
const (
	bootA = "00000000-0000-4000-8000-00000000000a"
	bootB = "00000000-0000-4000-8000-00000000000b"
)

// resetFloor forgets this process's readings (a new process).
func resetFloor(t *testing.T) {
	t.Helper()
	floor.mu.Lock()
	floor.bootID, floor.low = "", 0
	floor.mu.Unlock()
	t.Cleanup(func() {
		floor.mu.Lock()
		floor.bootID, floor.low = "", 0
		floor.mu.Unlock()
	})
}

// privateRunDir returns a run directory as the daemon keeps it (0700).
func privateRunDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBootTimeFileFormat(t *testing.T) {
	b, err := formatBootTime(bootA, 1_732_000_000_000_000)
	if err != nil || string(b) != bootA+" 1732000000000000\n" {
		t.Fatalf("formatBootTime = %q, %v", b, err)
	}
	if id, us, ok := parseBootTime(b); !ok || id != bootA || us != 1_732_000_000_000_000 {
		t.Fatalf("parseBootTime = %q, %d, %v", id, us, ok)
	}
	for _, bad := range []string{
		"", bootA, bootA + " ", bootA + " 0", bootA + " -5", bootA + " 12x", bootA + "  12", bootA + " 012",
		"00000000-0000-4000-8000-00000000000A 12", "not-a-boot-id 12", bootA + " 12\n\n", bootA + " 99999999999999999999",
	} {
		if _, _, ok := parseBootTime([]byte(bad)); ok {
			t.Errorf("parseBootTime(%q) accepted", bad)
		}
	}
	if _, err := formatBootTime("short", 5); err == nil {
		t.Error("a malformed boot id was formatted")
	}
	if _, err := formatBootTime(bootA, 0); err == nil {
		t.Error("a zero boot time was formatted")
	}
}

func TestEarliest(t *testing.T) {
	for _, c := range []struct {
		vs   []int64
		want int64
	}{
		{[]int64{5, 3, 9}, 3},
		{[]int64{5, 0, 9}, 5},
		{[]int64{0, -1}, 0},
		{[]int64{7}, 7},
		{nil, 0},
	} {
		if got := earliest(c.vs...); got != c.want {
			t.Errorf("earliest(%v) = %d, want %d", c.vs, got, c.want)
		}
	}
}

// D157: the floor is the smallest btime this boot has shown, kept in the
// process and in the run directory, and only ever lowered.
func TestBootFloor(t *testing.T) {
	resetFloor(t)
	dir := privateRunDir(t)
	file := filepath.Join(dir, bootTimeName)
	const h8 = int64(8 * 3600 * 1_000_000)
	const bt = int64(1_732_000_000_000_000)

	// The daemon notes btime before the host sleeps: recorded.
	if got := floor.lowest(bootA, bt, dir, true); got != bt {
		t.Fatalf("first reading %d", got)
	}
	if rec, ok := readBootTime(file, bootA); !ok || rec != bt {
		t.Fatalf("recorded %d, %v", rec, ok)
	}
	// After the sleep btime is 8 h later: the floor stays.
	if got := floor.lowest(bootA, bt+h8, dir, true); got != bt {
		t.Fatalf("after the jump %d, want %d", got, bt)
	}
	// A new process (a sealing worker) finds it in the run directory.
	resetFloor(t)
	if got := floor.lowest(bootA, bt+h8, dir, true); got != bt {
		t.Fatalf("a new process sees %d, want the recorded %d", got, bt)
	}
	// A new process without the run directory knows only its reading.
	resetFloor(t)
	if got := floor.lowest(bootA, bt+h8, "", true); got != bt+h8 {
		t.Fatalf("no run directory: %d", got)
	}
	// A lower reading (a clock step back) lowers the record.
	resetFloor(t)
	if got := floor.lowest(bootA, bt-1_000_000, dir, true); got != bt-1_000_000 {
		t.Fatalf("a step back: %d", got)
	}
	if rec, _ := readBootTime(file, bootA); rec != bt-1_000_000 {
		t.Fatalf("record after a step back: %d", rec)
	}
	// A later record (stale or forged) never raises the floor.
	if err := writeBootTime(dir, bootA, bt+h8); err != nil {
		t.Fatal(err)
	}
	resetFloor(t)
	if got := floor.lowest(bootA, bt, dir, true); got != bt {
		t.Fatalf("a later record raised the floor: %d", got)
	}
	if rec, _ := readBootTime(file, bootA); rec != bt {
		t.Fatalf("the later record was not replaced: %d", rec)
	}
	// Another boot's record is ignored and replaced.
	if err := writeBootTime(dir, bootB, bt-h8); err != nil {
		t.Fatal(err)
	}
	resetFloor(t)
	if got := floor.lowest(bootA, bt, dir, true); got != bt {
		t.Fatalf("another boot's record counted: %d", got)
	}
	if id, _, _ := parseBootTime(mustRead(t, file)); id != bootA {
		t.Fatalf("record of boot %s kept", id)
	}
	// A new boot forgets the process's readings too.
	if got := floor.lowest(bootB, bt+h8, "", true); got != bt+h8 {
		t.Fatalf("a new boot kept the old floor: %d", got)
	}
	// A liveness query reads the record and never writes one, so status
	// and doctor stay read-only.
	resetFloor(t)
	fresh := privateRunDir(t)
	if got := floor.lowest(bootA, bt, fresh, false); got != bt {
		t.Fatalf("query without a record: %d", got)
	}
	if _, err := os.Lstat(filepath.Join(fresh, bootTimeName)); err == nil {
		t.Fatal("a liveness query wrote the record")
	}
	if err := writeBootTime(fresh, bootA, bt-h8); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, filepath.Join(fresh, bootTimeName))
	resetFloor(t)
	if got := floor.lowest(bootA, bt-1, fresh, false); got != bt-h8 {
		t.Fatalf("query with a record: %d, want %d", got, bt-h8)
	}
	if after := mustRead(t, filepath.Join(fresh, bootTimeName)); string(after) != string(before) {
		t.Fatalf("a liveness query rewrote the record: %q", after)
	}
}

// D157: the record is kept only in a private run directory, only in a
// regular file of the user, never through a symlink.
func TestBootFloorFileCare(t *testing.T) {
	const bt = int64(1_732_000_000_000_000)
	resetFloor(t)
	open := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	floor.lowest(bootA, bt, open, true)
	if _, err := os.Lstat(filepath.Join(open, bootTimeName)); err == nil {
		t.Fatal("a record was written in a directory others can read")
	}
	if err := os.WriteFile(filepath.Join(open, bootTimeName), []byte(bootA+" 5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetFloor(t)
	if got := floor.lowest(bootA, bt, open, true); got != bt {
		t.Fatalf("a record in a directory others can read counted: %d", got)
	}

	dir := privateRunDir(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte(bootA+" 5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, bootTimeName)); err != nil {
		t.Fatal(err)
	}
	resetFloor(t)
	if got := floor.lowest(bootA, bt, dir, true); got != bt {
		t.Fatalf("a record read through a symlink counted: %d", got)
	}
	if b := mustRead(t, target); string(b) != bootA+" 5\n" {
		t.Fatalf("the symlink's target was written: %q", b)
	}
	if st, err := os.Lstat(filepath.Join(dir, bootTimeName)); err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		t.Fatalf("the symlink was not replaced by a 0600 file: %v %v", st, err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("leftovers in the run directory: %v", ents)
	}
	if err := os.Remove(filepath.Join(dir, bootTimeName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, bootTimeName), 0o700); err != nil {
		t.Fatal(err)
	}
	resetFloor(t)
	if got := floor.lowest(bootA, bt, dir, true); got != bt {
		t.Fatalf("a directory named boottime: %d", got)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The test seam: bootTimeNow follows setBootTime and restores.
func TestSetBootTime(t *testing.T) {
	restore := setBootTime(func() (int64, error) { return 42, nil })
	if v, err := bootTimeNow(); v != 42 || err != nil {
		t.Fatalf("bootTimeNow = %d, %v", v, err)
	}
	restore()
	if bootTimeOverride.Load() != nil {
		t.Fatal("not restored")
	}
}
