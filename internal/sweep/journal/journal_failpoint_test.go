//go:build failpoints

package journal_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/precinto/precinto/internal/fsx/failpoint"
	"github.com/precinto/precinto/internal/sweep/journal"
)

// TestAdvanceFailureKeepsThePreviousMilestone: a phase is persisted only
// once its write succeeded; a failed Advance leaves the previous milestone
// both on disk and in memory (D58).
func TestAdvanceFailureKeepsThePreviousMilestone(t *testing.T) {
	defer failpoint.Reset()
	j := newJournal(t)
	r, err := j.Begin(journal.KindSeal, "claude-code", "u1")
	if err != nil {
		t.Fatal(err)
	}
	failpoint.Set("journal.save=errno:EIO:2") // Begin was hit 1
	if err := j.Advance(r, journal.PhaseTmpWritten); !errors.Is(err, syscall.EIO) {
		t.Fatalf("Advance: %v, want EIO", err)
	}
	if r.Phase != journal.PhasePrepared {
		t.Fatalf("in-memory phase %s after a failed Advance", r.Phase)
	}
	if got := readOnDisk(t, j, r.ID); got.Phase != journal.PhasePrepared {
		t.Fatalf("on-disk phase %s after a failed Advance", got.Phase)
	}
	if err := j.Advance(r, journal.PhaseTmpWritten); err != nil {
		t.Fatal(err)
	}
	if got := readOnDisk(t, j, r.ID); got.Phase != journal.PhaseTmpWritten {
		t.Fatalf("on-disk phase %s", got.Phase)
	}
	if failpoint.Hits("journal.save") != 3 {
		t.Fatalf("journal.save hits = %d, want one per record write", failpoint.Hits("journal.save"))
	}
}

// TestBeginFailureWritesNothing: an injected error before the first write
// leaves no record and no temporary.
func TestBeginFailureWritesNothing(t *testing.T) {
	defer failpoint.Reset()
	j := newJournal(t)
	failpoint.Set("journal.save=errno:ENOSPC")
	if _, err := j.Begin(journal.KindSeal, "claude-code", "u1"); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("Begin: %v", err)
	}
	ents, _ := os.ReadDir(j.Dir)
	if len(ents) != 0 {
		t.Fatalf("files left: %v", ents)
	}
}

// TestCrashBeforeSaveKeepsTheMilestone kills a child process at the second
// record write (the Advance to tmp_written): the record on disk must still
// say prepared, complete and decodable.
func TestCrashBeforeSaveKeepsTheMilestone(t *testing.T) {
	if dir := os.Getenv("JOURNAL_CRASH_DIR"); dir != "" {
		j := journal.Open(dir)
		r, err := j.Begin(journal.KindSeal, "claude-code", "u1")
		if err != nil {
			os.Exit(3)
		}
		r.Capsule = "g000001.pcap"
		failpoint.Set("journal.save:2")           // hit 1 was Begin
		_ = j.Advance(r, journal.PhaseTmpWritten) // SIGKILL before the write
		os.Exit(0)
	}
	dir := filepath.Join(t.TempDir(), "journal")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashBeforeSaveKeepsTheMilestone$")
	cmd.Env = append(os.Environ(), "JOURNAL_CRASH_DIR="+dir)
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("child: %v", err)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("child status %v, want SIGKILL", ee)
	}
	p, err := journal.Open(dir).Pending()
	if err != nil || len(p) != 1 {
		t.Fatalf("pending %v %v", p, err)
	}
	if p[0].Phase != journal.PhasePrepared || p[0].Capsule != "" {
		t.Fatalf("record after crash: %+v", p[0])
	}
}
