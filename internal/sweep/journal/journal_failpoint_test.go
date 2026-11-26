//go:build failpoints

package journal_test

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/fsx/failpoint"
	"github.com/Neorichi/precinto/internal/sweep/journal"
)

// TestAdvanceFailureKeepsThePreviousMilestone: a phase is persisted only
// once its write succeeded; a failed Advance leaves the previous milestone
// both on disk and in memory (D58).
func TestAdvanceFailureKeepsThePreviousMilestone(t *testing.T) {
	failpoint.Reset() // hit counts are process-wide: count from this test on
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

// TestBeginLeavesItsFreedTemporaryNameAlone: once Begin has removed its
// temporary, another writer of the process may take the same name at once
// (a Save of the record: fsx.WriteFileAtomic builds it the same way); Begin
// must not remove that name again after its directory sync (as Enqueue,
// TestEnqueueLeavesItsFreedTemporaryNameAlone).
func TestBeginLeavesItsFreedTemporaryNameAlone(t *testing.T) {
	j := newJournal(t)
	var once sync.Once
	other := ""
	stop := failpoint.ObserveFS(func(op failpoint.FSOp) {
		if op.Kind != failpoint.FSDirSync || op.Path != j.Dir {
			return
		}
		ents, err := os.ReadDir(j.Dir)
		if err != nil {
			return
		}
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			once.Do(func() {
				// The other writer takes the freed name (plain os: an
				// observer must not call into fsx).
				name := filepath.Join(j.Dir, "."+e.Name()+".tmp-"+strconv.Itoa(os.Getpid())+"-0")
				f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if err != nil {
					t.Errorf("the temporary name was not free at the directory sync: %v", err)
					return
				}
				f.Close()
				other = name
			})
		}
	})
	defer stop()
	if _, err := j.Begin(journal.KindSeal, "claude-code", "u1"); err != nil {
		t.Fatal(err)
	}
	stop()
	if other == "" {
		t.Fatal("no directory sync of the journal after the record was linked")
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatalf("Begin removed the temporary name after it had freed it: %v", err)
	}
}

// TestBeginFailureWritesNothing: an injected error before the first write
// leaves no record and no temporary.
func TestBeginFailureWritesNothing(t *testing.T) {
	failpoint.Reset() // hit counts are process-wide: count from this test on
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
		// The child: it exits when its lifeline (stdin) closes, and after
		// two minutes whatever happens (TESTPLAN §1.8).
		go func() {
			_, _ = io.Copy(io.Discard, os.Stdin)
			os.Exit(70)
		}()
		time.AfterFunc(2*time.Minute, func() { os.Exit(71) })
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashBeforeSaveKeepsTheMilestone$", "-test.count=1")
	cmd.Env = append(os.Environ(), "JOURNAL_CRASH_DIR="+dir)
	cmd.WaitDelay = 10 * time.Second
	life, lifeline, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer lifeline.Close() // the child's lifeline: closed when this test ends
	cmd.Stdin = life
	err = cmd.Run()
	life.Close()
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
