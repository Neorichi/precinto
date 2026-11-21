package sweep

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/sweep/queue"
)

// CONC-1 (R19, FX-G4-17): ten SessionEnd sealers (seal --queue), three
// sweeps and a lock sweep run at once, each a process of its own, against
// one home: every unit is sealed exactly once, nothing deadlocks, and no
// more than two seals — large ones alone — ever overlap. The children are
// this test binary run again (lifeline, timeout); each traces its seals to
// a shared append-only file.
func TestCONC1AcrossProcesses(t *testing.T) {
	if os.Getenv("SWEEP_CONC_DIR") != "" {
		concChild(t)
		return
	}
	t.Parallel()
	te := newTestEnv(t)
	sids := make([]string, 8)
	large := map[string]bool{}
	for i := range sids {
		sids[i] = fmt.Sprintf("00000000-0000-4000-8000-0000000c%04d", i)
		te.writeSession(sids[i], "", nil)
		if i%2 == 0 {
			// A large unit: twice the threshold the children use.
			writeAt(t, filepath.Join(te.h.ClaudeTmp, "-pad", sids[i], "pad.bin"), make([]byte, 2*concBig))
			large[te.sessionKey(sids[i])] = true
		}
	}
	for i := 0; i < 10; i++ {
		_, err := queue.Enqueue(te.h.Layout.QueueDir, queue.Request{Harness: "claude-code", SID: sids[i%len(sids)], Reason: "other"})
		mustNoErr(t, err)
	}
	trace := filepath.Join(te.h.Dir, "seal-trace")
	roles := append(append(strings.Split(strings.Repeat("queue,", 10), ",")[:10], "sweep", "sweep", "sweep"), "lock")
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	for i, role := range roles {
		wg.Add(1)
		go func(i int, role string) {
			defer wg.Done()
			out, err := runChild(t, "SWEEP_CONC_DIR="+te.h.Dir, "SWEEP_CONC_RUN="+te.h.RunDir, "SWEEP_CONC_ROLE="+role,
				"SWEEP_CONC_SIDS="+strings.Join(sids, ","), "SWEEP_CONC_TRACE="+trace)
			if err != nil {
				mu.Lock()
				failures = append(failures, fmt.Sprintf("child %d (%s): %v\n%s", i, role, err, out))
				mu.Unlock()
			}
		}(i, role)
	}
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("children failed (or deadlocked):\n%s", strings.Join(failures, "\n"))
	}
	for _, sid := range sids {
		key := te.sessionKey(sid)
		if n := len(te.logged(key)); n != 1 {
			t.Fatalf("session %s sealed %d times, want exactly once", sid, n)
		}
		if _, ok := te.claude.sessionUnit(te.cc, sid); ok {
			t.Fatalf("session %s left in plaintext", sid)
		}
	}
	if reqs, _ := queue.List(te.h.Layout.QueueDir); len(reqs) != 0 {
		t.Fatalf("%d queued requests left", len(reqs))
	}
	all, big := maxOverlap(t, trace, large)
	if all > 2 || big > 1 {
		t.Fatalf("seals overlapping at once: %d (want ≤ 2), large ones: %d (want alone)", all, big)
	}
	if all == 0 {
		t.Fatal("no seal traced")
	}
}

// concBig is the large-unit threshold of the CONC-1 children (bigUnit).
const concBig = 64 << 10

// concChild is one CONC-1 process: a queue drain, a sweep or a lock sweep
// over the parent's home.
func concChild(t *testing.T) {
	holdLifeline()
	bigUnit = concBig
	te := newTestEnvWith(t, homeAt(t, os.Getenv("SWEEP_CONC_DIR"), os.Getenv("SWEEP_CONC_RUN")))
	te.claude.sids = strings.Split(os.Getenv("SWEEP_CONC_SIDS"), ",")
	trace := os.Getenv("SWEEP_CONC_TRACE")
	te.codec.traceSeal = func(unit string, start bool) {
		ev := "end"
		if start {
			ev = "start"
		}
		f, err := os.OpenFile(trace, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%s %s %d\n", unit, ev, time.Now().UnixNano())
			f.Close()
		}
		if start {
			time.Sleep(30 * time.Millisecond) // widen each seal so overlaps would show
		}
	}
	var err error
	switch os.Getenv("SWEEP_CONC_ROLE") {
	case "queue":
		_, err = te.run().drainCommand(tctx(t), Options{Reason: "session-end"})
	case "sweep":
		_, err = te.run().sweep(tctx(t), Options{})
	case "lock":
		_, err = te.run().sweep(tctx(t), Options{Reason: "lock", Lock: true, Wait: true})
	}
	if err != nil && err != ErrBusy {
		t.Fatalf("%s: %v", os.Getenv("SWEEP_CONC_ROLE"), err)
	}
}

// maxOverlap reads a seal trace and returns the most seals, and the most
// large seals, in flight at once.
func maxOverlap(t *testing.T, trace string, large map[string]bool) (all, big int) {
	t.Helper()
	f, err := os.Open(trace)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	type ev struct {
		at    int64
		unit  string
		start bool
	}
	var evs []ev
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) != 3 {
			t.Fatalf("trace line %q", sc.Text())
		}
		at, err := strconv.ParseInt(parts[2], 10, 64)
		mustNoErr(t, err)
		evs = append(evs, ev{at: at, unit: parts[0], start: parts[1] == "start"})
	}
	sort.SliceStable(evs, func(a, b int) bool {
		if evs[a].at != evs[b].at {
			return evs[a].at < evs[b].at
		}
		return !evs[a].start // an end before a start at the same instant
	})
	n, nb := 0, 0
	for _, e := range evs {
		d := 1
		if !e.start {
			d = -1
		}
		n += d
		if large[e.unit] {
			nb += d
		}
		all, big = max(all, n), max(big, nb)
	}
	return all, big
}
