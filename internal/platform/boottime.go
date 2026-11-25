package platform

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/Neorichi/precinto/internal/fsx"
)

// The earliest boot time of this boot (D157, amending D66). On linux a
// process's wall-clock start is btime + its start since boot, and btime
// (/proc/stat) is the wall clock minus the time since boot. Inside the WSL
// 2 virtual machine the clock that counts time since boot stops while the
// Windows host sleeps, and the wall clock is set forward at resume: btime
// jumps forward by the length of the sleep, and every process started
// before it seems to have started that much later. D18's registry check
// (a live pid whose start is at most startedAt + 2 s) then rejected the
// registry entry of a live Claude session. EarliestStartTime adds instead
// the earliest btime seen for this boot: this process's own readings and
// the one recorded in the run directory, which the daemon notes at start
// and at every tick (NoteBootTime). That start is never later than
// StartTime's, and is the real one when a precinto process read btime
// before the jump (a sleep while no agent ran is not undone), so liveness
// errs toward alive; StartTime keeps the current btime, which only ever
// gives a later start, for decisions that must not err that way
// (endsess.go: which process may be signalled), and the wrapper measures
// its child's start once, right after the spawn, for what it records
// (ChildSessions).

// bootTimeName is the file below the run directory that records the
// earliest btime of the current boot: "<boot id> <µs since the epoch>".
const bootTimeName = "boottime"

// bootTimeOverride replaces sysBootTimeUS when set (tests only:
// SetBootTimeForTest in -tags testing builds, the package's own tests).
var bootTimeOverride atomic.Pointer[func() (int64, error)]

// bootTimeNow returns the boot time in µs since the epoch (linux
// /proc/stat btime; ErrUnsupported elsewhere).
func bootTimeNow() (int64, error) {
	if f := bootTimeOverride.Load(); f != nil {
		return (*f)()
	}
	return sysBootTimeUS()
}

// setBootTime makes bootTimeNow call fn (nil: the system again) and
// returns a function that restores the previous source.
func setBootTime(fn func() (int64, error)) (restore func()) {
	var p *func() (int64, error)
	if fn != nil {
		p = &fn
	}
	old := bootTimeOverride.Swap(p)
	return func() { bootTimeOverride.Store(old) }
}

// bootFloor is this process's earliest btime of one boot.
type bootFloor struct {
	mu     sync.Mutex
	bootID string
	low    int64 // µs; 0: none yet
}

// floor is the process-wide bootFloor.
var floor bootFloor

// lowest returns the earliest btime known for boot bootID: cur (the
// current reading), this process's earlier readings and the value the run
// directory's boottime file records, and keeps it as this process's
// reading. With record (NoteBootTime: the daemon), it also writes the
// result to the file when that holds no value of this boot or a later
// one; a liveness query (EarliestStartTime) only reads, so status, doctor
// and the sealers never write there. A run directory that is missing or
// not private (fsx.CheckPrivateDir), and a file that is not a regular
// file of the user holding a well-formed value of this boot, add nothing;
// a failed write changes nothing either (the next tick tries again).
// Every value only ever lowers the result: a recorded value later than
// cur is ignored.
func (f *bootFloor) lowest(bootID string, cur int64, runDir string, record bool) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bootID != bootID {
		f.bootID, f.low = bootID, 0
	}
	low := earliest(cur, f.low)
	if runDir != "" && filepath.IsAbs(runDir) && fsx.CheckPrivateDir(runDir) == nil {
		rec, ok := readBootTime(filepath.Join(runDir, bootTimeName), bootID)
		if ok {
			low = earliest(low, rec)
		}
		if record && (!ok || rec > low) {
			_ = writeBootTime(runDir, bootID, low)
		}
	}
	f.low = low
	return low
}

// earliest returns the smallest positive value of vs (0 when none is).
func earliest(vs ...int64) int64 {
	var low int64
	for _, v := range vs {
		if v > 0 && (low == 0 || v < low) {
			low = v
		}
	}
	return low
}

// maxBootTimeFile bounds what readBootTime reads.
const maxBootTimeFile = 128

// readBootTime returns the btime path records for boot bootID.
func readBootTime(path, bootID string) (int64, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|fsx.ONoFollow|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil || !st.IsRegular() || int(st.UID) != os.Geteuid() {
		return 0, false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBootTimeFile+1))
	if err != nil || len(b) > maxBootTimeFile {
		return 0, false
	}
	id, us, ok := parseBootTime(b)
	if !ok || id != bootID {
		return 0, false
	}
	return us, true
}

// writeBootTime replaces runDir's boottime file with (bootID, us): a new
// 0600 file renamed over it (never through a symlink). It is metadata
// only, lost at reboot with the run directory or made stale by the next
// boot id, so it is not synced.
func writeBootTime(runDir, bootID string, us int64) error {
	b, err := formatBootTime(bootID, us)
	if err != nil {
		return err
	}
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(runDir, "."+bootTimeName+"-"+strconv.Itoa(os.Getpid())+"-"+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|fsx.ONoFollow, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(runDir, bootTimeName)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// formatBootTime renders the boottime file.
func formatBootTime(bootID string, us int64) ([]byte, error) {
	if !validBootID(bootID) || us <= 0 {
		return nil, fmt.Errorf("platform: boot time %q %d", bootID, us)
	}
	return []byte(bootID + " " + strconv.FormatInt(us, 10) + "\n"), nil
}

// parseBootTime reads "<boot id> <µs>\n": a boot id as the kernel prints
// it (/proc/sys/kernel/random/boot_id) and a positive decimal number.
func parseBootTime(b []byte) (bootID string, us int64, ok bool) {
	b = bytes.TrimSuffix(b, []byte("\n"))
	id, num, found := bytes.Cut(b, []byte(" "))
	if !found || !validBootID(string(id)) {
		return "", 0, false
	}
	v, ok := parsePositive(string(num), 1<<62)
	if !ok {
		return "", 0, false
	}
	return string(id), v, true
}

// validBootID accepts the kernel's boot id form: 36 characters of lower
// hexadecimal digits with dashes at 8, 13, 18 and 23.
func validBootID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}
