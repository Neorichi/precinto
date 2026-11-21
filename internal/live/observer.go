package live

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/platform"
)

const (
	// maxObservedEntries bounds one observation; a larger tree cannot be
	// proven stable and is reported as an error (live).
	maxObservedEntries = 200_000
	// futureSkew is how far a file time may lie ahead of the wall clock
	// before it counts as "in the future" (R16): file systems round times.
	futureSkew = 2 * time.Second
	// forgetAfter drops the history of units not observed for this long,
	// so the daemon's long-lived observer does not grow without bound.
	forgetAfter = 48 * time.Hour
)

// errTooLarge is returned for a unit with more entries than an
// observation can track.
var errTooLarge = errors.New("live: too many entries to observe")

// entry is the identity of one observed path. For directories, names is
// the sorted listing (a file appearing or vanishing changes it).
type entry struct {
	exists bool
	mode   uint32
	dev    uint64
	ino    uint64
	size   int64
	mtime  int64
	ctime  int64
	names  string
}

// observation is one look at a unit.
type observation map[string]entry

// history is the oldest observation a unit has kept unchanged since.
type history struct {
	snap  observation
	since time.Duration // monotonic reading when snap was first seen
	last  time.Duration // monotonic reading of the latest observation
}

// holdState tracks how long a unit has been live, for hold caps (S14).
type holdState struct {
	sinceWall time.Time     // first time seen live (continuously)
	weakWall  time.Time     // start of the current weak-only period
	weakMono  time.Duration // same, monotonic; zero time: not weak-only
	weak      bool
	last      time.Duration
}

// look is the result of one observation, with the detail Decide needs.
type look struct {
	stable    bool
	first     bool   // no earlier observation to compare with
	timesOnly bool   // only file times changed since the last observation
	future    string // a path whose mtime lies in the future
}

func newObserver(c platform.Clock) *Observer {
	return &Observer{clock: c, units: map[string]*history{}, holds: map[string]*holdState{}}
}

func (o *Observer) forget(key string) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.units, key)
	delete(o.holds, key)
}

func (o *Observer) observe(key string, paths []string, q time.Duration) (bool, error) {
	l, err := o.look(key, paths, q)
	return l.stable, err
}

// look takes an observation of paths and compares it with the unit's
// history on the monotonic clock (R16): the unit is stable when the same
// observation was first made at least q ago. Any change restarts the
// window; an error forgets the history (nothing can be proven).
func (o *Observer) look(key string, paths []string, q time.Duration) (look, error) {
	if o == nil || o.clock == nil {
		return look{first: true}, errors.New("live: observer without a clock")
	}
	snap, err := snapshot(paths)
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.units == nil {
		o.units = map[string]*history{}
	}
	now := o.clock.Mono()
	o.pruneLocked(now)
	if err != nil {
		delete(o.units, key)
		return look{first: true}, err
	}
	res := look{future: futurePath(snap, o.clock.Now())}
	h := o.units[key]
	switch {
	case h == nil:
		res.first = true
		o.units[key] = &history{snap: snap, since: now, last: now}
		// A first observation never proves stability: two are needed.
	case sameObservation(h.snap, snap):
		h.last = now
		res.stable = now-h.since >= q
	default:
		res.timesOnly = onlyTimesChanged(h.snap, snap)
		o.units[key] = &history{snap: snap, since: now, last: now}
	}
	return res, nil
}

// hold records whether key is live now and returns since when it has been
// live and whether it has been held only by weak evidence for at least
// holdCap, on either clock (S14). A unit seen not live is forgotten.
func (o *Observer) hold(key string, live, weakOnly bool, holdCap time.Duration) (time.Time, bool) {
	if o == nil || o.clock == nil {
		return time.Time{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.holds == nil {
		o.holds = map[string]*holdState{}
	}
	wall, mono := o.clock.Now(), o.clock.Mono()
	if !live {
		delete(o.holds, key)
		return time.Time{}, false
	}
	h := o.holds[key]
	if h == nil {
		h = &holdState{sinceWall: wall}
		o.holds[key] = h
	}
	h.last = mono
	if !weakOnly {
		h.weak = false
		return h.sinceWall, false
	}
	if !h.weak {
		h.weak, h.weakWall, h.weakMono = true, wall, mono
	}
	if holdCap <= 0 {
		return h.sinceWall, true
	}
	capped := mono-h.weakMono >= holdCap || wall.Sub(h.weakWall) >= holdCap
	return h.sinceWall, capped
}

func (o *Observer) pruneLocked(now time.Duration) {
	for k, h := range o.units {
		if now-h.last > forgetAfter {
			delete(o.units, k)
		}
	}
	for k, h := range o.holds {
		if now-h.last > forgetAfter {
			delete(o.holds, k)
		}
	}
}

// snapshot lstats every path (never following symlinks); directories are
// walked recursively so a file appended deep below a unit directory, or a
// new file, changes the observation. A missing path is recorded as absent;
// any other error fails the observation.
func snapshot(paths []string) (observation, error) {
	snap := observation{}
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("live: observed path %q is not absolute", p)
		}
		if err := observePath(snap, filepath.Clean(p)); err != nil {
			return nil, err
		}
	}
	return snap, nil
}

func observePath(snap observation, p string) error {
	if _, done := snap[p]; done {
		return nil
	}
	if len(snap) >= maxObservedEntries {
		return errTooLarge
	}
	st, err := fsx.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		snap[p] = entry{}
		return nil
	}
	if err != nil {
		return err
	}
	e := entry{exists: true, mode: st.Mode, dev: st.Dev, ino: st.Ino, size: st.Size, mtime: st.MtimeNS, ctime: st.CtimeNS}
	if !st.IsDir() {
		snap[p] = e
		return nil
	}
	des, err := os.ReadDir(p)
	if errors.Is(err, fs.ErrNotExist) {
		snap[p] = entry{}
		return nil // vanished between lstat and readdir: absent now
	}
	if err != nil {
		return err
	}
	names := make([]string, 0, len(des))
	for _, de := range des {
		names = append(names, de.Name())
	}
	sort.Strings(names)
	e.names = strings.Join(names, "\x00")
	snap[p] = e
	for _, n := range names {
		if err := observePath(snap, filepath.Join(p, n)); err != nil {
			return err
		}
	}
	return nil
}

func sameObservation(a, b observation) bool {
	if len(a) != len(b) {
		return false
	}
	for p, ea := range a {
		if eb, ok := b[p]; !ok || ea != eb {
			return false
		}
	}
	return true
}

// onlyTimesChanged reports whether a and b differ only in file times
// (mtime/ctime): no path appeared or vanished, no size, inode or listing
// changed. Such evidence is weak ("mtime-only", S14).
func onlyTimesChanged(a, b observation) bool {
	if len(a) != len(b) {
		return false
	}
	for p, ea := range a {
		eb, ok := b[p]
		if !ok || ea.exists != eb.exists || ea.mode != eb.mode || ea.dev != eb.dev || ea.ino != eb.ino ||
			ea.size != eb.size || ea.names != eb.names {
			return false
		}
	}
	return true
}

// futurePath returns one path whose mtime lies beyond now (plus skew).
func futurePath(snap observation, now time.Time) string {
	limit := now.Add(futureSkew).UnixNano()
	var found []string
	for p, e := range snap {
		if e.exists && e.mtime > limit {
			found = append(found, p)
		}
	}
	if len(found) == 0 {
		return ""
	}
	sort.Strings(found)
	return found[0]
}
