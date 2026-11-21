package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// newRootID implements NewRootID: 128 random bits as 32 lowercase hex
// digits. crypto/rand.Read never returns an error (since Go 1.24 it aborts
// the program if the system generator fails).
func newRootID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// strictest implements Strictest.
//
// Roots and harnesses are a union: a root or harness present in either input
// stays (removing one is weakening). Two inputs that disagree on a root's
// path keep one entry per path under the same id, so both folders stay
// protected by that root's vault; two ids for the same path keep both
// entries (gated while either is locked). Only in those conflict cases the
// result fails Validate (duplicate id or path): it is the effective policy,
// not a file to save. Per root, md is the stricter, md_exclude the
// intersection, include_tracked and claude_settings are or'ed, on_enter is
// the stricter effective value, harnesses the union and protected_at the
// earliest. Per harness, enabled and experimental are or'ed, min_version is
// the higher, homes are the union by (dir, tmp, cache), and bin (which has
// no protection order) is b's when set, else a's: the daemon passes the
// pinned configuration second (SPEC §12.8). max_unlock is clamped to
// MaxUnlockCap, and the version is SchemaVersion when either input has it.
// Nothing in the result aliases a or b.
func strictest(a, b Config) Config {
	out := Config{Version: mergeVersion(a.Version, b.Version)}
	for _, r := range policyRules {
		r.merge(&out.Policy, &a.Policy, &b.Policy)
	}
	if out.Policy.MaxUnlock.D() > MaxUnlockCap {
		out.Policy.MaxUnlock = Duration(MaxUnlockCap)
	}
	out.Roots = mergeRoots(a, b)
	out.Harness = mergeHarnesses(a.Harness, b.Harness)
	return out
}

// mergeVersion keeps the supported schema version when either input has it
// (the version is a format, not a protection level), else the higher one.
func mergeVersion(a, b int) int {
	if a == SchemaVersion || b == SchemaVersion {
		return SchemaVersion
	}
	return max(a, b)
}

// sourcedRoot is a root and the configuration it comes from (for its
// effective on_enter).
type sourcedRoot struct {
	r   Root
	cfg *Config
}

func mergeRoots(a, b Config) []Root {
	var order []string
	byID := map[string][]sourcedRoot{}
	add := func(c *Config) {
		for _, r := range c.Roots {
			if _, seen := byID[r.ID]; !seen {
				order = append(order, r.ID)
			}
			byID[r.ID] = append(byID[r.ID], sourcedRoot{r, c})
		}
	}
	add(&a)
	add(&b)
	var out []Root
	for _, id := range order {
		group := byID[id]
		merged := mergeRootFields(group)
		var seenPaths []string
		for _, s := range group {
			if slices.Contains(seenPaths, s.r.Path) {
				continue
			}
			seenPaths = append(seenPaths, s.r.Path)
			r := merged
			r.Path = s.r.Path
			r.MDExclude = slices.Clone(merged.MDExclude)
			r.Harnesses = slices.Clone(merged.Harnesses)
			out = append(out, r)
		}
	}
	return out
}

// mergeRootFields merges every field of the entries of one root id except
// the path. An on_enter left empty by every entry keeps inheriting the
// merged policy value, itself the stricter of both policies.
func mergeRootFields(group []sourcedRoot) Root {
	first := group[0].r
	r := Root{ID: first.ID, MD: first.MD, MDExclude: slices.Clone(first.MDExclude)}
	effOnEnter := group[0].cfg.EffectiveOnEnter(first)
	allInherit := true
	var harnesses []string
	allDefault := true
	for _, s := range group {
		x := s.r
		r.MD = stricter(cmpRank(mdRank), r.MD, x.MD)
		r.MDExclude = intersect(r.MDExclude, x.MDExclude)
		r.IncludeTracked = r.IncludeTracked || x.IncludeTracked
		r.ClaudeSettings = r.ClaudeSettings || x.ClaudeSettings
		effOnEnter = stricter(cmpRank(onEnterRank), effOnEnter, s.cfg.EffectiveOnEnter(x))
		if x.OnEnter != "" {
			allInherit = false
		}
		if len(x.Harnesses) > 0 {
			allDefault = false
		}
		for _, h := range effectiveHarnesses(x.Harnesses) {
			if !slices.Contains(harnesses, h) {
				harnesses = append(harnesses, h)
			}
		}
		if !x.ProtectedAt.IsZero() && (r.ProtectedAt.IsZero() || x.ProtectedAt.Before(r.ProtectedAt)) {
			r.ProtectedAt = x.ProtectedAt
		}
	}
	if !allInherit {
		r.OnEnter = effOnEnter
	}
	if !allDefault {
		r.Harnesses = harnesses
	}
	return r
}

// intersect returns the elements of a also in b, in a's order (nil if none).
func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func mergeHarnesses(a, b map[string]Harness) map[string]Harness {
	if a == nil && b == nil {
		return nil
	}
	out := make(map[string]Harness, len(a)+len(b))
	for id, h := range a {
		out[id] = cloneHarness(h)
	}
	for id, hb := range b {
		ha, ok := a[id]
		if !ok {
			out[id] = cloneHarness(hb)
			continue
		}
		m := Harness{
			Enabled:      ha.Enabled || hb.Enabled,
			Experimental: ha.Experimental || hb.Experimental,
			Bin:          ha.Bin,
			MinVersion:   stricter(cmpVersion, ha.MinVersion, hb.MinVersion),
			Homes:        mergeHomes(ha.Homes, hb.Homes),
		}
		if hb.Bin != "" {
			m.Bin = hb.Bin
		}
		out[id] = m
	}
	return out
}

func cloneHarness(h Harness) Harness {
	h.Homes = slices.Clone(h.Homes)
	return h
}

// homeKey identifies the locations a registered home makes sweeps visit.
type homeKey struct{ dir, tmp, cache string }

func keyOf(h Home) homeKey { return homeKey{h.Dir, h.Tmp, h.Cache} }

func mergeHomes(a, b []Home) []Home {
	var out []Home
	idx := map[homeKey]int{}
	for _, h := range slices.Concat(a, b) {
		k := keyOf(h)
		i, ok := idx[k]
		if !ok {
			idx[k] = len(out)
			out = append(out, h)
			continue
		}
		if h.SeenAt.After(out[i].SeenAt) {
			out[i].SeenAt = h.SeenAt
		}
		out[i].Default = out[i].Default || h.Default
	}
	return out
}

// diff implements Diff: version, then policy keys in declaration order, then
// roots by id, then harnesses by id. Lists compare as sets; seen_at and
// default of a home, a root's protected_at and changes that keep the same
// protection (md "" to "ledger") are reported as non-weakening changes.
func diff(old, new Config) []Change {
	var out []Change
	if old.Version != new.Version {
		// A schema this binary does not understand has no known protection
		// order: leaving the supported one is weakening (conservative).
		weak := old.Version == SchemaVersion && new.Version != SchemaVersion
		out = append(out, Change{Key: "version", Old: strconv.Itoa(old.Version), New: strconv.Itoa(new.Version), Weakening: weak})
	}
	for _, r := range policyRules {
		if c, ok := r.diff(&old.Policy, &new.Policy); ok {
			out = append(out, c)
		}
	}
	out = append(out, diffRoots(old, new)...)
	out = append(out, diffHarnesses(old.Harness, new.Harness)...)
	return out
}

func diffRoots(old, new Config) []Change {
	group := func(c Config) map[string][]Root {
		m := map[string][]Root{}
		for _, r := range c.Roots {
			m[r.ID] = append(m[r.ID], r)
		}
		return m
	}
	og, ng := group(old), group(new)
	var out []Change
	for _, id := range unionKeys(og, ng) {
		key := "roots[" + id + "]"
		os, ns := og[id], ng[id]
		switch {
		case len(ns) == 0:
			for _, o := range os {
				out = append(out, Change{Key: key, Old: o.Path, Weakening: true})
			}
			continue
		case len(os) == 0:
			for _, n := range ns {
				out = append(out, Change{Key: key, New: n.Path})
			}
			continue
		}
		pairs, oRest, nRest := pairUp(os, ns, func(r Root) string { return r.Path })
		for _, p := range pairs {
			out = append(out, diffRootFields(key, old, new, p[0], p[1])...)
		}
		// Extra entries for a path the other side also has are duplicates
		// (only Strictest produces them), not moves.
		oRest = slices.DeleteFunc(oRest, func(o Root) bool {
			if i := slices.IndexFunc(ns, func(n Root) bool { return n.Path == o.Path }); i >= 0 {
				out = append(out, diffRootFields(key, old, new, o, ns[i])...)
				return true
			}
			return false
		})
		nRest = slices.DeleteFunc(nRest, func(n Root) bool {
			if i := slices.IndexFunc(os, func(o Root) bool { return o.Path == n.Path }); i >= 0 {
				out = append(out, diffRootFields(key, old, new, os[i], n)...)
				return true
			}
			return false
		})
		for i := 0; i < len(oRest) || i < len(nRest); i++ {
			switch {
			case i >= len(nRest): // a path of this root is no longer protected
				out = append(out, Change{Key: key + ".path", Old: oRest[i].Path, Weakening: true})
			case i >= len(oRest): // an extra path is protected
				out = append(out, Change{Key: key + ".path", New: nRest[i].Path})
			default: // moved: the old folder loses its protection
				out = append(out, Change{Key: key + ".path", Old: oRest[i].Path, New: nRest[i].Path, Weakening: true})
				out = append(out, diffRootFields(key, old, new, oRest[i], nRest[i])...)
			}
		}
	}
	return out
}

func diffRootFields(key string, oldCfg, newCfg Config, o, n Root) []Change {
	var out []Change
	add := func(field, ov, nv string, weakening bool) {
		out = append(out, Change{Key: key + "." + field, Old: ov, New: nv, Weakening: weakening})
	}
	if o.MD != n.MD {
		add("md", o.MD, n.MD, cmpRank(mdRank)(n.MD, o.MD) < 0)
	}
	if !sameSet(o.MDExclude, n.MDExclude) {
		// Every extra exclude glob seals less.
		add("md_exclude", listText(o.MDExclude), listText(n.MDExclude), !subset(n.MDExclude, o.MDExclude))
	}
	if o.IncludeTracked != n.IncludeTracked {
		add("include_tracked", boolText(o.IncludeTracked), boolText(n.IncludeTracked), cmpTrue(n.IncludeTracked, o.IncludeTracked) < 0)
	}
	if o.OnEnter != n.OnEnter {
		weak := cmpRank(onEnterRank)(newCfg.EffectiveOnEnter(n), oldCfg.EffectiveOnEnter(o)) < 0
		add("on_enter", o.OnEnter, n.OnEnter, weak)
	}
	if !sameSet(o.Harnesses, n.Harnesses) {
		weak := !subset(effectiveHarnesses(o.Harnesses), effectiveHarnesses(n.Harnesses))
		add("harnesses", listText(o.Harnesses), listText(n.Harnesses), weak)
	}
	if o.ClaudeSettings != n.ClaudeSettings {
		add("claude_settings", boolText(o.ClaudeSettings), boolText(n.ClaudeSettings), cmpTrue(n.ClaudeSettings, o.ClaudeSettings) < 0)
	}
	if !o.ProtectedAt.Equal(n.ProtectedAt) {
		add("protected_at", timeText(o.ProtectedAt), timeText(n.ProtectedAt), false)
	}
	return out
}

func diffHarnesses(old, new map[string]Harness) []Change {
	var out []Change
	for _, id := range unionKeys(old, new) {
		key := "harness." + id
		o, inOld := old[id]
		n, inNew := new[id]
		switch {
		case !inNew:
			out = append(out, Change{Key: key, Old: id, Weakening: true})
			continue
		case !inOld:
			out = append(out, Change{Key: key, New: id})
			continue
		}
		if o.Enabled != n.Enabled {
			out = append(out, Change{Key: key + ".enabled", Old: boolText(o.Enabled), New: boolText(n.Enabled), Weakening: !n.Enabled})
		}
		if o.Experimental != n.Experimental {
			out = append(out, Change{Key: key + ".experimental", Old: boolText(o.Experimental), New: boolText(n.Experimental), Weakening: !n.Experimental})
		}
		if o.Bin != n.Bin {
			// No protection order: replacing or clearing a configured
			// executable waits for a confirmation (conservative); setting one
			// where none was configured pins it and applies at once.
			out = append(out, Change{Key: key + ".bin", Old: o.Bin, New: n.Bin, Weakening: o.Bin != ""})
		}
		if o.MinVersion != n.MinVersion {
			out = append(out, Change{Key: key + ".min_version", Old: o.MinVersion, New: n.MinVersion, Weakening: cmpVersion(n.MinVersion, o.MinVersion) < 0})
		}
		out = append(out, diffHomes(key, o.Homes, n.Homes)...)
	}
	return out
}

func diffHomes(key string, old, new []Home) []Change {
	group := func(hs []Home) map[string][]Home {
		m := map[string][]Home{}
		for _, h := range hs {
			m[h.Dir] = append(m[h.Dir], h)
		}
		return m
	}
	og, ng := group(old), group(new)
	var out []Change
	for _, dir := range unionKeys(og, ng) {
		hk := key + ".homes[" + dir + "]"
		os, ns := og[dir], ng[dir]
		switch {
		case len(ns) == 0:
			out = append(out, Change{Key: hk, Old: dir, Weakening: true})
			continue
		case len(os) == 0:
			out = append(out, Change{Key: hk, New: dir})
			continue
		}
		pairs, oRest, nRest := pairUp(os, ns, keyOf)
		for _, p := range pairs {
			out = append(out, diffHomeMeta(hk, p[0], p[1])...)
		}
		oRest = slices.DeleteFunc(oRest, func(o Home) bool {
			if i := slices.IndexFunc(ns, func(n Home) bool { return keyOf(n) == keyOf(o) }); i >= 0 {
				out = append(out, diffHomeMeta(hk, o, ns[i])...)
				return true
			}
			return false
		})
		nRest = slices.DeleteFunc(nRest, func(n Home) bool {
			if i := slices.IndexFunc(os, func(o Home) bool { return keyOf(o) == keyOf(n) }); i >= 0 {
				out = append(out, diffHomeMeta(hk, os[i], n)...)
				return true
			}
			return false
		})
		for i := 0; i < len(oRest) || i < len(nRest); i++ {
			switch {
			case i >= len(nRest): // a variant of this home is no longer visited
				out = append(out, Change{Key: hk, Old: homeText(oRest[i]), Weakening: true})
			case i >= len(oRest):
				out = append(out, Change{Key: hk, New: homeText(nRest[i])})
			default:
				o, n := oRest[i], nRest[i]
				// The old location is no longer visited unless it was unset.
				if o.Tmp != n.Tmp {
					out = append(out, Change{Key: hk + ".tmp", Old: o.Tmp, New: n.Tmp, Weakening: o.Tmp != ""})
				}
				if o.Cache != n.Cache {
					out = append(out, Change{Key: hk + ".cache", Old: o.Cache, New: n.Cache, Weakening: o.Cache != ""})
				}
			}
		}
	}
	return out
}

// diffHomeMeta reports the non-protection fields of one home.
func diffHomeMeta(hk string, o, n Home) []Change {
	var out []Change
	if !o.SeenAt.Equal(n.SeenAt) {
		out = append(out, Change{Key: hk + ".seen_at", Old: timeText(o.SeenAt), New: timeText(n.SeenAt)})
	}
	if o.Default != n.Default {
		out = append(out, Change{Key: hk + ".default", Old: boolText(o.Default), New: boolText(n.Default)})
	}
	return out
}

// pairUp matches old and new entries one to one by key, in order, and
// returns the pairs and the unmatched entries of each side.
func pairUp[T any, K comparable](old, new []T, key func(T) K) (pairs [][2]T, oRest, nRest []T) {
	used := make([]bool, len(new))
	for _, o := range old {
		k, found := key(o), false
		for i, n := range new {
			if !used[i] && key(n) == k {
				used[i], found = true, true
				pairs = append(pairs, [2]T{o, n})
				break
			}
		}
		if !found {
			oRest = append(oRest, o)
		}
	}
	for i, n := range new {
		if !used[i] {
			nRest = append(nRest, n)
		}
	}
	return pairs, oRest, nRest
}

func homeText(h Home) string {
	return fmt.Sprintf("dir=%s tmp=%s cache=%s", h.Dir, h.Tmp, h.Cache)
}

// unionKeys returns the keys of a and b, sorted.
func unionKeys[V any](a, b map[string]V) []string {
	keys := make([]string, 0, len(a)+len(b))
	for k := range a {
		keys = append(keys, k)
	}
	for k := range b {
		if _, dup := a[k]; !dup {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// subset reports whether every element of a is in b.
func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

func sameSet(a, b []string) bool { return subset(a, b) && subset(b, a) }

func listText(v []string) string { return strings.Join(v, ", ") }
