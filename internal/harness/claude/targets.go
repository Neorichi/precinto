package claude

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ledger"
)

// deniedIdentityNames are the deny-listed $CC entries whose (dev, ino) a
// target's first component must not share (a case or normalization
// variant, or a hard link, of a deny-listed name, SPEC §11.2).
var deniedIdentityNames = append([]string{"settings.json", "settings.local.json", "keybindings.json", "CLAUDE.md", ".credentials.json"}, deniedTop...)

// Targets returns the restore rules of a logged Claude capsule (SPEC
// §11.2), computed from the registered home and the authenticated unit id
// only. Every rule is the inverse of the inventory (configUnitOf,
// tmpSessionOf), so whatever Scan seals can be restored and nothing else
// can be written.
func (a *adapter) Targets(ctx context.Context, e harness.Env, ref harness.UnitRef, unitID string) (harness.TargetRules, error) {
	if err := ctx.Err(); err != nil {
		return harness.TargetRules{}, err
	}
	if ref.Harness != harness.ClaudeCode {
		return harness.TargetRules{}, fmt.Errorf("%w: %s", harness.ErrUnknownHarness, ref.Harness)
	}
	var h *home
	for _, rh := range registeredHomes(e.Cfg) {
		if rh.ID == ref.HomeID {
			hh := rh
			h = &hh
			break
		}
	}
	if h == nil {
		return harness.TargetRules{}, harness.ErrUnregistered
	}
	cc := h.configDir()
	bases := map[capsule.BaseID]string{capsule.BaseClaudeConfig: cc}
	if c := h.cacheDir(); c != "" {
		bases[capsule.BaseClaudeCache] = c
	}
	if t := h.tmpDir(); tmpSafe(t) {
		bases[capsule.BaseClaudeTmp] = t
	}
	var index *ledger.Index
	if e.Index != nil {
		index = e.Index(harnessName)
	}
	rules := harness.TargetRules{Bases: bases, Mode: harness.GenLayered, Policy: func(capsule.Entry) harness.Placement { return harness.PlaceExact }}
	configOK := func(rel string, want func([]string) bool) bool {
		parts, ok := cleanRel(rel)
		return ok && !deniedByIdentity(cc, parts[0]) && want(parts)
	}
	switch ref.Kind {
	case capsule.KindClaudeSession:
		if !isUUID(unitID) {
			return harness.TargetRules{}, fmt.Errorf("%w: session id", harness.ErrUnitKey)
		}
		sid := strings.ToLower(unitID)
		rules.Allow = func(base capsule.BaseID, rel string) bool {
			if _, ok := bases[base]; !ok {
				return false
			}
			switch base {
			case capsule.BaseClaudeConfig:
				return configOK(rel, func(parts []string) bool {
					if sameName(parts[0], "jobs") {
						// jobs/<id>/** of the session's background jobs (D25).
						return len(parts) >= 2 && safeComponent(parts[1])
					}
					cu, ok := configUnitOf(parts)
					return ok && cu.kind == capsule.KindClaudeSession && cu.id == sid
				})
			case capsule.BaseClaudeTmp:
				parts, ok := cleanRel(rel)
				if !ok {
					return false
				}
				s, p, ok := tmpSessionOf(parts)
				return ok && s == sid && projectKnown(cc, p, index)
			}
			return false
		}
		rules.Policy = func(en capsule.Entry) harness.Placement {
			if en.Base != capsule.BaseClaudeConfig {
				return harness.PlaceExact
			}
			parts, ok := cleanRel(en.Rel)
			if !ok {
				return harness.PlaceExact
			}
			if main, sub := isTranscript(parts, sid); main || sub {
				return harness.PlaceJSONLAppend
			}
			return harness.PlaceExact
		}
	case capsule.KindClaudeProject:
		if !safeComponent(unitID) {
			return harness.TargetRules{}, fmt.Errorf("%w: project directory", harness.ErrUnitKey)
		}
		proj := unitID
		rules.Allow = func(base capsule.BaseID, rel string) bool {
			if _, ok := bases[base]; !ok {
				return false
			}
			switch base {
			case capsule.BaseClaudeConfig:
				return configOK(rel, func(parts []string) bool {
					cu, ok := configUnitOf(parts)
					return ok && cu.kind == capsule.KindClaudeProject && sameName(cu.id, proj)
				})
			case capsule.BaseClaudeCache:
				parts, ok := cleanRel(rel)
				return ok && sameName(parts[0], proj)
			}
			return false
		}
	case capsule.KindClaudePlan:
		if !safeComponent(unitID) {
			return harness.TargetRules{}, fmt.Errorf("%w: plan slug", harness.ErrUnitKey)
		}
		slug := unitID
		rules.Allow = func(base capsule.BaseID, rel string) bool {
			return base == capsule.BaseClaudeConfig && configOK(rel, func(parts []string) bool {
				return len(parts) == 2 && sameName(parts[0], "plans") && planOf(parts[1], slug)
			})
		}
	case capsule.KindClaudeHistory:
		if unitID != "" && !containsFold(ref.RootIDs, unitID) {
			return harness.TargetRules{}, fmt.Errorf("%w: history unit id", harness.ErrUnitKey)
		}
		rules.Allow = func(base capsule.BaseID, rel string) bool {
			return base == capsule.BaseClaudeConfig && configOK(rel, func(parts []string) bool {
				return (len(parts) == 1 && sameName(parts[0], "history.jsonl")) ||
					(len(parts) == 2 && sameName(parts[0], "paste-cache"))
			})
		}
		rules.Policy = func(en capsule.Entry) harness.Placement {
			if en.Base == capsule.BaseClaudeConfig && sameName(en.Rel, "history.jsonl") {
				return harness.PlaceLineUnion
			}
			return harness.PlaceExact
		}
	case capsule.KindGlobalStore:
		if unitID != storeUsage && unitID != storeFeedback {
			return harness.TargetRules{}, fmt.Errorf("%w: store name", harness.ErrUnitKey)
		}
		store := unitID
		rules.Allow = func(base capsule.BaseID, rel string) bool {
			return base == capsule.BaseClaudeConfig && configOK(rel, func(parts []string) bool {
				cu, ok := configUnitOf(parts)
				return ok && cu.kind == capsule.KindGlobalStore && cu.id == store
			})
		}
	default:
		return harness.TargetRules{}, fmt.Errorf("%w: kind %s is not a Claude kind", harness.ErrUnitKey, ref.Kind)
	}
	return rules, nil
}

// planOf reports whether a plans/ file name belongs to slug: <slug>.md or
// <slug>-*.md (D46).
func planOf(name, slug string) bool {
	if !strings.HasSuffix(strings.ToLower(name), ".md") {
		return false
	}
	stem := name[:len(name)-len(".md")]
	return sameName(stem, slug) || (len(stem) > len(slug)+1 && sameName(stem[:len(slug)+1], slug+"-"))
}

// projectKnown reports whether a $TMP project directory name is a project
// of this home: it exists under projects/ or the project index knows it
// (SPEC §11.2).
func projectKnown(cc, p string, index *ledger.Index) bool {
	if !safeComponent(p) {
		return false
	}
	if isDir(filepath.Join(cc, "projects", p)) {
		return true
	}
	if index != nil {
		if _, ok, err := index.Lookup(cc, p); err == nil && ok {
			return true
		}
	}
	return false
}

// deniedByIdentity reports whether the existing $CC entry first is the
// same file or directory as a deny-listed one (case or normalization
// variants, hard links), so no spelling of a deny-listed name passes.
func deniedByIdentity(cc, first string) bool {
	if denied(first) {
		return true
	}
	st, err := fsx.Lstat(filepath.Join(cc, first))
	if err != nil {
		return false // does not exist: nothing to alias
	}
	for _, d := range deniedIdentityNames {
		if dst, err := fsx.Lstat(filepath.Join(cc, d)); err == nil && dst.SameFile(st) {
			return true
		}
	}
	return false
}
