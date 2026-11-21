package harness

import (
	"slices"
	"sync"
)

// registry holds the adapters cmd/precinto wires in, in registration order.
// It is process-wide: adapters are stateless values, registered once at
// start-up, and looked up by every subcommand.
var registry struct {
	mu       sync.RWMutex
	adapters []Adapter
}

// register adds a or, when an adapter with the same id is already
// registered, replaces it in place (so a test or a re-wiring never ends up
// with two adapters for one harness). A nil adapter is ignored.
func register(a Adapter) {
	if a == nil {
		return
	}
	id := a.ID()
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for i, old := range registry.adapters {
		if old.ID() == id {
			registry.adapters[i] = a
			return
		}
	}
	registry.adapters = append(registry.adapters, a)
}

func lookup(id ID) (Adapter, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	for _, a := range registry.adapters {
		if a.ID() == id {
			return a, true
		}
	}
	return nil, false
}

func registered() []Adapter {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return slices.Clone(registry.adapters)
}

// unitRef implements Unit.Ref; slices are copied so a UnitRef never aliases
// the unit it came from.
func unitRef(u Unit) UnitRef {
	return UnitRef{
		Harness: u.Harness,
		Kind:    u.Kind,
		Key:     u.Key,
		VaultID: u.VaultID,
		RootIDs: slices.Clone(u.RootIDs),
		HomeID:  u.Home.ID,
	}
}
