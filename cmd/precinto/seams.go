package main

import (
	"github.com/Neorichi/precinto/internal/hook"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/ledger"
	"github.com/Neorichi/precinto/internal/live"
	"github.com/Neorichi/precinto/internal/sweep"
	"github.com/Neorichi/precinto/internal/ui"
	"github.com/Neorichi/precinto/internal/vault"
	"github.com/Neorichi/precinto/internal/wrapper"
)

// Compile-time checks of the cross-group seams of docs/API.md §4: the
// concrete types of one group satisfy the interfaces another group
// consumes, without adapters.
var (
	_ hook.Daemon    = (*ipc.Client)(nil)
	_ hook.Ledger    = (*ledger.Ledger)(nil)
	_ wrapper.Daemon = (*ipc.Client)(nil)
	_ wrapper.Lease  = (*live.Held)(nil)
	_ sweep.FileKeys = (*ipc.KeySet)(nil)
	_ ipc.UIHandler  = (*ui.TTY)(nil)
)

// Compile-time checks of the adapters this package implements for other
// groups (docs/API.md §4) and of its own seams.
var (
	_ wrapper.Backend         = (*backend)(nil)   // `precinto run` orchestration
	_ sweep.KeySource         = (*keySource)(nil) // file keys over ipc (D39)
	_ func(*app) sweep.Grants = (*app).grants     // unlocked folders over ipc (R4)
	_ ipc.UIHandler           = headlessUI{}      // relayed prompts without a terminal
	_ vault.UI                = vaultUI{}         // init's vault.Store.Init
	_ terminal                = (*ui.TTY)(nil)    // the controlling terminal
	_ daemonClient            = ipcClient{}       // *ipc.Client behind the CLI seam
	_ wrapper.Daemon          = daemonClient(nil) // the wrapper uses the same client
	_ vaultStore              = storeAdapter{}    // *vault.Store behind the CLI seam
	_ shellOps                = shellinitOps{}    // internal/shellinit
	_ engine                  = (*sweepEngine)(nil)
)
