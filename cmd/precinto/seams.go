package main

import (
	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/wrapper"
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
