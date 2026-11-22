package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/vault"
)

// enforcedConfig is cfg (config.toml, or the settings standing in for a
// config.toml that does not load) with the folders the agent enforces, as
// far as a process without keys can tell (D142): its roots merged
// strictest with those of the confirmed settings (state/policy.pinned,
// D48, D55), so a folder whose removal from config.toml waits for a
// confirmation is still sealed, listed by status and written to
// roots.list; while the pin is missing or has a shape precinto never
// writes and a folder's vault exists (the agent's policy-tampered state at
// start, D91), every folder a vault records (vault.toml root_path) joins
// too, as in the agent (D145). A vault no setting names is otherwise a
// retired one (D74) and no folder of the result. Only the folders change:
// the policy and the harness tables stay cfg's (min_free comes from
// floorPolicy). A root id is kept once (cfg's path first, as the agent's
// RootByID), a path once, and only paths that could be saved
// (config.WithRoots).
func (a *app) enforcedConfig(cfg config.Config, l paths.Layout) config.Config {
	other := config.Default()
	pinned, ok, err := config.LoadPinned(l.PolicyPinned)
	if err == nil && ok {
		other = pinned.Config
	}
	ids := a.rootVaultIDs()
	tampered := len(ids) > 0 && (err != nil || !ok || pinned.CheckShape(a.vaultExists) != nil)
	merged := config.Strictest(cfg, other)
	out := cfg
	out.Roots = nil
	out = config.WithRoots(out, merged.Roots...)
	if tampered {
		out = config.WithRoots(out, a.recordedRoots(ids)...)
	}
	return out
}

// agentStatusWait bounds the question a sealing command asks the agent.
const agentStatusWait = 2 * time.Second

// withAgentRoots adds to cfg the folders a running agent reports it
// enforces (D142): every folder it locks, gates and has its lock worker
// seal, among them the folders vaults record while it finds the confirmed
// settings tampered (a MAC that failed at an unlock, D145), which a
// process without keys cannot tell from a pin of the right shape. Without
// an answer (no agent runs) cfg is returned as it is: the agent's lock
// worker then resolves its folder from the settings alone. It never
// starts the agent.
func (a *app) withAgentRoots(cfg config.Config) config.Config {
	ctx, cancel := context.WithTimeout(context.Background(), agentStatusWait)
	defer cancel()
	c, err := a.dial(ctx, false)
	if err != nil {
		return cfg
	}
	defer c.Close()
	st, err := c.Status(ctx)
	if err != nil {
		return cfg
	}
	return config.WithRoots(cfg, agentRoots(st)...)
}

// agentRoots returns the folders of an agent's status: every vault it
// reports but the global one, at the path it enforces.
func agentRoots(st ipc.StatusResp) []config.Root {
	var out []config.Root
	for _, v := range st.Vaults {
		if v.VaultID != vault.GlobalID {
			out = append(out, config.Root{ID: v.VaultID, Path: v.RootPath})
		}
	}
	return out
}

// rootVaultIDs lists the folder vaults (every vault but the global one);
// nil when there is none or the vault folder cannot be read.
func (a *app) rootVaultIDs() []string {
	l, err := a.layout()
	if err != nil || !fileExists(l.VaultsDir) {
		return nil
	}
	vs, err := a.vaults()
	if err != nil {
		return nil
	}
	all, err := vs.List()
	if err != nil {
		return nil
	}
	var ids []string
	for _, id := range all {
		if id != vault.GlobalID {
			ids = append(ids, id)
		}
	}
	return ids
}

// recordedRoots returns, for the vaults ids, the folders their vault.toml
// records (root_path), with the default folder settings: every protected
// folder has one (D121). They are never validated as a configuration:
// config.WithRoots drops what could not be saved.
func (a *app) recordedRoots(ids []string) []config.Root {
	vs, err := a.vaults()
	if err != nil {
		return nil
	}
	var out []config.Root
	for _, id := range ids {
		if m, err := vs.Meta(id); err == nil && m.RootPath != "" {
			out = append(out, config.Root{ID: id, Path: m.RootPath})
		}
	}
	return out
}

// unprotectedFolders lists the folders whose vault is kept but that cfg
// does not protect, while the confirmed settings name no folder at all
// (D145): such a pin is signed by the global vault alone, and only
// `unlock --global` (or recover) checks that MAC, so a one-shot writer
// that dropped every folder from config.toml and planted a pin of those
// settings would otherwise leave every folder unprotected with no alert.
// The list is also what a user who stopped protecting those folders sees
// (D74 keeps their vaults). Empty while the pin names a folder (a folder
// unlock checks its MAC), and while it is missing or has a forged shape
// (the folders vaults record are enforced then). cfg is the folder set
// the caller protects (config.toml's merged with the agent's).
func (a *app) unprotectedFolders(cfg config.Config, l paths.Layout) []config.Root {
	pinned, ok, err := config.LoadPinned(l.PolicyPinned)
	if err != nil || !ok || len(pinned.Config.Roots) > 0 || pinned.CheckShape(a.vaultExists) != nil {
		return nil
	}
	var out []config.Root
	for _, r := range config.WithRoots(config.Config{}, a.recordedRoots(a.rootVaultIDs())...).Roots {
		if !protects(cfg, r) {
			out = append(out, r)
		}
	}
	return out
}

// protects reports whether cfg holds folder r, by its id or its path.
func protects(cfg config.Config, r config.Root) bool {
	for _, x := range cfg.Roots {
		if x.ID == r.ID || x.Path == r.Path {
			return true
		}
	}
	return false
}

// unprotectedAttention is the status item of unprotectedFolders (D145):
// the folders, and the command that checks the confirmed settings.
func (a *app) unprotectedAttention(rs []config.Root) ipc.Attention {
	names := make([]string, 0, len(rs))
	for _, r := range rs {
		names = append(names, a.display(r.Path))
	}
	return ipc.Attention{Code: doctor.CheckUnprotectedFolders, Count: len(rs),
		Detail: fmt.Sprintf(textUnprotectedFolders, strings.Join(names, ", ")), Fix: "precinto unlock --global"}
}

// droppedFolderChanges renders unprotectedFolders as pending changes of
// the review a terminal unlock shows (D145): confirming adopts config.toml,
// which leaves those folders unprotected, so the review names them even
// when the agent lists nothing ("roots[<id>]: <path> → ", the agent's
// format for a folder removed).
func droppedFolderChanges(rs []config.Root) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, "roots["+r.ID+"]: "+r.Path+" → ")
	}
	return out
}

// vaultExists reports whether the vault a pin's MAC names exists (its
// vault.toml reads, D91).
func (a *app) vaultExists(id string) bool {
	vs, err := a.vaults()
	if err != nil {
		return false
	}
	_, err = vs.Meta(id)
	return err == nil
}
