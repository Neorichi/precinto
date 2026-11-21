package main

import (
	"context"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

func cmdVault(a *app, args []string) int {
	f := newFlags("vault")
	rootDir := f.String("root", "", "repair the vault of the protected folder `DIR`")
	global := f.Bool("global", false, "repair the global vault")
	useRecovery := f.Bool("recovery", false, "unlock with the recovery key (when the vault's keys may have been replaced too)")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) != 1 || pos[0] != "repair" {
		return a.usageFail(f, "the only vault subcommand is repair")
	}
	if (*rootDir == "") == !*global {
		return a.usageFail(f, "give exactly one of --root DIR or --global")
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("vault repair", err)
	}
	vaultID, folder, command := vault.GlobalID, "the global vault", "vault repair --global"
	if *rootDir != "" {
		r, err := a.rootArg(cfg, *rootDir)
		if err != nil {
			return a.fail("vault repair", err)
		}
		vaultID, folder, command = r.ID, a.display(r.Path), "vault repair --root "+a.display(r.Path)
	}
	if *useRecovery {
		command += " --recovery"
	}
	// D53: TTY only, never from an agent context (SEC-26).
	if err := a.refuseAgent(refusal{action: "repair the vault of", folder: folder, command: command}); err != nil {
		return exitLocked
	}
	t, err := a.needTerminal("vault repair")
	if err != nil {
		return exitLocked
	}
	defer t.Close()
	if err := a.sys.harden(); err != nil {
		return a.fail("vault repair", err)
	}
	var recovery *memguard.LockedBuffer
	if *useRecovery {
		recovery, err = t.Secret(ui.Format(ui.MsgRecoveryPrompt, ui.Vars{}))
		if err != nil {
			return a.fail("vault repair", err)
		}
		defer recovery.Destroy()
		if _, err := vault.ParseRecoveryKey(recovery); err != nil {
			return a.fail("vault repair", err)
		}
	}
	ctx := context.Background()
	c, err := a.dial(ctx, true)
	if err != nil {
		return a.fail("vault repair", err)
	}
	defer c.Close()

	// Phase 1 (Confirmed=false): the daemon unwraps the identity with a
	// factor (or the recovery key), checks that it opens the vault's older
	// capsules (C14.notgenuine otherwise) and reports what a repair would
	// rewrite, changing nothing.
	send := func() (*memguard.LockedBuffer, error) {
		if recovery == nil {
			return nil, nil
		}
		return copySecret(recovery)
	}
	rec1, err := send()
	if err != nil {
		return a.fail("vault repair", err)
	}
	plan, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: vaultID, UseRecovery: *useRecovery}, rec1, t)
	if rec1 != nil {
		rec1.Destroy()
	}
	if err != nil {
		return a.fail("vault repair", err)
	}
	// Even with unchanged recipients the repair rewrites the MAC and the
	// verified copy (a tampered MAC alone also stops sealing), so it always
	// asks.
	a.showRepairPlan(plan)
	// Phase 2: the user saw the diff and types "repair" (C14.confirm).
	if err := a.typedWord(t, ui.Format(ui.MsgVaultRepairConfirm, ui.Vars{Folder: folder}), wordRepair); err != nil {
		return exitLocked
	}
	rec2, err := send()
	if err != nil {
		return a.fail("vault repair", err)
	}
	done, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: vaultID, UseRecovery: *useRecovery, Confirmed: true}, rec2, t)
	if rec2 != nil {
		rec2.Destroy()
	}
	if err != nil {
		return a.fail("vault repair", err)
	}
	a.line(ui.MsgVaultRepaired, ui.Vars{Folder: folder, N: len(done.Exposed)})
	for _, p := range done.Exposed {
		a.say(textRepairExposed, p)
	}
	return exitOK
}

// showRepairPlan prints the recipient diff of a repair.
func (a *app) showRepairPlan(p ipc.VaultRepairResp) {
	if p.RecipientChanged {
		a.say(textRepairDiff, "vault recipient", "rewritten from the key you unlocked")
	}
	if p.RecoveryChanged {
		a.say(textRepairDiff, "recovery recipient", "rewritten from your recovery key")
	}
	if !p.RecipientChanged && !p.RecoveryChanged {
		a.say(textRepairDiff, "recipients", "unchanged; the vault's checksum and verified copy are rewritten")
	}
	for _, e := range p.Exposed {
		a.say(textRepairExposed, e)
	}
}
