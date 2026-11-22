package main

import (
	"sort"

	"github.com/precinto/precinto/internal/ui"
)

// User-facing text. Every message the catalog of internal/ui defines is
// printed from there (SPEC §16.3). The catalog has no entries for the CLI's
// own usage errors, summaries and prompts, so those live here, under the
// same rules: they name the folder and the next command, never include
// prompt text, titles or file content, and never say "root", "grant",
// "soft" or "hard" (the --root flag excepted; text_test.go enforces it).
// They are candidates for catalog ids (reported to the lead).
const (
	textDeferred          = "this command is planned for a later version of precinto."
	textNotConfirmed      = "not confirmed; nothing was changed."
	textNothingToDo       = "nothing to do."
	textAlreadyInit       = "precinto is already set up. Add another way to unlock with: precinto factor add"
	textRecoveryOutBad    = "refusing to write the recovery key to %s: %s"
	textInitDone          = "set up. Protect a folder with: precinto protect DIR"
	textInitNotConfirmed  = "init stopped before you confirmed the recovery key, so nothing was set up. Run precinto init again when you can write the key down."
	textInitCancelled     = "init cancelled; nothing was set up. Run precinto init again when you are ready."
	textInitKeyUnused     = "nothing was set up, so the recovery key of this run is not used. Run precinto init again for a new one."
	textNoSEPlugin        = "age-plugin-se did not return a key (%s)."
	textRecoveryOK        = "the recovery key opens your sealed folders."
	textRecoveryUnknown   = "the recovery key could not be checked: %s"
	textRecoveryNotNewest = "WARNING: this is your recovery key, but it does not open the newest sealed capsule, which was sealed to another recovery key. Run precinto doctor."
	textRecoveryFile      = "reading the recovery key from a plain file needs --insecure-key-file (the key opens every sealed folder)."
	textRecovered         = "unlocked %d folder(s) with the recovery key. Add a new way to unlock with: precinto factor add"

	textProtected          = "protecting %s. Sessions and notes there are sealed when it locks. Lock it now with: precinto lock --root %s"
	textAlreadyProt        = "%s is already protected."
	textOverlap            = "%s overlaps the protected folder %s."
	textOverlapAsk         = "Protect it anyway? The deepest folder wins for each session. [y/N]"
	textOwnData            = "refusing to protect %s: it contains (or is inside) precinto's own data folder."
	textHarnessData        = "refusing to protect %s: it is inside a harness data folder (Claude's or Codex's own files)."
	textVaultRetry         = "%s is listed as protected, but its vault could not be created. Run precinto protect %s again."
	textGitExcludeAsk      = "Add *.md.precinto to .git/info/exclude of %d repository(s) in %s (local, never committed)? [Y/n]"
	textRepoOutside        = "note: %s belongs to the git repository %s; Claude's memory for it is shared with sessions outside the folder."
	textSettingsDone       = "wrote precinto's Claude settings to %s."
	textSettingsRemoved    = "removed precinto's Claude settings from %s (your other settings are kept)."
	textProtectReused      = "%s was protected before: its vault and sealed copies serve again. It is locked; unlock it with: precinto unlock --root %s"
	textUnprotectList      = "%s holds %d sealed unit(s); they are restored before protection stops."
	textUnprotectDone      = "%s is no longer protected. Its sealed copies stay in the vault until you run precinto forget or precinto prune."
	textUnprotectWhat      = "Stopping protection of %s"
	textUnprotectKept      = "%s stays protected: not every sealed unit could be restored (%s)."
	textUnprotectWaits     = "%s stays protected until you confirm its removal: precinto unlock --root %s, in a terminal, shows the change again."
	textUnprotectedFolders = "%s: their vaults are kept, but no setting protects them; if you did not stop protecting them, check the settings you confirmed"
	textPolicyLine         = "  %s"
	textNoLongerProtected  = "no longer protected"
	textNewlyProtected     = "newly protected"
	textAlreadyOpen        = "%s is already unlocked."
	textUnlockWhich        = "%s is not inside a protected folder. Unlock a folder with: precinto unlock --root DIR (or --all)"
	textUnlockPick         = "Unlock which folder? Type its number (1-%d), or all:"
	textUnlockPickLine     = "  %d) %s"
	textAllOpen            = "every folder is already unlocked."
	textLocked             = "locked %s."
	textLockAllInstead     = "without a config.toml that loads precinto cannot find the folder; lock every folder with: precinto lock"
	textConfigBroken       = "fix config.toml, then check it with: precinto doctor"
	textConfigFix          = "fix config.toml (precinto keeps the settings it loaded last), then run precinto doctor"
	textCheckConfig        = "status --check cannot tell whether every locked folder is sealed while config.toml does not load (%s). Fix config.toml, then run precinto status --check again."
	textCheckUnscanned     = "status --check cannot tell whether every locked folder is sealed: %s. Run precinto doctor."
	textPlainUnscanned     = "the folders could not be scanned"
	textPlainNotSetUp      = "precinto is not set up"
	textStandInPinned      = "the settings confirmed last"
	textStandInDefaults    = "the default settings"
	textLockedNone         = "every folder is locked."
	textEnded              = "ended %d session(s)."
	textStillPlain         = "%d unit(s) are still unencrypted (in use). See: precinto status"
	textSealed             = "sealed %d unit(s) (%d files, %s)."
	textSealSkipped        = "%d unit(s) are still in use and stay unencrypted for now; precinto seals them when they are quiet."
	textSealHeldLine       = "  %s (%d): %s" // under textSealSkipped, printed without the "precinto: " prefix
	textRemoveFailed       = "%d unit(s) were sealed, but some of their files could not be removed and stay unencrypted; the next sweep removes them. See: precinto status"
	textSealAdopted        = "%d session(s) from before the folder was protected, or run without precinto's hooks, stay unencrypted. Seal them with: precinto seal --adopt"
	textSealDry            = "would seal %d unit(s) (%d files, %s); nothing was sealed. Seal them with the same command without --dry-run."
	textSealSkippedDry     = "%d unit(s) are still in use: a seal now would leave them unencrypted until they are quiet."
	textSealAdoptedDry     = "%d session(s) from before the folder was protected, or run without precinto's hooks, would stay unencrypted. Seal them with: precinto seal --adopt"
	textSealNoSpace        = "not enough free space to seal %d unit(s): they need %s, and precinto keeps min_free (%s) free on the disk. Free some space, then seal again: precinto seal"
	textQuietWait          = "waiting %s for the files to stop changing…"
	textSealNone           = "nothing to seal."
	textQueued             = "queued the session for sealing."
	textRestored           = "restored %d unit(s) (%d files, %s)."
	textRestoreNone        = "nothing to restore."
	textConflicts          = "%d file(s) were kept in both versions. List them with: precinto ls --conflicts"
	textSkippedUnits       = "%d unit(s) were skipped (budget, free space or in use)."
	textRestoreStopped     = "the restore stopped: a folder locked or the precinto agent stopped answering. What was not restored stays sealed; unlock and run precinto restore again."
	textForgetWhat         = "Forgetting %d sealed generation(s) of %s"
	textForgetNone         = "no sealed copies found for %s."
	textForgot             = "forgot %d unit(s)."
	textPruneWhat          = "Deleting %d old generation(s) of %d unit(s)"
	textPruneLine          = "  %s %s: %d capsule(s) (%s)"
	textUnprotectUnit      = "  %s %s (%d generation(s))"
	textPruneDry           = "would delete %d old generation(s) of %d unit(s). Run without --dry-run to delete them."
	textPruned             = "deleted old generations of %d unit(s)."
	textResolveWhich       = "Keep which version of %s? Type capsule or plaintext:"
	textResolved           = "resolved %s."
	textCatNeedTTY         = "cat prints a note only to a terminal. Write it to a file with: precinto cat FILE --to OUT"
	textCatOutExists       = "refusing to overwrite %s."
	textOpened             = "opened %d note(s)."
	textNotHarness         = "%s is not a known harness. Name it with: precinto run --harness H -- CMD"
	textNoHarnessBin       = "%s was not found in PATH."
	textRunNotFound        = "%s is not installed (it is not in PATH). Install it, or run it by its full path: precinto run -- /path/to/it"
	textReconciled         = "reconciled the Codex history of %s."
	textSyncedConfig       = "copied your Codex config.toml into the sealed Codex home of %s."
	textAgentRunning       = "agent running (pid %d)."
	textAgentStopped       = "agent stopped."
	textAgentNotRunning    = "the agent is not running, so every folder is locked."
	textServiceLinux       = "the background re-seal service is not available on linux in this version: sessions are sealed when they end and when a folder locks."
	textServiceOn          = "background re-seal installed: %s runs precinto sweep --quiet every 10 minutes."
	textServiceOff         = "background re-seal removed."
	textServiceNone        = "background re-seal is not installed. Install it with: precinto service install"
	textServiceStatus      = "background re-seal installed (%s); last sweep: %s."
	textServiceTCC         = "the background re-seal may not be allowed to read %s (macOS privacy settings); sessions there are sealed by the terminal agent instead."
	textShellInstall       = "Add the precinto shell integration to %s? [Y/n]"
	textShellDone          = "added the shell integration to %s. Open a new terminal to use it."
	textIntegrateBin       = "linked %s to this precinto binary."
	textIntegrateOld       = "%s %s is older than %s, which precinto needs. Update it with: %s update"
	textIntegrateRun       = "run: %s"
	textIntegratePrint     = "precinto integrate %s first writes precinto's plugin, from this precinto binary, to %s, then runs these commands, which need that folder (--print changed nothing):"
	textIntegrateFailed    = "%s failed, so precinto's hooks are not installed and precinto's settings were not changed. Fix what the error above says, then run precinto integrate %s again. These are the commands it runs; try them yourself to see the whole error:"
	textIntegrateCmd       = "  %s" // a command line, printed without the "precinto:" prefix
	textIntegrateDone      = "precinto's %s plugin is installed."
	textIntegrateExp       = "%s support is experimental (wrapper only): start it with precinto run %s. precinto cannot pause it when a folder locks."
	textIntegrateHost      = "%s support is experimental: %s"
	textCodexTrust         = "In Codex run /hooks and trust \"precinto\", so prompts pause when the folder locks."
	textNeedExp            = "%s support is experimental: add --experimental."
	textFactorRemove       = "Remove the unlock method %s from every folder? [y/N]"
	textFactorRemoved      = "removed %s."
	textFactorAdded        = "added %s to every folder."
	textFactorTested       = "%s works."
	textFactorNeedOpen     = "unlock every folder first: precinto unlock --all"
	textRepinNotPlugin     = "%s is not a plugin factor (see precinto factor list)."
	textRepinSame          = "%s is already pinned to the binary its path names; nothing to do."
	textRepinWhat          = "Re-pinning the unlock method %s in every folder's vault:"
	textRepinLine          = "  %-16s %s"
	textRepinDone          = "re-pinned %s: unlocking with it works again."
	textRepinChanged       = "WARNING: the binary of %s changed again while you confirmed, so the pin names a binary you did not see. Check it, then run precinto factor repin %s again."
	textRepairDiff         = "  %s: %s"
	textRepairNothing      = "%s's vault matches the key you unlocked; nothing to repair."
	textRepairExposed      = "  exposed: %s"
	textBusySweep          = "another sweep is running; it will rescan."
	textResumeHarness      = "resume supports claude-code and codex."
	textWorkerFailed       = "could not start the background sealer: %s"
)

// Typed confirmation words (C12.typed, C14.confirm, C2.confirmall).
const (
	wordForget    = "forget"
	wordPrune     = "prune"
	wordUnprotect = "unprotect"
	wordRepair    = "repair"
	wordUnlock    = "unlock"
	wordRepin     = "repin"
)

// line prints a catalog message on stderr.
func (a *app) line(id ui.MsgID, v ui.Vars) { ui.Writer{W: a.err}.Line(id, v) }

// lineOut prints a catalog message on stdout.
func (a *app) lineOut(id ui.MsgID, v ui.Vars) { ui.Writer{W: a.out}.Line(id, v) }

func sortedStrings(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}
