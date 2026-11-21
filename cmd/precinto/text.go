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
	textDeferred        = "this command is planned for a later version (see docs/DECISIONS.md D49)"
	textNotProtected    = "%s is not inside a protected folder. Protect it with: precinto protect DIR"
	textNotInitialized  = "precinto is not set up yet. Run: precinto init"
	textAgentDown       = "the precinto agent isn't running, so every folder is locked. Unlock with: precinto unlock"
	textNeedTerminal    = "%s needs your own terminal (stdin and stdout must be a terminal). Run it yourself in a terminal."
	textNotConfirmed    = "not confirmed; nothing was changed."
	textNothingToDo     = "nothing to do."
	textAlreadyInit     = "precinto is already set up. Add another way to unlock with: precinto factor add"
	textRecoveryHeader1 = "Your precinto recovery key. It opens every sealed folder if you lose your other ways to unlock."
	textRecoveryHeader2 = "Write it down and keep it offline. It is shown only once."
	textRecoveryWritten = "recovery key written to %s. Move it offline (it opens every sealed folder)."
	textRecoveryAgain   = "The recovery key is shown only now. Show it again? [Y/n]"
	textRecoveryLost    = "WARNING: the recovery key was not confirmed and cannot be shown again. Keep your other ways to unlock safe."
	textRecoveryOutBad  = "refusing to write the recovery key to %s: %s"
	textInitDone        = "set up. Protect a folder with: precinto protect DIR"
	textServiceOffer    = "Seal in the background every 10 minutes (installs a LaunchAgent)? [Y/n]"
	textPassphraseNew   = "Choose a precinto passphrase (at least 12 characters), or press Enter to get a generated one:"
	textPassphraseAgain = "Type the passphrase again:"
	textPassphraseWeak  = "that passphrase is too weak (at least 12 characters and about 80 bits are needed). Try again."
	textPassphraseDiff  = "the two passphrases differ. Try again."
	textPassphraseGen   = "Your new precinto passphrase:"
	textNoSEPlugin      = "age-plugin-se did not return a key (%s)."
	textRecoveryPrompt  = "precinto recovery key:"
	textRecoveryOK      = "the recovery key opens your sealed folders."
	textRecoveryUnknown = "the recovery key could not be checked: %s"
	textRecoveryFile    = "reading the recovery key from a plain file needs --insecure-key-file (the key opens every sealed folder)."
	textRecovered       = "unlocked %d folder(s) with the recovery key. Add a new way to unlock with: precinto factor add"
	textRecordGap       = "(precinto cannot record the successful test yet; status keeps showing it as untested)"

	textProtected      = "protecting %s. Sessions and notes there are sealed when it locks. Lock it now with: precinto lock --root %s"
	textAlreadyProt    = "%s is already protected."
	textOverlap        = "%s overlaps the protected folder %s."
	textOverlapAsk     = "Protect it anyway? The deepest folder wins for each session. [y/N]"
	textOwnData        = "refusing to protect %s: it contains (or is inside) precinto's own data folder."
	textHarnessData    = "refusing to protect %s: it is inside a harness data folder (Claude's or Codex's own files)."
	textVaultRetry     = "%s is listed as protected, but its vault could not be created. Run precinto protect %s again."
	textGitExcludeAsk  = "Add *.md.precinto to .git/info/exclude of %d repository(s) in %s (local, never committed)? [Y/n]"
	textRepoOutside    = "note: %s belongs to the git repository %s; Claude's memory for it is shared with sessions outside the folder."
	textSettingsDone   = "wrote precinto's Claude settings to %s."
	textUnprotectList  = "%s holds %d sealed unit(s); they are restored before protection stops."
	textUnprotectDone  = "%s is no longer protected. Its sealed copies stay in the vault until you run precinto forget or precinto prune."
	textUnprotectWhat  = "Stopping protection of %s"
	textUnprotectKept  = "%s stays protected: not every sealed unit could be restored (%s)."
	textPolicyConfirm  = "Confirm these changes? [y/N]"
	textPolicyLine     = "  %s"
	textAlreadyOpen    = "%s is already unlocked."
	textUnlockWhich    = "%s is not inside a protected folder. Unlock a folder with: precinto unlock --root DIR (or --all)"
	textLocked         = "locked %s."
	textLockedNone     = "every folder is locked."
	textEnded          = "ended %d session(s)."
	textStillPlain     = "%d unit(s) are still unencrypted (in use). See: precinto status"
	textSealed         = "sealed %d unit(s) (%d files, %s)."
	textSealSkipped    = "%d unit(s) are still in use and stay unencrypted for now; precinto seals them when they are quiet."
	textSealNone       = "nothing to seal."
	textQueued         = "queued the session for sealing."
	textRestored       = "restored %d unit(s) (%d files, %s)."
	textRestoreNone    = "nothing to restore."
	textConflicts      = "%d file(s) were kept in both versions. List them with: precinto ls --conflicts"
	textSkippedUnits   = "%d unit(s) were skipped (budget, free space or in use)."
	textForgetWhat     = "Forgetting %d sealed generation(s) of %s"
	textForgetNone     = "no sealed copies found for %s."
	textForgot         = "forgot %d unit(s)."
	textPruneWhat      = "Deleting %d old generation(s) of %d unit(s)"
	textPruneLine      = "  %s %s generation %d (%s)"
	textUnprotectUnit  = "  %s %s (%d generation(s))"
	textPruneDry       = "would delete %d old generation(s) of %d unit(s). Run without --dry-run to delete them."
	textPruned         = "deleted old generations of %d unit(s)."
	textResolveWhich   = "Keep which version of %s? Type capsule or plaintext:"
	textResolved       = "resolved %s."
	textCatNeedTTY     = "cat prints a note only to a terminal. Write it to a file with: precinto cat FILE --to OUT"
	textCatOutExists   = "refusing to overwrite %s."
	textOpened         = "opened %d note(s)."
	textNotHarness     = "%s is not a known harness. Name it with: precinto run --harness H -- CMD"
	textNoHarnessBin   = "%s was not found in PATH."
	textReconciled     = "reconciled the Codex history of %s."
	textSyncedConfig   = "copied your Codex config.toml into the sealed Codex home of %s."
	textAgentRunning   = "agent running (pid %d)."
	textAgentStopped   = "agent stopped."
	textServiceLinux   = "the background re-seal service is not available on linux in this version (see docs/DECISIONS.md D49)."
	textServiceOn      = "background re-seal installed: %s runs precinto sweep --quiet every 10 minutes."
	textServiceOff     = "background re-seal removed."
	textServiceNone    = "background re-seal is not installed. Install it with: precinto service install"
	textServiceStatus  = "background re-seal installed (%s); last sweep: %s."
	textServiceTCC     = "the background re-seal may not be allowed to read %s (macOS privacy settings); sessions there are sealed by the terminal agent instead."
	textShellInstall   = "Add the precinto shell integration to %s? [Y/n]"
	textShellDone      = "added the shell integration to %s. Open a new terminal to use it."
	textIntegrateBin   = "linked %s to this precinto binary."
	textIntegrateOld   = "%s %s is older than %s, which precinto needs. Update it first."
	textIntegrateRun   = "run: %s"
	textIntegrateDone  = "precinto's %s plugin is installed."
	textIntegrateExp   = "%s support is experimental (wrapper only): start it with precinto run %s. precinto cannot pause it when a folder locks."
	textIntegrateHost  = "%s support is experimental: %s"
	textCodexTrust     = "In Codex run /hooks and trust \"precinto\", so prompts pause when the folder locks."
	textNeedExp        = "%s support is experimental: add --experimental."
	textDoctorOK       = "no problems found."
	textFactorRemove   = "Remove the unlock method %s from every folder? [y/N]"
	textFactorRemoved  = "removed %s."
	textFactorAdded    = "added %s to every folder."
	textFactorTested   = "%s works."
	textFactorNeedOpen = "unlock every folder first: precinto unlock --all"
	textRepairDiff     = "  %s: %s"
	textRepairNothing  = "%s's vault matches the key you unlocked; nothing to repair."
	textRepairExposed  = "  exposed: %s"
	textBusySweep      = "another sweep is running; it will rescan."
	textResumeHarness  = "resume supports claude-code and codex."
	textWorkerFailed   = "could not start the background sealer: %s"
)

// Typed confirmation words (C12.typed, C14.confirm, C2.confirmall).
const (
	wordForget    = "forget"
	wordPrune     = "prune"
	wordUnprotect = "unprotect"
	wordRepair    = "repair"
	wordUnlock    = "unlock"
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
