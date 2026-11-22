package doctor

import "github.com/precinto/precinto/internal/harness"

// check is one entry of the registry. Run evaluates the entries in this
// order, Codes lists their codes in it, and findings are reported in it.
type check struct {
	code    string
	harness harness.ID // "" when the check is not specific to one harness
	leaks   bool       // runs only with Options.Leaks (slow residue scans)
	// folders: the check looks at the protected folders, their vaults or
	// their settings, so without config.toml (Options.ConfigErr) it is
	// never ok: it looked only at the settings standing in (UX-09).
	folders bool
	run     func(*env) []Finding
}

// registry returns every check in display order. Each code appears exactly
// once; codes shared with `status` attention items are the ipc.Attn*
// constants (one vocabulary, SPEC §16.4).
//
// Interrupted operations (journal leftovers, abandoned staging, history
// hold links) report under interrupted, the privacy of precinto's own
// directories and of Claude's temp folder under permissions, socket
// problems under agent-socket; stuck locks and the heartbeat stay under
// service-running (CC-44).
func registry() []check {
	claudeH, codexH := harness.ClaudeCode, harness.Codex
	return []check{
		{code: CheckConfig, run: checkConfig},
		{code: CheckDiskEncryption, run: checkDiskEncryption},
		{code: CheckUnhardenedBuild, run: checkUnhardenedBuild},
		{code: CheckLoaderEnv, run: checkLoaderEnv},
		{code: CheckBaseSynced, run: checkBaseSynced},
		{code: CheckBackups, run: checkBackups},
		{code: CheckSpotlight, folders: true, run: checkSpotlight},
		{code: CheckCloudRoot, folders: true, run: checkCloudRoot},
		{code: CheckClaudeVersion, harness: claudeH, run: checkClaudeVersion},
		{code: CheckClaudePlugin, harness: claudeH, run: checkClaudePlugin},
		{code: CheckClaudeHooksOff, harness: claudeH, folders: true, run: checkClaudeHooksOff},
		{code: CheckClaudeSettings, harness: claudeH, folders: true, run: checkClaudeSettings},
		{code: CheckClaudeSettingsEnv, harness: claudeH, folders: true, run: checkClaudeSettingsEnv},
		{code: CheckClaudeRetention, harness: claudeH, run: checkClaudeRetention},
		{code: CheckClaudeLegacy, harness: claudeH, folders: true, run: checkClaudeLegacy},
		{code: CheckCodexVersion, harness: codexH, run: checkCodexVersion},
		{code: CheckCodexHooksTrust, harness: codexH, folders: true, run: checkCodexHooksTrust},
		{code: CheckCodexShellNoise, harness: codexH, run: checkCodexShellNoise},
		{code: CheckCodexWrongHome, harness: codexH, folders: true, run: checkCodexWrongHome},
		{code: CheckCodexOutsideRuns, harness: codexH, folders: true, run: checkCodexOutsideRuns},
		{code: CheckExperimentalVersion, run: checkExperimentalVersion},
		{code: CheckRecoveryTested, folders: true, run: checkRecoveryTested},
		{code: CheckPassphraseFactor, folders: true, run: checkPassphraseFactor},
		{code: CheckPluginPin, folders: true, run: checkPluginPin},
		{code: CheckServiceRunning, run: checkServiceRunning},
		{code: CheckAgentSocket, run: checkAgentSocket},
		{code: CheckPermissions, run: checkPermissions},
		{code: CheckServiceTCC, folders: true, run: checkServiceTCC},
		{code: CheckTerminalResidue, leaks: true, run: checkTerminalResidue},
		{code: CheckQuarantine, run: checkQuarantine},
		{code: CheckUnsealed, folders: true, run: checkUnsealed},
		{code: CheckInterrupted, run: checkInterrupted},
		{code: CheckHoldCapped, folders: true, run: checkHoldCapped},
		{code: CheckResidue, run: checkResidue},
		{code: CheckPendingPolicy, folders: true, run: checkPendingPolicy},
		{code: CheckPolicyTampered, folders: true, run: checkPolicyTampered},
		{code: CheckUnprotectedFolders, folders: true, run: checkUnprotectedFolders},
		{code: CheckHistoryPending, harness: claudeH, folders: true, run: checkHistoryPending},
		{code: CheckVaultTampered, folders: true, run: checkVaultTampered},
		{code: CheckExposed, folders: true, run: checkExposed},
		{code: CheckUngatedSession, run: checkUngatedSession},
		{code: CheckConflict, folders: true, run: checkConflict},
	}
}

// folderChecks is the set of codes of the checks that look at the
// protected folders (check.folders).
func folderChecks() map[string]bool {
	m := map[string]bool{}
	for _, c := range registry() {
		if c.folders {
			m[c.code] = true
		}
	}
	return m
}

// codes implements Codes. It returns a fresh slice on every call.
func codes() []string {
	cs := registry()
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.code
	}
	return out
}

// codeRank maps a code to its display position (unknown codes sort last).
func codeRank() map[string]int {
	cs := codes()
	m := make(map[string]int, len(cs))
	for i, c := range cs {
		m[c] = i
	}
	return m
}
