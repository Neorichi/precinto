package doctor

import "github.com/precinto/precinto/internal/harness"

// check is one entry of the registry. Run evaluates the entries in this
// order, Codes lists their codes in it, and findings are reported in it.
type check struct {
	code    string
	harness harness.ID // "" when the check is not specific to one harness
	leaks   bool       // runs only with Options.Leaks (slow residue scans)
	run     func(*env) []Finding
}

// registry returns every check in display order. Each code appears exactly
// once; codes shared with `status` attention items are the ipc.Attn*
// constants (one vocabulary, SPEC §16.4).
//
// Some health checks of this package have no code of their own in the
// contract yet. They report under the code of the component they break,
// and this is the only place that knows it (change request: dedicated
// codes): interrupted operations (journal leftovers) under unsealed,
// abandoned staging directories and the Claude temp directory's
// permissions under residue, history hold links under history-pending,
// and stuck locks, socket problems and the permissions of precinto's own
// directories under service-running (each of them stops the agent or the
// background sweeps).
func registry() []check {
	claudeH, codexH := harness.ClaudeCode, harness.Codex
	return []check{
		{code: CheckDiskEncryption, run: checkDiskEncryption},
		{code: CheckUnhardenedBuild, run: checkUnhardenedBuild},
		{code: CheckLoaderEnv, run: checkLoaderEnv},
		{code: CheckBaseSynced, run: checkBaseSynced},
		{code: CheckBackups, run: checkBackups},
		{code: CheckSpotlight, run: checkSpotlight},
		{code: CheckCloudRoot, run: checkCloudRoot},
		{code: CheckClaudeVersion, harness: claudeH, run: checkClaudeVersion},
		{code: CheckClaudePlugin, harness: claudeH, run: checkClaudePlugin},
		{code: CheckClaudeHooksOff, harness: claudeH, run: checkClaudeHooksOff},
		{code: CheckClaudeSettings, harness: claudeH, run: checkClaudeSettings},
		{code: CheckClaudeSettingsEnv, harness: claudeH, run: checkClaudeSettingsEnv},
		{code: CheckClaudeRetention, harness: claudeH, run: checkClaudeRetention},
		{code: CheckClaudeLegacy, harness: claudeH, run: checkClaudeLegacy},
		{code: CheckCodexVersion, harness: codexH, run: checkCodexVersion},
		{code: CheckCodexHooksTrust, harness: codexH, run: checkCodexHooksTrust},
		{code: CheckCodexShellNoise, harness: codexH, run: checkCodexShellNoise},
		{code: CheckCodexWrongHome, harness: codexH, run: checkCodexWrongHome},
		{code: CheckCodexOutsideRuns, harness: codexH, run: checkCodexOutsideRuns},
		{code: CheckRecoveryTested, run: checkRecoveryTested},
		{code: CheckPassphraseFactor, run: checkPassphraseFactor},
		{code: CheckServiceRunning, run: checkServiceRunning},
		{code: CheckServiceTCC, run: checkServiceTCC},
		{code: CheckTerminalResidue, leaks: true, run: checkTerminalResidue},
		{code: CheckQuarantine, run: checkQuarantine},
		{code: CheckUnsealed, run: checkUnsealed},
		{code: CheckHoldCapped, run: checkHoldCapped},
		{code: CheckResidue, run: checkResidue},
		{code: CheckPendingPolicy, run: checkPendingPolicy},
		{code: CheckPolicyTampered, run: checkPolicyTampered},
		{code: CheckHistoryPending, harness: claudeH, run: checkHistoryPending},
		{code: CheckVaultTampered, run: checkVaultTampered},
		{code: CheckExposed, run: checkExposed},
		{code: CheckUngatedSession, run: checkUngatedSession},
		{code: CheckConflict, run: checkConflict},
	}
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
