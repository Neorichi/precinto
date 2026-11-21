package ui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// TTY is an opened controlling terminal (/dev/tty), used for prompts that
// must not go through redirected stdio. *TTY implements ipc.UIHandler
// (Display, Secret, Confirm), asserted in cmd/precinto, so the CLI relays
// daemon prompts without an adapter.
type TTY struct {
	in, out *os.File
	modes   termModes   // nil: golang.org/x/term; tests over pipes use a no-op
	owned   bool        // Close closes in and out
	mu      sync.Mutex  // serializes prompts and output; held for a whole prompt
	closed  bool        // guarded by mu
	abort   atomic.Bool // set by Close: a running prompt cancels within pollInterval
}

// OpenTTY opens /dev/tty; it fails in hooks (no controlling terminal).
func OpenTTY() (*TTY, error) { return openTTY(devTTY) }

// Close releases the terminal.
func (t *TTY) Close() error {
	if t == nil {
		return os.ErrInvalid
	}
	// A prompt running in another goroutine notices abort within
	// pollInterval, restores the terminal mode and releases mu.
	t.abort.Store(true)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if !t.owned {
		return nil
	}
	var errs []error
	if t.in != nil {
		errs = append(errs, t.in.Close())
	}
	if t.out != nil && t.out != t.in {
		errs = append(errs, t.out.Close())
	}
	return errors.Join(errs...)
}

// Printf writes to the terminal.
func (t *TTY) Printf(format string, args ...any) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.usable() != nil {
		return
	}
	// Arguments are folder paths, config values and diffs, which a process
	// of the same user can edit: control characters never reach the
	// terminal (S17).
	_ = t.write(SanitizeTerminal([]byte(fmt.Sprintf(format, args...))))
}

// Display shows one informational line (ipc.UIHandler).
func (t *TTY) Display(msg string) error {
	if t == nil {
		return errNotOpen
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.usable(); err != nil {
		return err
	}
	return t.write(oneLine(msg))
}

// Secret prompts and reads a secret with echo off directly into a locked
// buffer; Ctrl-C returns ErrCancelled (ipc.UIHandler).
func (t *TTY) Secret(prompt string) (*memguard.LockedBuffer, error) {
	if t == nil {
		return nil, errNotOpen
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.usable(); err != nil {
		return nil, err
	}
	return t.secret(prompt)
}

// Confirm asks a question answered by typing yes or no (the words of the
// relayed request, ipc.UIHandler); anything else counts as no.
func (t *TTY) Confirm(prompt, yes, no string) (bool, error) {
	text, yesWord, ambiguous := confirmText(prompt, yes, no)
	line, err := t.visiblePrompt(text)
	if err != nil {
		return false, err
	}
	answer := strings.Join(strings.Fields(line), " ")
	return !ambiguous && strings.EqualFold(answer, yesWord), nil
}

// YesNo asks a [y/N] or [Y/n] question.
func (t *TTY) YesNo(prompt string, def bool) (bool, error) {
	if t == nil {
		return false, errNotOpen
	}
	text, def := yesNoHint(prompt, def)
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.usable(); err != nil {
		return false, err
	}
	s, err := t.begin()
	if err != nil {
		return false, err
	}
	defer s.end()
	for i := 0; i < yesNoTries; i++ {
		line, err := t.readVisible(s, text)
		if err != nil {
			return false, err
		}
		answer := def
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
		case "y", "yes":
			answer = true
		case "n", "no":
			answer = false
		default:
			continue // asked again
		}
		if s.end() {
			return false, ErrCancelled
		}
		return answer, nil
	}
	return false, ErrCancelled
}

// ReadLine reads one visible line (typed-back confirmations such as
// MsgConfirmTyped and MsgUnlockConfirmAll).
func (t *TTY) ReadLine(prompt string) (string, error) { return t.visiblePrompt(promptText(prompt)) }

// ShowSecretScreen shows lines on the alternate screen (the secret in
// groups of 6), requires the user to type back its last confirmLast
// characters (4, D7), then clears screen and scrollback (ESC[2J ESC[3J,
// iTerm2 ClearScrollback) and leaves the alternate screen. The buffer is not
// retained.
func (t *TTY) ShowSecretScreen(header []string, secret *memguard.LockedBuffer, confirmLast int) error {
	return t.showSecretScreen(header, secret, confirmLast)
}

// ErrCancelled is returned when the user cancels a prompt.
var ErrCancelled = errorString("ui: cancelled")

type errorString string

func (e errorString) Error() string { return string(e) }

// Interactive reports whether both stdin and stdout are terminals.
func Interactive(stdin, stdout *os.File) bool { return isTerminal(stdin) && isTerminal(stdout) }

// AgentContext reports whether the current process runs inside an AI agent
// session: any paths.AgentMarkers, or an ancestor whose executable is a
// known harness (claude, codex, droid, cursor-agent, copilot, gemini, kimi,
// opencode), or no controlling terminal (D59). The returned string names
// the evidence (D7, D28). An ancestor whose lookup fails for any reason
// other than having exited (platform.ErrNoProcess) is an agent context
// ("process ancestry unavailable"); an exited ancestor ends the walk (the
// no-controlling-terminal rule covers reparented processes). In -tags
// testing builds only, the walk also ends at the process named by
// paths.TestAncestryStop (D64): it and its ancestors are ignored,
// everything below is checked, and markers and the no-controlling-terminal
// rule still apply.
func AgentContext(e paths.Env, t platform.ProcTable) (bool, string) {
	return agentContext(e, t, agentProbe{
		markers: paths.AgentMarkers,
		pid:     os.Getpid(),
		ctty:    hasControllingTerminal,
	})
}

// SanitizeTerminal strips C0/C1 control characters except '\n' and '\t'
// (escape-sequence injection defence for `precinto cat` to a TTY, S17).
func SanitizeTerminal(b []byte) []byte { return sanitizeTerminal(b) }

// FactorName names the first usable unlock factor of kinds (a folder's
// enrolled factor kinds in unlock order, ipc.VaultStatus.Factors) for
// {factor}: "Mac password" for "se" when a GUI dialog can appear (gui,
// from platform.DetectUIContext), "security key" for "plugin", "precinto
// passphrase" for "passphrase"; "" when none is usable (then callers use
// the .plain variant of the message). "recovery" is never named.
func FactorName(kinds []string, gui bool) string {
	for _, k := range kinds {
		switch k {
		case "se":
			if gui {
				return "Mac password"
			}
		case "plugin":
			return "security key"
		case "passphrase":
			return "precinto passphrase"
		}
	}
	return ""
}

// Reason is why a folder is locked, as shown to users (SPEC §16.3 C3).
type Reason string

// Lock reasons.
const (
	ReasonIdle   Reason = "idle"   // "idle N min"
	ReasonScreen Reason = "screen" // "screen locked"
	ReasonLimit  Reason = "limit"  // "8 h limit reached"
	ReasonManual Reason = "manual" // "locked by you"
	ReasonSleep  Reason = "sleep"  // "computer slept"
	ReasonStart  Reason = "start"  // never unlocked since the agent started
	ReasonAgent  Reason = "agent"  // "the precinto agent stopped responding"
)

// MsgID identifies a catalog message (SPEC §16.3; text from the UX review).
type MsgID string

// Catalog. The comment gives the normative English text with
// {placeholders} (\n is a line break); Format renders the same text from
// an unexported table that a unit test keeps identical to these comments.
// Two texts are also frozen outside this package and asserted
// byte-identical by tests: MsgNoteMarker (sweep.MarkerText writes it,
// plus a final newline) and MsgShimFailed (the static block text of the
// byte-frozen POSIX shims, D41).
const (
	MsgEnterNotify        MsgID = "C1.notify"          // precinto: {folder} is locked. It unlocks when you start claude or codex here, or run: precinto unlock
	MsgEnterPrompt        MsgID = "C1.prompt"          // precinto: {folder} is locked. Unlock now with your {factor}? [Enter = yes · any other key = skip]
	MsgEnterPromptPlain   MsgID = "C1.prompt.plain"    // precinto: {folder} is locked. Unlock now? [Enter = yes · any other key = skip]
	MsgEnterElsewhere     MsgID = "C1.elsewhere"       // precinto: {folder} is being unlocked in another terminal.
	MsgUnlockSE           MsgID = "C2.se"              // precinto: unlock {folder} for {harness} ({tty}). Enter your Mac password in the system dialog. (Ctrl-C to cancel)
	MsgUnlockHook         MsgID = "C2.hook"            // precinto: {harness} in {folder} asks to unlock it. Approve the system dialog, or cancel it to keep the folder locked.
	MsgUnlockPassphrase   MsgID = "C2.passphrase"      // precinto passphrase for {folder} (Ctrl-C to cancel):
	MsgUnlockTouch        MsgID = "C2.touch"           // Touch your YubiKey...
	MsgUnlockOK           MsgID = "C2.ok"              // precinto: {folder} unlocked. Restoring {n} recent sessions in the background. Locks after {idle} idle, at {until} at the latest.
	MsgUnlockCancelled    MsgID = "C2.cancelled"       // precinto: unlock cancelled. {folder} stays locked.
	MsgUnlockBadSecret    MsgID = "C2.badsecret"       // precinto: that passphrase or recovery key is not right. {folder} stays locked.
	MsgUnlockNoGUI        MsgID = "C2.nogui"           // precinto: the Mac password dialog can't appear inside tmux or over SSH. Run precinto unlock in a local terminal tab; every terminal unlocks at once.
	MsgUnlockPassFallback MsgID = "C2.passfallback"    // Using your precinto passphrase instead.
	MsgUnlockConfirmAll   MsgID = "C2.confirmall"      // precinto: unlock {n} folders ({folder} …)? Each asks for presence once. Type "unlock" to confirm:
	MsgPromptBlocked      MsgID = "C3.blocked"         // precinto: {folder} is locked ({reason}). Your message was not sent; press ↑ to get it back after unlocking. To unlock, run precinto unlock in any terminal.
	MsgPromptUnlockCxl    MsgID = "C3.cancelled"       // precinto: unlock cancelled. Your message was not sent (press ↑ to get it back).
	MsgAgentDown          MsgID = "C3.agentdown"       // precinto: the precinto agent isn't running, so {folder} stays locked. Run precinto unlock in a terminal.
	MsgGateFailed         MsgID = "C3.failed"          // precinto: precinto could not check {folder}, so it stays locked. Run precinto unlock in a terminal, then precinto doctor if this repeats.
	MsgToolStop           MsgID = "C3.stop"            // precinto: {folder} is locked
	MsgMovedFolder        MsgID = "C3.moved"           // precinto: this session moved into {other}, which is locked. Run precinto unlock --root {other}.
	MsgToolDenied         MsgID = "C3.tooldenied"      // precinto: the user's project {folder} is locked. Do not retry this tool or use other tools. End your turn now with one short sentence asking the user to run "precinto unlock".
	MsgCompactPaused      MsgID = "C3.compact"         // precinto: compaction is paused while {folder} is locked.
	MsgStartLockedModel   MsgID = "C3.start.model"     // precinto: this project is locked. If precinto denies a tool, stop and ask the user to run "precinto unlock".
	MsgStartLockedUser    MsgID = "C3.start.user"      // precinto: {folder} is locked. Your first message will ask you to unlock.
	MsgCodexWrongHome     MsgID = "C3.codexhome"       // precinto: Codex in {folder} must be started with precinto run codex (or the shell integration) so its history stays in the folder's sealed home.
	MsgOverlayTitle       MsgID = "C4.title"           // Locked by precinto
	MsgOverlayLine        MsgID = "C4.line"            // {folder} · locked after {reason}
	MsgOverlayPaused      MsgID = "C4.paused"          // Your session is paused, not closed. It continues where it was.
	MsgOverlayKeys        MsgID = "C4.keys"            // Enter   unlock ({factor})          Ctrl-D   end session and seal it
	MsgOverlayKeysPlain   MsgID = "C4.keys.plain"      // Enter   unlock          Ctrl-D   end session and seal it
	MsgOverlayBusy        MsgID = "C4.busy"            // {harness} is finishing its current step. New messages wait until you unlock.
	MsgOverlayEnding      MsgID = "C4.ending"          // Ending session... sealed.
	MsgEnded              MsgID = "C5.ended"           // precinto: locked {folder} and ended {n} session(s) after {reason}. Resume with: {resume}
	MsgSealedOK           MsgID = "C6.ok"              // precinto: sealed this session ({sid} · {files} files · {size}). {folder} stays unlocked until {idle} idle.
	MsgSealDeferred       MsgID = "C6.deferred"        // precinto: sealing this session as soon as {harness} finishes writing (usually under 2 min).
	MsgSealFailed         MsgID = "C6.failed"          // precinto: WARNING: couldn't seal session {sid} ({cause}). Its files are still readable on disk. Run precinto doctor.
	MsgResumeOlder        MsgID = "C7.older"           // precinto: Claude's list shows your {n} most recent sessions in this folder. Older ones: precinto resume --pick
	MsgResumeMiss         MsgID = "C7.miss"            // precinto: session {sid} is sealed. Resume it with: claude --resume {sid}
	MsgResumeTwice        MsgID = "C7.twice"           // Session {sid} is already open in another terminal (pid {pid}). Opening it twice can lose messages. Open a copy instead (--fork-session)? [Y/n]
	MsgResumeOld          MsgID = "C7.old"             // precinto: Claude deletes sessions older than {days} days when it starts (cleanupPeriodDays). This session was restored with today's date so Claude keeps it; the sealed copy is safe either way.
	MsgPurgeForget        MsgID = "C7.purge"           // precinto: claude purge deletes Claude's own copies of these sessions. precinto keeps its sealed copies (precinto forget deletes them). Run claude purge? [y/N]
	MsgExpiry             MsgID = "C8.expiry"          // precinto: {folder} locks in 10 min ({limit} limit). Run precinto unlock --extend to keep working without interruption.
	MsgCodexUntrusted     MsgID = "C9.codex"           // precinto: Codex hasn't trusted precinto's hooks yet, so it won't pause prompts when this folder locks. Your history is still sealed when Codex exits. In Codex run /hooks and trust "precinto". Start anyway? [Y/n]
	MsgCodexModified      MsgID = "C9.codexmodified"   // precinto: the trust Codex keeps for precinto's hooks doesn't match the hooks precinto ships: they changed since you trusted them, or this Codex version records trust differently. If /hooks in Codex shows them as changed, Codex skips them and won't pause prompts when this folder locks: trust "precinto" again there. Your history is still sealed when Codex exits. Start anyway? [Y/n]
	MsgCodexNoPlugin      MsgID = "C9.codexplugin"     // precinto: this folder's Codex doesn't have precinto's plugin enabled, so it won't pause prompts when the folder locks. Your history is still sealed when Codex exits. Run precinto integrate codex (if it is installed already: precinto codex sync-config --root {folder}). Start anyway? [Y/n]
	MsgClaudeNoHooks      MsgID = "C9.claude"          // precinto: Claude's precinto hooks didn't run in this session (plugin disabled, --bare or disableAllHooks). Prompts weren't paused while locked; the session is sealed now.
	MsgBareWarning        MsgID = "C9.bare"            // precinto: --bare turns off precinto's hooks. This session will be sealed when it ends but won't pause when the folder locks. Continue? [y/N]
	MsgUngatedSession     MsgID = "C9.ungated"         // precinto: {harness} (pid {pid}) runs in {folder} without precinto's hooks, so it can't be paused when the folder locks. Quit it, or start it with: precinto run {harness}
	MsgCodexOutside       MsgID = "C9.codexoutside"    // precinto: {n} Codex conversation(s) from {folder} were saved in your own Codex history, which precinto doesn't seal. Start Codex there with: precinto run codex
	MsgSettingsKept       MsgID = "C9.settings"        // precinto: you passed your own --settings, so precinto did not add its settings that stop Claude compacting or summarizing while you are away. Add idleCompaction: false and awaySummaryEnabled: false to them.
	MsgCodexConsent       MsgID = "C10.consent"        // precinto keeps a separate, sealed Codex history for each protected folder. Codex started in a protected folder through precinto uses that folder's history; elsewhere Codex is unchanged. Protect Codex in {folder}? [Y/n]
	MsgNoteConflict       MsgID = "C11.conflict"       // precinto: {file} changed while it was sealed. Kept both: {file} and {conflict}. Keep one with: precinto resolve {file}
	MsgNoteRestored       MsgID = "C11.restored"       // precinto: restored {file} from the vault (its .md.precinto file had been deleted). To delete it for good: precinto forget {file}
	MsgCodexConflict      MsgID = "C11.codex"          // precinto: Codex ran while its history was sealed: {n} new conversation(s) kept separately. Run: precinto doctor codex
	MsgNoteMarker         MsgID = "C11.marker"         // This note is sealed by precinto. Run `precinto unlock` in this folder to open it.\nid: {unit}
	MsgRefuseAgent        MsgID = "C12.agent"          // precinto: refusing to {action} {folder} from inside an AI agent session. Run precinto {command} yourself in a terminal.
	MsgRefuseCodexLive    MsgID = "C12.codexlive"      // precinto: Codex is already running (pid {pid}) and its history is sealed. Quit it first.
	MsgConfirmTyped       MsgID = "C12.typed"          // precinto: {action} can't be undone. Type "{command}" to confirm:
	MsgPolicyPending      MsgID = "C13.policy"         // precinto: config.toml changes that weaken protection are waiting for your confirmation ({n}). Review them at your next unlock in a terminal.
	MsgPolicyTampered     MsgID = "C13.tampered"       // precinto: the saved copy of the settings you confirmed was changed outside precinto. Until you confirm them again at your next unlock in a terminal, precinto applies the strictest settings.
	MsgPolicyConfirm      MsgID = "C13.confirm"        // Confirm these changes? [y/N]
	MsgVaultTampered      MsgID = "C14.tampered"       // precinto: WARNING: {folder}'s vault file was changed outside precinto, so precinto stopped encrypting there and its files stay readable on disk. Check it, then run: precinto vault repair --root {folder}
	MsgVaultRepairConfirm MsgID = "C14.confirm"        // precinto: reset {folder}'s vault to the key you just unlocked? Capsules sealed since the change will be listed as exposed. Type "repair" to confirm:
	MsgVaultRepaired      MsgID = "C14.repaired"       // precinto: repaired {folder}'s vault; encryption resumes now. {n} capsule(s) sealed while it was changed may be readable by whoever changed it: see precinto status.
	MsgVaultNotGenuine    MsgID = "C14.notgenuine"     // precinto: the key you unlocked does not open {folder}'s older capsules, so its key files may have been replaced too. Nothing was changed. Use your recovery key: precinto vault repair --root {folder} --recovery
	MsgInitRefuseAgent    MsgID = "B.refuse"           // precinto init must be run by you in your own terminal, not by an AI agent: the recovery key would end up in the agent's transcript and be sent to the model provider.
	MsgInitNeedSE         MsgID = "B.needse"           // Unlocking with your Mac password needs age-plugin-se: brew install age-plugin-se, then run precinto init again. (Or use a passphrase only: precinto init --factor passphrase.)
	MsgInitRemote         MsgID = "B.remote"           // precinto: you're in tmux, screen or SSH, where the Mac password dialog can't appear. Add a passphrase as a second way to unlock? [Y/n]
	MsgPassphraseNew      MsgID = "B.passphrase.new"   // Choose a precinto passphrase (at least 12 characters), or press Enter to get a generated one:
	MsgPassphraseAgain    MsgID = "B.passphrase.again" // Type the passphrase again:
	MsgPassphraseWeak     MsgID = "B.passphrase.weak"  // that passphrase is too weak (at least 12 characters and about 80 bits are needed). Try again.
	MsgPassphraseDiff     MsgID = "B.passphrase.diff"  // the two passphrases differ. Try again.
	MsgPassphraseGen      MsgID = "B.passphrase.gen"   // Your new precinto passphrase:
	MsgRecoveryHeader     MsgID = "B.recovery.header"  // Your precinto recovery key. It opens every sealed folder if you lose your other ways to unlock.\nWrite it down and keep it offline. It is shown only once.
	MsgRecoveryAgain      MsgID = "B.recovery.again"   // The recovery key is shown only now. Show it again? [Y/n]
	MsgRecoveryLost       MsgID = "B.recovery.lost"    // WARNING: the recovery key was not confirmed and cannot be shown again. Keep your other ways to unlock safe.
	MsgRecoveryWritten    MsgID = "B.recovery.written" // recovery key written to {file}. Move it offline (it opens every sealed folder).
	MsgRecoveryPrompt     MsgID = "B.recovery.prompt"  // precinto recovery key:
	MsgServiceOffer       MsgID = "B.service"          // Seal in the background every 10 minutes (installs a LaunchAgent)? [Y/n]
	MsgNotProtected       MsgID = "E.notprotected"     // {folder} is not inside a protected folder. Protect it with: precinto protect DIR
	MsgNotInitialized     MsgID = "E.notinit"          // precinto is not set up yet. Run: precinto init
	MsgAgentDownAll       MsgID = "E.agentdown"        // the precinto agent isn't running, so every folder is locked. Unlock with: precinto unlock
	MsgNeedTerminal       MsgID = "E.needtty"          // {command} needs your own terminal (stdin and stdout must be a terminal). Run it yourself in a terminal.
	MsgShimFailed         MsgID = "D.shim"             // precinto: precinto could not run, so this protected folder stays locked. Reinstall precinto, then run: precinto doctor
)

// catalog holds the text of every MsgID (identical to the comments above).
var catalog = map[MsgID]string{
	MsgEnterNotify:        "precinto: {folder} is locked. It unlocks when you start claude or codex here, or run: precinto unlock",
	MsgEnterPrompt:        "precinto: {folder} is locked. Unlock now with your {factor}? [Enter = yes · any other key = skip]",
	MsgEnterPromptPlain:   "precinto: {folder} is locked. Unlock now? [Enter = yes · any other key = skip]",
	MsgEnterElsewhere:     "precinto: {folder} is being unlocked in another terminal.",
	MsgUnlockSE:           "precinto: unlock {folder} for {harness} ({tty}). Enter your Mac password in the system dialog. (Ctrl-C to cancel)",
	MsgUnlockHook:         "precinto: {harness} in {folder} asks to unlock it. Approve the system dialog, or cancel it to keep the folder locked.",
	MsgUnlockPassphrase:   "precinto passphrase for {folder} (Ctrl-C to cancel):",
	MsgUnlockTouch:        "Touch your YubiKey...",
	MsgUnlockOK:           "precinto: {folder} unlocked. Restoring {n} recent sessions in the background. Locks after {idle} idle, at {until} at the latest.",
	MsgUnlockCancelled:    "precinto: unlock cancelled. {folder} stays locked.",
	MsgUnlockBadSecret:    "precinto: that passphrase or recovery key is not right. {folder} stays locked.",
	MsgUnlockNoGUI:        "precinto: the Mac password dialog can't appear inside tmux or over SSH. Run precinto unlock in a local terminal tab; every terminal unlocks at once.",
	MsgUnlockPassFallback: "Using your precinto passphrase instead.",
	MsgUnlockConfirmAll:   "precinto: unlock {n} folders ({folder} …)? Each asks for presence once. Type \"unlock\" to confirm:",
	MsgPromptBlocked:      "precinto: {folder} is locked ({reason}). Your message was not sent; press ↑ to get it back after unlocking. To unlock, run precinto unlock in any terminal.",
	MsgPromptUnlockCxl:    "precinto: unlock cancelled. Your message was not sent (press ↑ to get it back).",
	MsgAgentDown:          "precinto: the precinto agent isn't running, so {folder} stays locked. Run precinto unlock in a terminal.",
	MsgGateFailed:         "precinto: precinto could not check {folder}, so it stays locked. Run precinto unlock in a terminal, then precinto doctor if this repeats.",
	MsgToolStop:           "precinto: {folder} is locked",
	MsgMovedFolder:        "precinto: this session moved into {other}, which is locked. Run precinto unlock --root {other}.",
	MsgToolDenied:         "precinto: the user's project {folder} is locked. Do not retry this tool or use other tools. End your turn now with one short sentence asking the user to run \"precinto unlock\".",
	MsgCompactPaused:      "precinto: compaction is paused while {folder} is locked.",
	MsgStartLockedModel:   "precinto: this project is locked. If precinto denies a tool, stop and ask the user to run \"precinto unlock\".",
	MsgStartLockedUser:    "precinto: {folder} is locked. Your first message will ask you to unlock.",
	MsgCodexWrongHome:     "precinto: Codex in {folder} must be started with precinto run codex (or the shell integration) so its history stays in the folder's sealed home.",
	MsgOverlayTitle:       "Locked by precinto",
	MsgOverlayLine:        "{folder} · locked after {reason}",
	MsgOverlayPaused:      "Your session is paused, not closed. It continues where it was.",
	MsgOverlayKeys:        "Enter   unlock ({factor})          Ctrl-D   end session and seal it",
	MsgOverlayKeysPlain:   "Enter   unlock          Ctrl-D   end session and seal it",
	MsgOverlayBusy:        "{harness} is finishing its current step. New messages wait until you unlock.",
	MsgOverlayEnding:      "Ending session... sealed.",
	MsgEnded:              "precinto: locked {folder} and ended {n} session(s) after {reason}. Resume with: {resume}",
	MsgSealedOK:           "precinto: sealed this session ({sid} · {files} files · {size}). {folder} stays unlocked until {idle} idle.",
	MsgSealDeferred:       "precinto: sealing this session as soon as {harness} finishes writing (usually under 2 min).",
	MsgSealFailed:         "precinto: WARNING: couldn't seal session {sid} ({cause}). Its files are still readable on disk. Run precinto doctor.",
	MsgResumeOlder:        "precinto: Claude's list shows your {n} most recent sessions in this folder. Older ones: precinto resume --pick",
	MsgResumeMiss:         "precinto: session {sid} is sealed. Resume it with: claude --resume {sid}",
	MsgResumeTwice:        "Session {sid} is already open in another terminal (pid {pid}). Opening it twice can lose messages. Open a copy instead (--fork-session)? [Y/n]",
	MsgResumeOld:          "precinto: Claude deletes sessions older than {days} days when it starts (cleanupPeriodDays). This session was restored with today's date so Claude keeps it; the sealed copy is safe either way.",
	MsgPurgeForget:        "precinto: claude purge deletes Claude's own copies of these sessions. precinto keeps its sealed copies (precinto forget deletes them). Run claude purge? [y/N]",
	MsgExpiry:             "precinto: {folder} locks in 10 min ({limit} limit). Run precinto unlock --extend to keep working without interruption.",
	MsgCodexUntrusted:     "precinto: Codex hasn't trusted precinto's hooks yet, so it won't pause prompts when this folder locks. Your history is still sealed when Codex exits. In Codex run /hooks and trust \"precinto\". Start anyway? [Y/n]",
	MsgCodexModified:      "precinto: the trust Codex keeps for precinto's hooks doesn't match the hooks precinto ships: they changed since you trusted them, or this Codex version records trust differently. If /hooks in Codex shows them as changed, Codex skips them and won't pause prompts when this folder locks: trust \"precinto\" again there. Your history is still sealed when Codex exits. Start anyway? [Y/n]",
	MsgCodexNoPlugin:      "precinto: this folder's Codex doesn't have precinto's plugin enabled, so it won't pause prompts when the folder locks. Your history is still sealed when Codex exits. Run precinto integrate codex (if it is installed already: precinto codex sync-config --root {folder}). Start anyway? [Y/n]",
	MsgClaudeNoHooks:      "precinto: Claude's precinto hooks didn't run in this session (plugin disabled, --bare or disableAllHooks). Prompts weren't paused while locked; the session is sealed now.",
	MsgBareWarning:        "precinto: --bare turns off precinto's hooks. This session will be sealed when it ends but won't pause when the folder locks. Continue? [y/N]",
	MsgUngatedSession:     "precinto: {harness} (pid {pid}) runs in {folder} without precinto's hooks, so it can't be paused when the folder locks. Quit it, or start it with: precinto run {harness}",
	MsgCodexOutside:       "precinto: {n} Codex conversation(s) from {folder} were saved in your own Codex history, which precinto doesn't seal. Start Codex there with: precinto run codex",
	MsgSettingsKept:       "precinto: you passed your own --settings, so precinto did not add its settings that stop Claude compacting or summarizing while you are away. Add idleCompaction: false and awaySummaryEnabled: false to them.",
	MsgCodexConsent:       "precinto keeps a separate, sealed Codex history for each protected folder. Codex started in a protected folder through precinto uses that folder's history; elsewhere Codex is unchanged. Protect Codex in {folder}? [Y/n]",
	MsgNoteConflict:       "precinto: {file} changed while it was sealed. Kept both: {file} and {conflict}. Keep one with: precinto resolve {file}",
	MsgNoteRestored:       "precinto: restored {file} from the vault (its .md.precinto file had been deleted). To delete it for good: precinto forget {file}",
	MsgCodexConflict:      "precinto: Codex ran while its history was sealed: {n} new conversation(s) kept separately. Run: precinto doctor codex",
	MsgNoteMarker:         "This note is sealed by precinto. Run `precinto unlock` in this folder to open it.\nid: {unit}",
	MsgRefuseAgent:        "precinto: refusing to {action} {folder} from inside an AI agent session. Run precinto {command} yourself in a terminal.",
	MsgRefuseCodexLive:    "precinto: Codex is already running (pid {pid}) and its history is sealed. Quit it first.",
	MsgConfirmTyped:       "precinto: {action} can't be undone. Type \"{command}\" to confirm:",
	MsgPolicyPending:      "precinto: config.toml changes that weaken protection are waiting for your confirmation ({n}). Review them at your next unlock in a terminal.",
	MsgPolicyTampered:     "precinto: the saved copy of the settings you confirmed was changed outside precinto. Until you confirm them again at your next unlock in a terminal, precinto applies the strictest settings.",
	MsgPolicyConfirm:      "Confirm these changes? [y/N]",
	MsgVaultTampered:      "precinto: WARNING: {folder}'s vault file was changed outside precinto, so precinto stopped encrypting there and its files stay readable on disk. Check it, then run: precinto vault repair --root {folder}",
	MsgVaultRepairConfirm: "precinto: reset {folder}'s vault to the key you just unlocked? Capsules sealed since the change will be listed as exposed. Type \"repair\" to confirm:",
	MsgVaultRepaired:      "precinto: repaired {folder}'s vault; encryption resumes now. {n} capsule(s) sealed while it was changed may be readable by whoever changed it: see precinto status.",
	MsgVaultNotGenuine:    "precinto: the key you unlocked does not open {folder}'s older capsules, so its key files may have been replaced too. Nothing was changed. Use your recovery key: precinto vault repair --root {folder} --recovery",
	MsgInitRefuseAgent:    "precinto init must be run by you in your own terminal, not by an AI agent: the recovery key would end up in the agent's transcript and be sent to the model provider.",
	MsgInitNeedSE:         "Unlocking with your Mac password needs age-plugin-se: brew install age-plugin-se, then run precinto init again. (Or use a passphrase only: precinto init --factor passphrase.)",
	MsgInitRemote:         "precinto: you're in tmux, screen or SSH, where the Mac password dialog can't appear. Add a passphrase as a second way to unlock? [Y/n]",
	MsgPassphraseNew:      "Choose a precinto passphrase (at least 12 characters), or press Enter to get a generated one:",
	MsgPassphraseAgain:    "Type the passphrase again:",
	MsgPassphraseWeak:     "that passphrase is too weak (at least 12 characters and about 80 bits are needed). Try again.",
	MsgPassphraseDiff:     "the two passphrases differ. Try again.",
	MsgPassphraseGen:      "Your new precinto passphrase:",
	MsgRecoveryHeader:     "Your precinto recovery key. It opens every sealed folder if you lose your other ways to unlock.\nWrite it down and keep it offline. It is shown only once.",
	MsgRecoveryAgain:      "The recovery key is shown only now. Show it again? [Y/n]",
	MsgRecoveryLost:       "WARNING: the recovery key was not confirmed and cannot be shown again. Keep your other ways to unlock safe.",
	MsgRecoveryWritten:    "recovery key written to {file}. Move it offline (it opens every sealed folder).",
	MsgRecoveryPrompt:     "precinto recovery key:",
	MsgServiceOffer:       "Seal in the background every 10 minutes (installs a LaunchAgent)? [Y/n]",
	MsgNotProtected:       "{folder} is not inside a protected folder. Protect it with: precinto protect DIR",
	MsgNotInitialized:     "precinto is not set up yet. Run: precinto init",
	MsgAgentDownAll:       "the precinto agent isn't running, so every folder is locked. Unlock with: precinto unlock",
	MsgNeedTerminal:       "{command} needs your own terminal (stdin and stdout must be a terminal). Run it yourself in a terminal.",
	MsgShimFailed:         "precinto: precinto could not run, so this protected folder stays locked. Reinstall precinto, then run: precinto doctor",
}

// Vars fills catalog placeholders.
type Vars struct {
	Folder   string // {folder}: display path (paths.Tilde)
	Other    string // {other}
	Reason   Reason // {reason}: ReasonText(Reason, Idle or Limit)
	Idle     time.Duration
	Harness  string // {harness}
	TTY      string // {tty}
	Factor   string // {factor}
	N        int    // {n}
	Until    time.Time
	Limit    time.Duration
	SID      string // {sid}: short sid (first 8 characters are shown)
	PID      int    // {pid}
	Files    int    // {files}
	Bytes    int64  // {size}: HumanBytes
	Cause    string // {cause}: short error class, never an OS error string
	Resume   string // {resume}: resume command
	Days     int    // {days}
	File     string // {file}
	Conflict string // {conflict}
	Action   string // {action}
	Command  string // {command}
	Unit     string // {unit}: unit key (note markers)
}

// Format renders a catalog message: every {placeholder} of the text is
// replaced from v ({idle} and {limit} as "15 min" / "8 h", {until} as
// 15:04 in v.Until's location, {size} with HumanBytes). An unknown id
// renders as the id itself so a missing entry is visible. Implemented in
// the scaffold.
func Format(id MsgID, v Vars) string {
	text, ok := catalog[id]
	if !ok {
		return string(id)
	}
	sid := v.SID
	if utf8.RuneCountInString(sid) > 8 {
		// The first 8 characters, never a cut inside a multi-byte one.
		n := 0
		for i := range sid {
			if n == 8 {
				sid = sid[:i]
				break
			}
			n++
		}
	}
	reasonDur := v.Idle
	if v.Reason == ReasonLimit {
		reasonDur = v.Limit
	}
	r := strings.NewReplacer(
		"{folder}", v.Folder,
		"{other}", v.Other,
		"{reason}", ReasonText(v.Reason, reasonDur),
		"{idle}", humanDuration(v.Idle),
		"{harness}", v.Harness,
		"{tty}", v.TTY,
		"{factor}", v.Factor,
		"{n}", strconv.Itoa(v.N),
		"{until}", v.Until.Format("15:04"),
		"{limit}", humanDuration(v.Limit),
		"{sid}", sid,
		"{pid}", strconv.Itoa(v.PID),
		"{files}", strconv.Itoa(v.Files),
		"{size}", HumanBytes(v.Bytes),
		"{cause}", v.Cause,
		"{resume}", v.Resume,
		"{days}", strconv.Itoa(v.Days),
		"{file}", v.File,
		"{conflict}", v.Conflict,
		"{action}", v.Action,
		"{command}", v.Command,
		"{unit}", v.Unit,
	)
	return r.Replace(text)
}

// ReasonText renders a Reason with its parameter d, the idle time for
// ReasonIdle ("idle 15 min") or the limit for ReasonLimit ("8 h limit
// reached"). Implemented in the scaffold.
func ReasonText(r Reason, d time.Duration) string {
	switch r {
	case ReasonIdle:
		return "idle " + humanDuration(d)
	case ReasonScreen:
		return "screen locked"
	case ReasonLimit:
		return humanDuration(d) + " limit reached"
	case ReasonManual:
		return "locked by you"
	case ReasonSleep:
		return "computer slept"
	case ReasonStart:
		return "not unlocked yet"
	case ReasonAgent:
		return "the precinto agent stopped responding"
	default:
		return string(r)
	}
}

// humanDuration renders "45 s", "15 min", "8 h" or "1 h 30 min".
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d/time.Second)) + " s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " min"
	case d%time.Hour < time.Minute:
		return strconv.Itoa(int(d/time.Hour)) + " h"
	default:
		return strconv.Itoa(int(d/time.Hour)) + " h " + strconv.Itoa(int(d%time.Hour/time.Minute)) + " min"
	}
}

// HumanBytes renders sizes with decimal units: 512 B, 12 kB, 12 MB, 1.2 GB.
// Implemented in the scaffold.
func HumanBytes(n int64) string {
	switch {
	case n < 1000:
		return strconv.FormatInt(n, 10) + " B"
	case n < 1000*1000:
		return strconv.FormatInt(n/1000, 10) + " kB"
	case n < 1000*1000*1000:
		return strconv.FormatInt(n/(1000*1000), 10) + " MB"
	default:
		return strconv.FormatFloat(float64(n)/1e9, 'f', 1, 64) + " GB"
	}
}

// Writer prints status/summary lines to w with the "precinto: " prefix.
type Writer struct {
	W io.Writer
}

// Line prints one message followed by a newline, adding the "precinto: "
// prefix when the text lacks it. Implemented in the scaffold.
func (w Writer) Line(id MsgID, v Vars) {
	s := Format(id, v)
	if !strings.HasPrefix(s, "precinto") {
		s = "precinto: " + s
	}
	io.WriteString(w.W, s+"\n")
}
