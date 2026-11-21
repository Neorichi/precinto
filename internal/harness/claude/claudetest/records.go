package claudetest

// Record shapes of Claude Code 2.1.329 transcripts (field names only; the
// values are synthetic). Conversation records (user, assistant) carry the
// uuid/parentUuid chain that ScanLinks and the placement table use (SPEC
// §11.3, D11); metadata records (ai-title, last-prompt,
// file-history-snapshot) carry no uuid, as in real transcripts.

// convRecord is a user or assistant record. ParentUUID is null for the
// first record of a chain.
type convRecord struct {
	ParentUUID    *string `json:"parentUuid"`
	IsSidechain   bool    `json:"isSidechain"`
	UserType      string  `json:"userType"`
	Cwd           string  `json:"cwd"`
	SessionID     string  `json:"sessionId"`
	Version       string  `json:"version"`
	GitBranch     string  `json:"gitBranch"`
	AgentID       string  `json:"agentId,omitempty"`
	Slug          string  `json:"slug,omitempty"`
	Type          string  `json:"type"`
	Message       any     `json:"message"`
	RequestID     string  `json:"requestId,omitempty"`
	ToolUseResult any     `json:"toolUseResult,omitempty"`
	UUID          string  `json:"uuid"`
	Timestamp     string  `json:"timestamp"`
}

type userTextMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type userResultMessage struct {
	Role    string            `json:"role"`
	Content []toolResultBlock `json:"content"`
}

type toolResultBlock struct {
	ToolUseID string `json:"tool_use_id"`
	Type      string `json:"type"`
	Content   string `json:"content"`
}

type assistantMessage struct {
	ID           string  `json:"id"`
	Type         string  `json:"type"`
	Role         string  `json:"role"`
	Model        string  `json:"model"`
	Content      []any   `json:"content"`
	StopReason   string  `json:"stop_reason"`
	StopSequence *string `json:"stop_sequence"`
	Usage        usage   `json:"usage"`
}

type usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type textBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolUseBlock struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	Name  string `json:"name"`
	Input any    `json:"input"`
}

type writeInput struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
}

type editInput struct {
	FilePath   string `json:"file_path"`
	OldString  string `json:"old_string"`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all"`
}

type bashInput struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

type writeResult struct {
	Type            string  `json:"type"`
	FilePath        string  `json:"filePath"`
	Content         string  `json:"content"`
	StructuredPatch []any   `json:"structuredPatch"`
	OriginalFile    *string `json:"originalFile"`
}

type editResult struct {
	FilePath   string `json:"filePath"`
	OldString  string `json:"oldString"`
	NewString  string `json:"newString"`
	ReplaceAll bool   `json:"replaceAll"`
}

type bashResult struct {
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	Interrupted bool   `json:"interrupted"`
	IsImage     bool   `json:"isImage"`
}

type aiTitleRecord struct {
	Type      string `json:"type"`
	AITitle   string `json:"aiTitle"`
	SessionID string `json:"sessionId"`
}

type lastPromptRecord struct {
	Type       string `json:"type"`
	LastPrompt string `json:"lastPrompt"`
	SessionID  string `json:"sessionId"`
}

type snapshotRecord struct {
	Type             string       `json:"type"`
	MessageID        string       `json:"messageId"`
	Snapshot         snapshotBody `json:"snapshot"`
	IsSnapshotUpdate bool         `json:"isSnapshotUpdate"`
}

type snapshotBody struct {
	MessageID          string               `json:"messageId"`
	TrackedFileBackups map[string]backupRef `json:"trackedFileBackups"`
	Timestamp          string               `json:"timestamp"`
}

type backupRef struct {
	BackupFileName string `json:"backupFileName"`
	Version        int    `json:"version"`
	BackupTime     string `json:"backupTime"`
}

// registryFile is one sessions/<pid>.json (Claude's live-session registry).
// procStart is opaque: precinto never parses it (SPEC §9.1).
type registryFile struct {
	PID        int    `json:"pid"`
	SessionID  string `json:"sessionId"`
	Cwd        string `json:"cwd"`
	StartedAt  int64  `json:"startedAt"` // Unix milliseconds
	ProcStart  string `json:"procStart"`
	Kind       string `json:"kind"`
	Entrypoint string `json:"entrypoint"`
	Status     string `json:"status,omitempty"` // absent until the first turn
}

// jobFile is one jobs/<id>/state.json (background/supervised session).
type jobFile struct {
	ID        string `json:"id"`
	SessionID string `json:"sessionId"`
	State     string `json:"state"`
	UpdatedAt int64  `json:"updatedAt"` // Unix milliseconds
}

// historyLine is one history.jsonl line.
type historyLine struct {
	Display        string              `json:"display"`
	PastedContents map[string]pasteRef `json:"pastedContents"`
	Timestamp      int64               `json:"timestamp"` // Unix milliseconds
	Project        string              `json:"project"`
	SessionID      string              `json:"sessionId,omitempty"`
}

// pasteRef points at paste-cache/<contentHash>.txt.
type pasteRef struct {
	ID          int    `json:"id"`
	Type        string `json:"type"`
	ContentHash string `json:"contentHash"`
}

type taskFile struct {
	ID          string   `json:"id"`
	Subject     string   `json:"subject"`
	Description string   `json:"description"`
	ActiveForm  string   `json:"activeForm"`
	Status      string   `json:"status"`
	Blocks      []string `json:"blocks"`
	BlockedBy   []string `json:"blockedBy"`
}

type todoItem struct {
	Content    string `json:"content"`
	Status     string `json:"status"`
	ActiveForm string `json:"activeForm"`
}

type subagentMeta struct {
	AgentType   string `json:"agentType"`
	Description string `json:"description"`
}

type mcpLogLine struct {
	Debug     string `json:"debug,omitempty"`
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp"`
	SessionID string `json:"sessionId"`
	Cwd       string `json:"cwd"`
}

// stepKind is one record of the synthetic conversation script.
type stepKind int

const (
	stepPrompt      stepKind = iota // user prompt (marker in the text)
	stepWrite                       // assistant Write tool_use of MDWrites[n]
	stepWriteResult                 // user tool_result of that Write
	stepAITitle                     // ai-title (metadata)
	stepBash                        // assistant Bash tool_use (output spilled to tool-results/)
	stepBashResult                  // user tool_result pointing at tool-results/
	stepSnapshot                    // file-history-snapshot (metadata) of the edited file
	stepEdit                        // assistant Edit tool_use of the edited (non-Markdown) file
	stepEditResult                  // user tool_result of that Edit
	stepAnswer                      // assistant text answer
	stepLastPrompt                  // last-prompt (metadata)
)

type step struct {
	kind stepKind
	n    int // prompt/answer number, or the MDWrites index
}

// hasUUID reports whether records of this kind carry uuid/parentUuid.
func (k stepKind) hasUUID() bool {
	switch k {
	case stepAITitle, stepSnapshot, stepLastPrompt:
		return false
	}
	return true
}

// tailSteps follow the Markdown writes: the title, a Bash call whose output
// is spilled to tool-results/, a checkpointed Edit, an answer and the
// last-prompt record.
var tailSteps = [...]step{
	{kind: stepAITitle},
	{kind: stepBash},
	{kind: stepBashResult},
	{kind: stepSnapshot},
	{stepPrompt, 1},
	{kind: stepEdit},
	{kind: stepEditResult},
	{stepAnswer, 1},
	{kind: stepLastPrompt},
}

// stepAt returns record i of the conversation script of a session that
// writes `writes` Markdown files: the opening prompt, one Write and its
// result per file, tailSteps, then prompt/answer pairs for ever. Callers
// keep at least 1+2·writes records, so every MDWrites path is in the
// transcript. It is O(1), so huge transcripts stream without a script in
// memory.
func stepAt(i, writes int) step {
	switch {
	case i == 0:
		return step{stepPrompt, 0}
	case i <= 2*writes:
		if i%2 == 1 {
			return step{stepWrite, (i - 1) / 2}
		}
		return step{stepWriteResult, (i - 1) / 2}
	}
	k := i - 1 - 2*writes
	if k < len(tailSteps) {
		return tailSteps[k]
	}
	m := k - len(tailSteps)
	if m%2 == 0 {
		return step{stepPrompt, 2 + m/2}
	}
	return step{stepAnswer, 2 + m/2}
}
