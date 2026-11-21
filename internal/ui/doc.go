// Package ui holds the terminal interaction primitives (secret prompts into
// locked buffers, confirmations, the alternate-screen recovery-key display),
// agent-context detection (D7, D28) and the normative message catalog of
// SPEC §16.3 (user-facing words: "folder", "locked", "paused", "ended and
// sealed"; never "root", "grant", "soft" or "hard").
//
// Owner: G7 (CLI). Imports: stdlib, golang.org/x/term,
// github.com/awnumar/memguard, internal/paths, internal/platform.
//
// Messages never contain prompt text, session titles or file content.
// The scaffold implements Format, ReasonText, HumanBytes and Writer.Line
// over a catalog table that a unit test keeps identical to the normative
// comments of the MsgID constants; TTY prompts and AgentContext are G7's.
package ui
