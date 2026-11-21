package doctor_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/harness/codex/codextest"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault"
)

// snapshot records every entry below the given roots: type and mode,
// size, mtime, symlink target and a hash of regular files. Access times are
// left out (reading changes them).
func snapshot(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			fi, err := os.Lstat(p)
			if err != nil {
				return err
			}
			desc := fmt.Sprintf("%v %d %d", fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
			switch {
			case fi.Mode()&fs.ModeSymlink != 0:
				target, err := os.Readlink(p)
				if err != nil {
					return err
				}
				desc += " -> " + target
			case fi.Mode().IsRegular():
				f, err := os.Open(p)
				if err != nil {
					return err
				}
				h := sha256.New()
				_, err = io.Copy(h, f)
				f.Close()
				if err != nil {
					return err
				}
				desc += " " + hex.EncodeToString(h.Sum(nil))
			}
			if fi.IsDir() {
				desc = fmt.Sprintf("%v", fi.Mode()) // a directory's mtime/size follow its entries, compared through them
			}
			out[p] = desc
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// TestReadOnly is the "read-only (no writes under a canary tree)"
// obligation of the doctor contract: a fake HOME carrying every artifact
// a check reads, a full Run with --leaks on the darwin code paths, and the
// whole tree (fake HOME, precinto base, run dir, temp dir) unchanged
// afterwards, down to the bytes and mtimes.
func TestReadOnly(t *testing.T) {
	f := newFixture(t)
	marker := testkit.Marker(t)
	f.secret(marker)
	h := f.h

	// Claude: sessions, history, registry, settings, legacy files, residue.
	l := claudetest.New(t, h.Dir)
	l.WriteSession(t, claudetest.Session{SID: "00000000-0000-4000-8000-000000000001", Cwd: h.Root, Lines: 4, Marker: marker})
	l.WriteHistory(t, h.Root, "00000000-0000-4000-8000-000000000001", 3, marker)
	l.WriteRegistry(t, 4242, "00000000-0000-4000-8000-000000000001", h.Root, "idle", true)
	f.installClaudePlugin()
	writeJSON(t, filepath.Join(h.Root, ".claude", "settings.local.json"), map[string]any{"env": map[string]string{"PRECINTO_BIN": marker}, "disableAllHooks": true})
	writeJSON(t, filepath.Join(h.HomeDir, ".claude.json"), map[string]any{"projects": map[string]any{h.Root: map[string]any{"lastSessionFirstPrompt": marker}}})
	mkdir(t, filepath.Join(h.ClaudeConfig, "session-memory"), 0o700)
	snap := writeFile(t, filepath.Join(h.ClaudeConfig, "shell-snapshots", "snapshot-zsh-1.sh"), "export K="+marker+"\n", 0o600)
	setMtime(t, snap, 72*time.Hour)
	writeFile(t, filepath.Join(h.ClaudeConfig, "usage-data", "u.json"), marker, 0o600)
	if err := os.Link(filepath.Join(h.ClaudeConfig, "history.jsonl"), filepath.Join(h.ClaudeConfig, ".precinto-hold-op9")); err != nil {
		t.Fatal(err)
	}

	// Codex: the user's own home with conversations of a folder, a sealed
	// per-root home written outside precinto.
	codextest.New(t, filepath.Join(h.HomeDir, "work", "codex-home"), codextest.Options{Rollouts: 2, Marker: marker, WithWAL: true, WithLocks: true})
	h.Protect(t, "work/codextest-workspace")
	f.o.Cfg = h.Cfg
	f.o.Cfg.Roots[0].ClaudeSettings = true // protect --claude-settings ran (settings now drifted)
	f.setEnv("CODEX_HOME", filepath.Join(h.HomeDir, "work", "codex-home"))
	codextest.New(t, h.Layout.CodexHome("root-acme"), codextest.Options{Rollouts: 1, Marker: marker})

	// precinto's store: capsules (logged, forged), quarantine, staging,
	// journal, queue, heartbeat, pinned policy, a stale socket, the salt.
	writeFile(t, filepath.Join(h.Layout.CapsulesDir, "claude-code", unitA, "g000001.pcap"), "age-encryption.org/v1\n", 0o600)
	writeFile(t, filepath.Join(h.Layout.CapsulesDir, "claude-code", unitB, "g000001.pcap"), "age-encryption.org/v1\n", 0o600)
	writeFile(t, h.Layout.CapsuleLog, "{}\n", 0o600)
	writeFile(t, filepath.Join(h.Layout.QuarantineDir, "op1", "g000001.pcap"), "x", 0o600)
	writeFile(t, filepath.Join(h.Layout.StagingDir, "op-orphan", "f000001"), marker, 0o600)
	writeFile(t, filepath.Join(h.Layout.JournalDir, "op9.json"), "{}", 0o600)
	writeFile(t, filepath.Join(h.Layout.QueueDir, "q1.json"), "{}", 0o600)
	writeFile(t, h.Layout.SweepLast, "", 0o600)
	setMtime(t, h.Layout.SweepLast, 5*time.Hour)
	writeFile(t, h.Layout.NameSalt, strings.Repeat("s", 32), 0o600)
	writeFile(t, h.Layout.LockFile("sweep"), "", 0o600)
	if err := config.SavePinned(h.Layout.PolicyPinned, config.Pinned{Version: config.PinnedVersion, Config: h.Cfg, MACs: map[string]string{"root-acme": strings.Repeat("0", 64)}}); err != nil {
		t.Fatal(err)
	}
	if ln, err := net.Listen("unix", h.Layout.Socket); err == nil {
		ln.(*net.UnixListener).SetUnlinkOnClose(false)
		ln.Close()
	}
	writeFile(t, filepath.Join(h.HomeDir, "Library", "LaunchAgents", paths.ServiceLabel+".plist"), "<plist/>", 0o644)
	mkdir(t, filepath.Join(h.HomeDir, "Library", "Saved Application State", "com.googlecode.iterm2.savedState"), 0o700)
	mkdir(t, filepath.Join(h.HomeDir, ".tmux", "resurrect"), 0o700)
	writeFile(t, filepath.Join(h.Dir, "tmp", "codex-hook_outputs", "o.txt"), marker, 0o600)

	// A harness process in the folder, holding a file open.
	h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 4242, StartUS: now.Add(-time.Hour).UnixMicro()}, PPID: 1,
		Exe: "/opt/claude/versions/2.1.200", Comm: "2.1.200"})
	h.Procs.SetCwd(4242, h.Root)

	// Dependencies: fakes that report problems everywhere, so every branch
	// runs; the real shell runner on a script that writes nothing; the real
	// Mach-O reader on the test binary.
	noop := writeFile(t, filepath.Join(h.Dir, "bin", "noop-shell"), "#!/bin/sh\nexit 0\n", 0o700)
	f.setEnv("SHELL", noop)
	f.o.Leaks = true
	f.d.GOOS = "darwin"
	f.d.RunShell = doctor.RunLoginShell
	f.d.Executable = os.Executable
	f.d.DiskEncryption = func(context.Context) (bool, bool, error) { return false, true, nil }
	f.d.CloudSynced = func(string) bool { return true }
	f.d.SpotlightIndexed = func(context.Context, string) (bool, bool, error) { return true, true, nil }
	f.d.BackupExcluded = func(context.Context, string) (bool, bool, error) { return false, true, nil }
	f.d.CapsuleLog = func() ([]capslog.Entry, error) {
		return []capslog.Entry{{Path: "claude-code/" + unitA + "/g000001.pcap", HeaderSHA256: "aa", VaultID: "root-acme", RecipientsFpr: "other"}}, nil
	}
	f.d.CapsuleHeaderSHA = func(string) (string, error) { return "bb", nil }
	f.d.JournalPending = func() ([]*journal.Record, error) {
		return []*journal.Record{{ID: "op9", Kind: journal.KindSeal, PID: 99999, Updated: now.Add(-2 * time.Hour)}}, nil
	}
	f.d.QueueList = func() ([]queue.Request, error) {
		return []queue.Request{{ID: "q1", Harness: "codex", At: now.Add(-9 * time.Hour), Deadline: now.Add(-time.Hour)}}, nil
	}
	f.d.Plaintext = func(context.Context) ([]sweep.Plaintext, error) {
		return []sweep.Plaintext{{RootID: "root-acme", Files: 3, Bytes: 9, ByReason: map[string]int{"restored": 1, "inaccessible": 1, doctor.CheckHoldCapped: 1}}}, nil
	}
	// An experimental harness outside its verified range (SPEC §7.3).
	gemini := writeFile(t, filepath.Join(h.Dir, "opt", "gemini-cli", "9.9.9", "bin", "gemini"), "#!/bin/sh\nexit 0\n", 0o700)
	hs := map[string]config.Harness{"gemini": {Enabled: true, Experimental: true, Bin: gemini}}
	for k, v := range f.o.Cfg.Harness {
		hs[k] = v
	}
	f.o.Cfg.Harness = hs
	f.d.Inventory = func(id string) (harness.Inventory, error) {
		if id == "gemini" {
			return harness.Inventory{ID: id, Name: "Gemini CLI", Status: "experimental", VerifiedVersions: ">=0.10.0 <0.11.0",
				Process: harness.ProcessMatch{ExeBasenames: []string{"gemini"}}}, nil
		}
		return harness.Inventory{}, errors.New("no inventory")
	}
	// Restore staging on another volume (a directory standing in for its
	// mount point).
	vol := mkdir(t, filepath.Join(h.Dir, "Volumes", "USB"), 0o700)
	writeFile(t, filepath.Join(vol, ".precinto-staging", "op-vol", "f000001"), marker, 0o600)
	f.o.Cfg.Roots = append(append([]config.Root{}, f.o.Cfg.Roots...), config.Root{ID: "root-usb", Path: mkdir(t, filepath.Join(vol, "notes"), 0o700), MD: config.MDLedger})
	f.d.VolumeRoot = func(p string) string {
		if strings.HasPrefix(p, vol+"/") {
			return vol
		}
		return h.Dir
	}
	// Settings in a subfolder of a protected folder.
	writeJSON(t, filepath.Join(h.Root, "app", ".claude", "settings.json"), map[string]any{"env": map[string]string{"PRECINTO_HOME": marker}})
	f.d.Units = func(context.Context, bool) ([]sweep.UnitInfo, error) {
		return []sweep.UnitInfo{{Unit: unitA, RootIDs: []string{"root-acme"}, Conflicts: 1}}, nil
	}
	f.d.Receipt = func(string) (sweep.Receipt, bool, error) {
		return sweep.Receipt{Files: []sweep.ReceiptFile{{Base: capsule.BaseCodexHome, Rel: "x"}}}, true, nil
	}
	f.d.CodexHooksTrusted = func(string) (bool, bool, error) { return false, true, nil }
	// A pinned plugin whose binary changed since (plugin-pin, D75).
	plug := writeFile(t, filepath.Join(h.Dir, "bin", "age-plugin-yubikey"), "#!/bin/sh\nexit 0\n", 0o700)
	f.d.OpenVault = func(id string) (*vault.Vault, error) {
		return &vault.Vault{Meta: vault.Meta{ID: id, Factors: []vault.Factor{
			{Name: "yubikey", Kind: vault.FactorPlugin, PluginPath: plug, PluginSHA256: strings.Repeat("0", 64)},
			{Name: "passphrase", Kind: vault.FactorPassphrase, ScryptLogN: 10},
		}}}, nil
	}
	f.d.CleanupPeriodDays = func(string) (int, error) { return 1, nil }
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) { return ipc.StatusResp{}, ipc.ErrNoDaemon }

	before := snapshot(t, h.Dir, h.RunDir)
	fs := f.run()
	after := snapshot(t, h.Dir, h.RunDir)

	if len(fs) < 30 {
		t.Errorf("only %d findings: the canary run did not reach every check", len(fs))
	}
	var changed []string
	for p, d := range before {
		if a, ok := after[p]; !ok {
			changed = append(changed, "removed "+p)
		} else if a != d {
			changed = append(changed, "changed "+p+": "+d+" => "+a)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			changed = append(changed, "created "+p)
		}
	}
	sort.Strings(changed)
	for _, c := range changed {
		t.Errorf("doctor wrote: %s", c)
	}
	// The whole tree was read for leaks: none of its content reached a
	// finding (checkInvariants), and the run covered every code that can
	// fire without the agent.
	seen := map[string]bool{}
	for _, x := range fs {
		seen[x.Code] = true
	}
	for _, c := range doctor.Codes() {
		if !seen[c] {
			t.Errorf("no finding of %s in the canary run", c)
		}
	}
	// The new sources each reached their check.
	want(t, fs, doctor.CheckHoldCapped, doctor.Warn, "1 file of "+f.tilde(h.Root))
	want(t, fs, doctor.CheckExperimentalVersion, doctor.Warn, "Gemini CLI 9.9.9 is outside")
	want(t, fs, doctor.CheckInterrupted, doctor.Warn, filepath.Join(vol, ".precinto-staging", "op-vol")+" is an abandoned restore staging folder")
	want(t, fs, doctor.CheckClaudeSettingsEnv, doctor.Fail, f.tilde(filepath.Join(h.Root, "app", ".claude", "settings.json"))+" sets PRECINTO_HOME")
}

// forbiddenCalls are the functions doctor must never call: anything that
// writes, creates, removes, locks, signals, spawns, prompts or unlocks
// (import path → function names).
var forbiddenCalls = map[string][]string{
	"os": {"WriteFile", "Create", "CreateTemp", "Mkdir", "MkdirAll", "MkdirTemp", "Remove", "RemoveAll", "Rename",
		"Chmod", "Chown", "Lchown", "Chtimes", "Symlink", "Link", "Truncate", "Setenv", "Unsetenv", "Clearenv", "StartProcess", "FindProcess"},
	"syscall": {"Kill", "Unlink", "Rmdir", "Mkdir", "Rename", "Chmod", "Flock", "Mkfifo", "Write", "Truncate", "Exec", "ForkExec", "Open"},
	"github.com/precinto/precinto/internal/fsx": {"WriteFileAtomic", "AppendLine", "MkdirPrivate", "TryLock", "WaitLock", "ProbeHeld",
		"NewStaging", "OpenStaging", "SyncDir", "FullSync"},
	"github.com/precinto/precinto/internal/config":   {"Save", "SavePinned", "WriteRootsList"},
	"github.com/precinto/precinto/internal/capsule":  {"Seal", "LoadSalt", "Extract"},
	"github.com/precinto/precinto/internal/platform": {"Signal", "SignalGroup", "Spawn", "ScrubTTY", "ExcludeFromBackup", "Harden"},
	"github.com/precinto/precinto/internal/sweep": {"Seal", "Sweep", "Restore", "RestoreMarkdown", "SealMarkdown", "Prune", "Forget",
		"Quarantine", "Recover", "Resolve", "RotateHistory", "MergeHistory", "OpenNotes", "CatNote", "ReconcileCodex", "DrainQueue", "NextGen"},
	"github.com/precinto/precinto/internal/sweep/queue":   {"Enqueue", "Update", "Remove"},
	"github.com/precinto/precinto/internal/live":          {"Acquire"},
	"github.com/precinto/precinto/internal/harness/codex": {"PrepareHome", "SyncAuthBack"},
	"github.com/precinto/precinto/internal/ui":            {"OpenTTY"},
	"github.com/precinto/precinto/internal/ipc":           {"Listen"},
	"github.com/precinto/precinto/internal/harness":       {"Register"},
}

// forbiddenMethods are method names that mutate state on the types doctor
// can reach (capslog.Log, journal.Journal, ledger.Ledger/Index, vault.Store
// and Vault, fsx.Dir/Staging/Lock, ipc.Client, live.Held, os.Process,
// paths.Layout).
var forbiddenMethods = []string{
	"Append", "MarkDeleted", "Compact", "Begin", "Advance", "Done", "Save", "Put", "Archive",
	"Lock", "Unlock", "Keys", "Repair", "Verify", "Init", "Create", "AddFactor", "RemoveFactor", "Unwrap",
	"Release", "SetChild", "Inheritable", "Register", "Unregister", "Activity", "Gate", "Subscribe",
	"VaultCreate", "FactorAdd", "VaultRepair", "Policy", "Shutdown", "Signal", "Kill", "EnsureDirs",
	"Remove", "Rename", "RenameTo", "Link", "CreateTemp", "Chmod", "Chtimes", "UnlinkIfUnchanged",
	"RemoveEmptyDirs", "Sync", "OpenDir", "Unlink", "Truncate", "WriteAt", "Unlink",
}

// TestNeverWritesSignalsOrUnlocks enforces "doctor never writes, never
// signals and never unlocks" on doctor's own source: no mutating call, a
// read-only os.OpenFile, and ipc.Dial only without autostart.
func TestNeverWritesSignalsOrUnlocks(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	methods := map[string]bool{}
	for _, m := range forbiddenMethods {
		methods[m] = true
	}
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		local := map[string]string{} // import name → path
		for _, imp := range af.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			name := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			local[name] = path
		}
		ast.Inspect(af, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pos := fset.Position(n.Pos())
				if x, ok := sel.X.(*ast.Ident); ok {
					if path, isPkg := local[x.Name]; isPkg {
						for _, bad := range forbiddenCalls[path] {
							if sel.Sel.Name == bad {
								t.Errorf("%s: doctor calls %s.%s", pos, path, bad)
							}
						}
						if path == "os" && sel.Sel.Name == "OpenFile" {
							checkReadOnlyFlags(t, pos, n)
						}
						return true
					}
				}
				if methods[sel.Sel.Name] {
					t.Errorf("%s: doctor calls a mutating method .%s", pos, sel.Sel.Name)
				}
			case *ast.CompositeLit:
				sel, ok := n.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "DialOptions" {
					return true
				}
				for _, el := range n.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Autostart" {
						if v, ok := kv.Value.(*ast.Ident); !ok || v.Name != "false" {
							t.Errorf("%s: doctor dials the agent with Autostart", fset.Position(kv.Pos()))
						}
					}
				}
			}
			return true
		})
	}
	if checked < 10 {
		t.Fatalf("only %d source files checked", checked)
	}
}

// checkReadOnlyFlags requires the flag argument of os.OpenFile to name no
// writing or creating flag.
func checkReadOnlyFlags(t *testing.T, pos token.Position, call *ast.CallExpr) {
	t.Helper()
	if len(call.Args) < 2 {
		return
	}
	ast.Inspect(call.Args[1], func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			switch id.Name {
			case "O_WRONLY", "O_RDWR", "O_CREATE", "O_CREAT", "O_APPEND", "O_TRUNC", "O_EXCL":
				t.Errorf("%s: os.OpenFile with %s", pos, id.Name)
			}
		}
		return true
	})
}
