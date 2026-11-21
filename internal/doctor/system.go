package doctor

import (
	"path/filepath"
	"sort"
	"strings"
)

// System checks: disk encryption, the binary's hardening, the loader
// environment, cloud sync, backups and Spotlight (SPEC §4.6, §8.6, §19).

func checkDiskEncryption(e *env) []Finding {
	ctx, cancel := e.bounded()
	defer cancel()
	on, known, err := e.d.DiskEncryption(ctx)
	fix := "turn on FileVault in System Settings > Privacy & Security"
	what := "FileVault"
	if e.d.GOOS != "darwin" {
		fix = "keep your home directory on an encrypted volume (LUKS, fscrypt)"
		what = "disk encryption"
	}
	switch {
	case err != nil || !known:
		return []Finding{info(CheckDiskEncryption, "could not tell whether "+what+" is on", fix)}
	case !on:
		return []Finding{warn(CheckDiskEncryption, what+" is off: sealed files are safe, but deleted plaintext can be recovered from the disk", fix)}
	}
	return []Finding{ok(CheckDiskEncryption, what+" is on")}
}

func checkUnhardenedBuild(e *env) []Finding {
	if e.d.GOOS != "darwin" {
		return nil // hardened runtime is a macOS code-signing property (SPEC §4.6)
	}
	exe, err := e.d.Executable()
	if err != nil {
		return []Finding{info(CheckUnhardenedBuild, "could not find the precinto executable to check its code signature", "")}
	}
	targets := []string{exe}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		targets[0] = real
	}
	// The pinned link the hook shim runs (D6) may name another binary.
	if real, err := filepath.EvalSymlinks(e.o.Layout.BinLink); err == nil && real != targets[0] {
		targets = append(targets, real)
	}
	var out []Finding
	for _, p := range targets {
		hardened, signed, known, err := hardenedRuntime(p)
		switch {
		case err != nil || !known:
			out = append(out, info(CheckUnhardenedBuild, "could not read the code signature of "+e.show(p), ""))
		case !hardened:
			how := "not code-signed"
			if signed {
				how = "signed without the hardened runtime"
			}
			out = append(out, warn(CheckUnhardenedBuild, e.show(p)+" is "+how+": other programs of your user can inject code into it more easily (S15)",
				"install a signed release of precinto once one is published (builds from source are not hardened)"))
		}
	}
	if len(out) == 0 {
		return []Finding{ok(CheckUnhardenedBuild, "precinto is signed with the hardened runtime")}
	}
	return out
}

// injectionVars are the loader variables that load code into every
// process, precinto included.
var injectionVars = map[string]bool{"DYLD_INSERT_LIBRARIES": true, "LD_PRELOAD": true, "LD_AUDIT": true}

func checkLoaderEnv(e *env) []Finding {
	var names []string
	inject := false
	for _, kv := range e.o.Env.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "DYLD_") || strings.HasPrefix(k, "LD_") {
			names = append(names, k) // names only, never values
			if injectionVars[k] {
				inject = true
			}
		}
	}
	if len(names) == 0 {
		return []Finding{ok(CheckLoaderEnv, "no DYLD_* or LD_* variables are set")}
	}
	sort.Strings(names)
	list := joinNames(names)
	msg := "loader variables are set in this environment (" + list + "): they can load other code into precinto and the harnesses (S15)"
	fix := "unset " + strings.Join(names, " ") + " and remove them from your shell profile"
	if inject {
		return []Finding{fail(CheckLoaderEnv, msg, fix)}
	}
	return []Finding{warn(CheckLoaderEnv, msg, fix)}
}

func checkBaseSynced(e *env) []Finding {
	base := e.o.Layout.Base
	if e.d.CloudSynced(base) {
		return []Finding{fail(CheckBaseSynced, "precinto's data folder "+e.show(base)+" is inside a cloud-synced folder: the Codex homes and restore staging there hold plaintext while folders are unlocked (S9)",
			"exclude "+e.arg(base)+" from syncing")}
	}
	return []Finding{ok(CheckBaseSynced, "precinto's data folder is not cloud-synced")}
}

func checkCloudRoot(e *env) []Finding {
	var out []Finding
	for _, r := range e.o.Cfg.Roots {
		if e.d.CloudSynced(r.Path) {
			out = append(out, warn(CheckCloudRoot, e.folder(r)+" is in a cloud-synced folder: its notes are uploaded while it is unlocked (S17)",
				"move the folder out of the synced location, or exclude it from syncing"))
		}
	}
	if len(out) == 0 && len(e.o.Cfg.Roots) > 0 {
		out = append(out, ok(CheckCloudRoot, "no protected folder is cloud-synced"))
	}
	return out
}

func checkSpotlight(e *env) []Finding {
	if e.d.GOOS != "darwin" {
		return nil
	}
	var out []Finding
	clean := 0
	for _, r := range e.o.Cfg.Roots {
		if !isDir(r.Path) {
			continue
		}
		ctx, cancel := e.bounded()
		indexed, known, err := e.d.SpotlightIndexed(ctx, r.Path)
		cancel()
		switch {
		case err != nil || !known:
			out = append(out, info(CheckSpotlight, "could not tell whether Spotlight indexes "+e.folder(r), ""))
		case indexed:
			out = append(out, warn(CheckSpotlight, "Spotlight indexes "+e.folder(r)+": its index can keep the text of notes after they are sealed (S17)",
				"add "+e.folder(r)+" to System Settings > Siri & Spotlight > Spotlight Privacy"))
		default:
			clean++
		}
	}
	if len(out) == 0 && clean > 0 {
		out = append(out, ok(CheckSpotlight, "Spotlight does not index the protected folders"))
	}
	return out
}

// backupDirs are the harness directories that hold plaintext while folders
// are unlocked; capsules are ciphertext and belong in backups.
func (e *env) backupDirs() []string {
	var dirs []string
	add := func(p string) {
		if p == "" || !isDir(p) {
			return
		}
		for _, d := range dirs {
			if d == p {
				return
			}
		}
		dirs = append(dirs, p)
	}
	for _, d := range e.claudeConfigDirs() {
		add(d)
	}
	for _, h := range e.o.Cfg.Harness["claude-code"].Homes {
		add(h.Cache)
	}
	add(e.codexUserHome())
	add(e.o.Layout.HomesDir)
	add(e.o.Layout.StagingDir)
	return dirs
}

func checkBackups(e *env) []Finding {
	if e.d.GOOS != "darwin" {
		return nil // Time Machine (S18)
	}
	var out []Finding
	checked := 0
	for _, d := range e.backupDirs() {
		ctx, cancel := e.bounded()
		excluded, known, err := e.d.BackupExcluded(ctx, d)
		cancel()
		switch {
		case err == nil && !known:
			checked++ // no backup destination: nothing is backed up
		case err != nil || !known:
			out = append(out, info(CheckBackups, "could not tell whether Time Machine backs up "+e.show(d), ""))
		case !excluded:
			out = append(out, warn(CheckBackups, "Time Machine backs up "+e.show(d)+", which holds plaintext sessions while folders are unlocked (sealed copies are safe in backups)",
				"tmutil addexclusion "+e.arg(d)))
		default:
			checked++
		}
	}
	if len(out) == 0 && checked > 0 {
		out = append(out, ok(CheckBackups, "Time Machine does not back up the harness folders that hold plaintext"))
	}
	return out
}
