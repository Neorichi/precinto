package doctor

import (
	"errors"
	"path/filepath"

	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/harness/claude"
	"github.com/Neorichi/precinto/internal/paths"
)

// Windows through WSL 2 (D155, D156). These checks find nothing outside
// WSL. Under WSL they report what precinto refuses (WSL 1, its folders on
// a Windows drive) and what it cannot do (stop a Windows program from
// reading the agent's memory, keep the distribution running).

// The fix of a location on a Windows drive, by kind.
const (
	fixDriveFolder = "move the folder into the Linux file system of this WSL distribution (for example under /home) and protect it there"
	fixDriveBase   = "set HOME, or XDG_DATA_HOME and XDG_RUNTIME_DIR, to folders in the Linux file system of this WSL distribution"
	fixDriveClaude = "keep Claude Code's folders (CLAUDE_CONFIG_DIR, its temporary and cache folders) in the Linux file system of this WSL distribution, and run Claude Code from there"
	fixDriveCodex  = "set CODEX_HOME to a folder in the Linux file system of this WSL distribution, or unset it to use ~/.codex there"
)

// wslConvertFix is how a distribution moves to WSL 2.
const wslConvertFix = "in Windows run wsl --set-version <distro> 2 (wsl -l -v lists the distributions)"

func checkWSL(e *env) []Finding {
	switch e.d.WSL().Version {
	case 0:
		return nil
	case 1:
		return []Finding{fail(CheckWSL, "this distribution runs under WSL 1, where precinto does not protect folders: init, protect, unlock and precinto run refuse, and the precinto agent does not start", wslConvertFix)}
	}
	return []Finding{ok(CheckWSL, "precinto runs under WSL 2")}
}

func checkWSLInterop(e *env) []Finding {
	w := e.d.WSL()
	if w.Version == 0 {
		return nil
	}
	const fix = "set enabled=false under [interop] in /etc/wsl.conf, then run wsl --shutdown in Windows (Windows programs of your account can still do it through wsl.exe; lock folders when you leave them)"
	// /etc/wsl.conf decides (paths.WSL.Interop): WSL 2's WSLInterop
	// binfmt entry serves the whole virtual machine, and /init starts a
	// Windows program without it while the distribution's interop runs.
	switch {
	case w.Interop:
		return []Finding{warn(CheckWSLInterop, "Windows interoperability is on (/etc/wsl.conf does not set enabled=false under [interop]): a program of this distribution, an agent included, can run wsl.exe to become the superuser of the distribution and read the keys of unlocked folders from the precinto agent's memory", fix)}
	case !w.InteropKnown:
		return []Finding{info(CheckWSLInterop, "could not tell whether Windows interoperability is on (/etc/wsl.conf could not be read)", fix)}
	}
	return []Finding{ok(CheckWSLInterop, "/etc/wsl.conf turns Windows interoperability off (enabled=false under [interop]): once WSL has restarted since that setting was made (wsl --shutdown), programs of this distribution cannot start Windows programs")}
}

func checkWSLIdle(e *env) []Finding {
	if e.d.WSL().Version != 2 {
		return nil
	}
	return []Finding{info(CheckWSLIdle, "WSL stops this distribution about 15 seconds after its last terminal closes (instanceIdleTimeout): that stops the precinto agent, which wipes the keys, and a folder left unlocked is sealed only when precinto runs again",
		"to keep it running, set instanceIdleTimeout=-1 under [general] in .wslconfig of your Windows profile, then run wsl --shutdown")}
}

// driveLocation is one location checkWindowsDrive judges.
type driveLocation struct {
	what string // "precinto's data folder", "the protected folder", …
	path string
	fix  string
}

func checkWindowsDrive(e *env) []Finding {
	if e.d.WSL().Version == 0 {
		return nil
	}
	var out []Finding
	seen := map[string]bool{}
	for _, l := range e.driveLocations() {
		if l.path == "" || !filepath.IsAbs(l.path) || seen[l.path] {
			continue
		}
		seen[l.path] = true
		err := e.d.CheckDrive(l.path)
		if err == nil {
			continue
		}
		var de *paths.DriveError
		if errors.As(err, &de) && de.Unknown {
			why := ""
			if de.Why != "" {
				why = " (" + de.Why + ")"
			}
			out = append(out, fail(CheckWindowsDrive, "could not tell whether "+l.what+" "+e.show(l.path)+" is on a Windows drive"+why+", so precinto treats it as one and does not seal, restore or keep files there", l.fix))
			continue
		}
		out = append(out, fail(CheckWindowsDrive, l.what+" "+e.show(l.path)+" is on a Windows drive: Windows programs change files there without precinto seeing them, so precinto does not seal, restore or keep files there", l.fix))
	}
	if len(out) == 0 {
		out = append(out, ok(CheckWindowsDrive, "no protected folder, harness folder or folder of precinto is on a Windows drive"))
	}
	return out
}

// driveLocations lists what must not lie on a Windows drive (D156):
// precinto's data and run folders, the protected folders, Claude's
// folders (registered; this environment's config, temporary and cache
// folders, as protect and integrate refuse them; and the config and
// temporary folders hooks reported for Claude sessions, which Claude
// really used), and the Codex home a folder's sealed Codex home is seeded
// from.
func (e *env) driveLocations() []driveLocation {
	l := e.o.Layout
	out := []driveLocation{{"precinto's data folder", l.Base, fixDriveBase}}
	if l.RunDir != "" && !paths.Within(l.Base, l.RunDir) {
		out = append(out, driveLocation{"precinto's run folder", l.RunDir, fixDriveBase})
	}
	for _, r := range e.o.Cfg.Roots {
		out = append(out, driveLocation{"the protected folder", r.Path, fixDriveFolder})
	}
	if e.protectsHarness(harness.ClaudeCode) {
		for _, h := range e.o.Cfg.Harness[string(harness.ClaudeCode)].Homes {
			out = append(out, driveLocation{"Claude's config folder", h.Dir, fixDriveClaude},
				driveLocation{"Claude's temporary folder", h.Tmp, fixDriveClaude},
				driveLocation{"Claude's cache folder", h.Cache, fixDriveClaude})
		}
		dir, tmp, cache, _ := claude.EnvDirs(e.o.Env, e.d.GOOS, e.d.EUID, e.home)
		out = append(out, driveLocation{"Claude's config folder", dir, fixDriveClaude},
			driveLocation{"Claude's temporary folder", tmp, fixDriveClaude},
			driveLocation{"Claude's cache folder", cache, fixDriveClaude})
		if e.d.Sessions != nil {
			if ss, err := e.d.Sessions(harness.ClaudeCode); err == nil {
				for _, s := range ss {
					for _, d := range s.ConfigDirs {
						out = append(out, driveLocation{"Claude's config folder", cleanAbs(d), fixDriveClaude})
					}
					for _, d := range s.TmpDirs {
						out = append(out, driveLocation{"Claude's temporary folder", cleanAbs(d), fixDriveClaude})
					}
				}
			}
		}
	}
	if e.protectsHarness(harness.Codex) {
		if h, err := e.d.CodexUserHome(e.o.Env); err == nil && filepath.IsAbs(h) {
			out = append(out, driveLocation{"Codex's folder", filepath.Clean(h), fixDriveCodex})
		}
	}
	return out
}

// checkWindowsHarnessData (doctor --leaks) lists the Claude Code and Codex
// folders of Windows accounts: <mount root><drive>/Users/<name>/.claude
// and .codex. Sessions of Claude Code or Codex run in Windows write there,
// outside the distribution, and precinto neither gates nor seals them.
func checkWindowsHarnessData(e *env) []Finding {
	w := e.d.WSL()
	if w.Version == 0 {
		return nil
	}
	root := w.MountRoot
	if root == "" {
		root = paths.DefaultWSLMountRoot
	}
	drives, err := listDir(root)
	if err != nil {
		return []Finding{info(CheckWindowsHarnessData, "could not list the Windows drives in "+e.show(root)+" ("+errClass(err)+")", "")}
	}
	var out []Finding
	for _, d := range drives {
		if len(d.Name()) != 1 || !isLetter(d.Name()[0]) {
			continue
		}
		usersDir := filepath.Join(root, d.Name(), "Users")
		users, err := listDir(usersDir)
		if err != nil {
			out = append(out, info(CheckWindowsHarnessData, "could not list "+e.show(usersDir)+" ("+errClass(err)+")", ""))
			continue
		}
		for _, u := range users {
			if !u.IsDir() {
				continue
			}
			for _, h := range []struct{ dir, name string }{{".claude", "Claude Code"}, {".codex", "Codex"}} {
				p := filepath.Join(usersDir, u.Name(), h.dir)
				if !isDir(p) {
					continue
				}
				out = append(out, warn(CheckWindowsHarnessData, h.name+" data of a Windows account is in "+e.show(p)+": sessions of "+h.name+" run in Windows write there, and precinto neither pauses nor seals them",
					"run "+h.name+" inside this WSL distribution through precinto, and delete the Windows copy when you no longer need it"))
			}
		}
	}
	if len(out) == 0 {
		out = append(out, ok(CheckWindowsHarnessData, "no Claude Code or Codex data in the Windows user folders"))
	}
	return out
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// cleanAbs is p cleaned, or "" when it is not absolute (a ledger value).
func cleanAbs(p string) string {
	if !filepath.IsAbs(p) {
		return ""
	}
	return filepath.Clean(p)
}

// wslDiskFix is the disk-encryption fix under WSL: the distribution's disk
// is a virtual disk file on a Windows drive (D156).
const wslDiskFix = "turn on BitLocker or Device Encryption in Windows for the drive that holds the WSL virtual disks (%LocalAppData%\\wsl by default)"

// wslDiskText is the disk-encryption finding under WSL, where Linux cannot
// read whether the drive holding the distribution's disk is encrypted.
const wslDiskText = "could not tell whether disk encryption is on: this distribution's disk is a virtual disk file on a Windows drive, whose BitLocker or Device Encryption Linux cannot read; deleted plaintext can be recovered from that drive unless it is encrypted"
