# Precinto on Windows, through WSL 2

On Windows, Precinto runs inside **WSL 2**, the Windows Subsystem for Linux: a real Linux system that Windows runs in a lightweight virtual machine. You install Precinto there, together with Claude Code or Codex, keep your projects on WSL's Linux disk, and work from a Linux terminal. Precinto then protects those sessions much as on Linux, with one big difference: your Windows account is the boundary. Any Windows program running as you can become root in the distribution and read the keys of the folders that are unlocked, and locking Windows does not lock them (see [What Precinto does not protect on Windows](#what-precinto-does-not-protect-on-windows)).

There is no native Windows version: `precinto.exe` can be built, but it refuses to do anything. Precinto is pre-release (specification v0.2) and has not been used day to day on Windows yet, so details may still change. What Precinto does and how it works are explained in the [README](../README.md); this page covers what is different on Windows.

## Contents

- [How it fits together](#how-it-fits-together)
- [Set up, step by step](#set-up-step-by-step)
- [Recommended settings](#recommended-settings)
- [What Precinto does not protect on Windows](#what-precinto-does-not-protect-on-windows)
- [Do not install the plugin in Claude Code for Windows](#do-not-install-the-plugin-in-claude-code-for-windows)
- [What Precinto refuses, and what to do](#what-precinto-refuses-and-what-to-do)
- [Checks in `precinto doctor`](#checks-in-precinto-doctor)
- [FAQ](#faq)
- [Design notes](#design-notes)

## How it fits together

| | Inside WSL 2: protected | In Windows: not protected |
|---|---|---|
| Precinto | its Linux build, installed in the distribution | `precinto.exe` refuses to run |
| Claude Code, Codex | their Linux versions, installed and started in the same distribution | Claude Code or Codex for Windows, the Claude desktop app |
| Your projects | the distribution's Linux file system, for example `~/work/acme` | `C:\…` (which Linux sees as `/mnt/c/…`) and every other Windows drive |

- **Everything Precinto protects lives on the distribution's Linux disk:** the folders you protect, the folders of Claude Code (`~/.claude`, with its temporary and cache folders) and Codex (`~/.codex`), and Precinto's own folder (`~/.local/share/precinto`). Windows programs can change files on a Windows drive without Precinto seeing it, so Precinto refuses to seal, restore or keep files there.
- **Precinto runs only a Linux `claude` or `codex`.** WSL adds the Windows `PATH` to the Linux one, so `claude` or `codex` could find a Windows install; Precinto refuses to run it.
- **You unlock in a terminal**, with a passphrase or a YubiKey, not in a window.

## Set up, step by step

### 1. Install WSL 2 and Ubuntu 24.04

You need Windows 11, or Windows 10 version 2004 (build 19041) or later. Open PowerShell as administrator (right-click it, then *Run as administrator*) and run:

```powershell
wsl --install -d Ubuntu-24.04
```

Restart Windows when asked. Then open *Ubuntu 24.04* from the Start menu and choose a Linux user name and password; they are separate from your Windows account. Use this user for everything below: Precinto refuses to run as root.

If you already use WSL, the same command adds Ubuntu 24.04 next to your other distributions. Check that it runs under WSL 2, in PowerShell:

```powershell
wsl -l -v
```

The `VERSION` column must say `2`. If it says `1`, convert the distribution with `wsl --set-version Ubuntu-24.04 2`.

Ubuntu normally starts with systemd under WSL (`systemd=true` under `[boot]` in `/etc/wsl.conf`); keep it that way. Microsoft's guide: [Install WSL](https://learn.microsoft.com/en-us/windows/wsl/install).

### 2. Keep your work on the Linux side

Your Linux home is `/home/<your Linux user>`, or `~` for short. Keep the projects you want to protect there, for example under `~/work`. A project that is on the Windows side today can be copied in from the Ubuntu terminal:

```sh
mkdir -p ~/work
cp -r /mnt/c/path/to/acme ~/work/acme
```

Then work on the copy in `~/work/acme`, not on the original. For a git repository, clone it instead, from its remote or from the Windows copy (`git clone /mnt/c/path/to/acme ~/work/acme`), bring over only the uncommitted files you need, and install its dependencies again inside Ubuntu: a plain copy brings Windows line endings, which git may report as changes in many files, and dependencies built for Windows. You can still open these files from Windows by typing `\\wsl.localhost\Ubuntu-24.04` in the File Explorer address bar, but a Windows program that changes them does so out of Precinto's sight: let your agents work on them from Ubuntu. Microsoft recommends the Linux file system for Linux tools anyway, because it is faster than `/mnt/c`.

### 3. Build and install Precinto

There are no downloads yet, so you build Precinto from its source, inside Ubuntu, as in [Install from source](../README.md#install-from-source). Put the source in the Linux file system too. If your copy is on the Windows side, clone it first with `git clone /mnt/c/path/to/precinto ~/src/precinto`. Then:

```sh
sudo apt update && sudo apt install -y golang-go make git
cd ~/src/precinto                    # your copy of the source
GOTOOLCHAIN=auto make build          # Ubuntu's Go fetches the Go version Precinto needs
sudo install -m 0755 bin/precinto /usr/local/bin/precinto
precinto version
```

The first build downloads that Go version, so it needs network access. Each time you replace the binary later, run `precinto agent --restart`.

### 4. Install Claude Code or Codex inside Ubuntu

Install the harnesses you use inside Ubuntu, with their instructions for Linux, from the Ubuntu terminal (not from PowerShell). If you install them with npm, use a Node.js installed inside Ubuntu too. Then check which programs Linux finds:

```sh
which claude codex
```

Every path it prints must be in the Linux file system, for example under `/home` or `/usr`. A path under `/mnt/` is a Windows install that WSL found through the Windows `PATH`, and Precinto refuses to run it (see [A Windows program](#a-windows-program)).

### 5. Set up Precinto

Run these commands yourself, in your own Ubuntu terminal, not inside an agent session:

```sh
precinto init                       # a passphrase and your recovery key (once)
precinto protect ~/work/acme        # protect a folder in your Linux home
precinto shell-init bash --install  # claude and codex start through the wrapper
precinto integrate claude-code      # install the hooks
precinto integrate codex
```

- `precinto init` asks for a passphrase of at least 12 characters (press Enter to get a generated one of 7 words), then shows your recovery key once. Write the key down and keep it offline; whoever has it can decrypt all your sealed sessions. Test it later with `precinto recover --verify`.
- `precinto protect` also asks, when Codex is installed, whether Precinto should keep a separate, sealed Codex history for the folder.
- `precinto shell-init bash --install` asks first, then adds one line to `~/.bashrc`. Open a new terminal afterwards, so that `claude` and `codex` start through Precinto.
- Codex runs Precinto's hooks only after you trust them: run `/hooks` in Codex, started in a folder that is not protected, and trust Precinto.

Each step is explained in detail in the README's [Quick start](../README.md#quick-start).

### 6. Check the setup

```sh
precinto doctor
```

Under WSL, `doctor` adds the checks described in [Checks in `precinto doctor`](#checks-in-precinto-doctor). `precinto doctor --leaks` also looks for Claude Code and Codex data in your Windows user folders.

### 7. Work

```sh
cd ~/work/acme
claude              # through Precinto, thanks to the shell integration
precinto lock       # when you step away: locking Windows does not lock your folders
precinto unlock     # when you come back, in a terminal
```

Start Claude Code and Codex from a terminal, through Precinto. Under WSL, Precinto cannot see your keyboard and mouse in Windows: only your keystrokes in a session that Precinto started count as activity. In a session started any other way, such as an IDE's chat panel, Precinto's hooks still block prompts and tools while the folder is locked, but typing there does not keep the folder unlocked, and there is no lock screen to hide the conversation.

## Recommended settings

Each of these settings closes a gap that WSL leaves open, and each has a cost. Choose what fits how you work.

### Turn off Windows interoperability

**What.** In Ubuntu, open `/etc/wsl.conf` as administrator, for example with `sudo nano /etc/wsl.conf`. Add these lines, and keep what is already in the file (such as `systemd=true` under `[boot]`):

```ini
[interop]
enabled=false
appendWindowsPath=false
```

Then run `wsl --shutdown` in PowerShell, wait a few seconds and open Ubuntu again: WSL applies the file only when the distribution starts.

**Why.** With interoperability on, as it is by default, every program in the distribution, an agent included, can start Windows programs. One of them is `wsl.exe`, which can open the distribution as root without asking for a password, and root can read the keys of unlocked folders from the memory of Precinto's background agent. `enabled=false` stops programs in the distribution from starting Windows programs. `appendWindowsPath=false` also keeps the Windows `PATH` out of Linux, so `claude` and `codex` can only be the Linux ones.

**Cost.** Ubuntu can no longer start Windows programs: `code .`, `explorer.exe .`, `clip.exe` and the like stop working from the Linux side. Open your WSL folders from VS Code itself instead (see below); if VS Code's WSL extension does not connect on your machine with interop off, you have to choose between the two. Git Credential Manager from Git for Windows, the credential helper Microsoft recommends for git in WSL, is a Windows program too, so `git push` and `git pull` over HTTPS stop working wherever they rely on it, in your agents' sessions too: before you turn interop off, set up git credentials inside Ubuntu, with an SSH key or a Git Credential Manager installed in Linux.

While interop is on, `precinto doctor` warns `wsl-interop`, and `precinto status` lists it among the items that need attention.

**What it does not close.** Turning interop off removes only the direct path from inside. Windows programs of your account can still open the distribution as root (see [What Precinto does not protect on Windows](#what-precinto-does-not-protect-on-windows)). And while the Windows drives are mounted under `/mnt`, as they are by default, a program in the distribution can still write files that Windows or WSL later runs as you, such as a script in your Windows Startup folder or a custom kernel named in `%UserProfile%\.wslconfig`, and so reach root at your next sign-in or the next time WSL starts. To close that route too, stop WSL from mounting the Windows drives, in the same file:

```ini
[automount]
enabled=false
```

Then `/mnt/c` and the other Windows drives are gone from Ubuntu: copy your projects in first (or later from Windows, through `\\wsl.localhost`), check that the tools you rely on, VS Code's WSL extension included, still work, and expect `precinto doctor --leaks` to find no Claude Code or Codex data in your Windows user folders, since it can no longer look there.

### Keep the distribution running

**What.** In Windows, create or edit the file `.wslconfig` in your user profile folder (`%UserProfile%\.wslconfig`; in PowerShell, `notepad "$env:USERPROFILE\.wslconfig"` opens it). Make sure it is named `.wslconfig`, not `.wslconfig.txt`, and add:

```ini
[general]
instanceIdleTimeout=-1
```

Then run `wsl --shutdown` in PowerShell.

**Why.** By default, WSL shuts the distribution down when it has been idle for 15 seconds, for example after you close its last terminal, and Precinto's background agent stops with it. The agent's keys are wiped, so every folder is locked, but nothing seals what the sessions left in plain text until Precinto runs again: the agent seals those leftovers when it next starts. With `-1` the distribution keeps running, and so do Precinto's timers: folders lock after 15 minutes without your input, and their paused sessions are ended and sealed after 60 minutes.

**Cost.** WSL keeps running in the background, with the memory it uses, until you run `wsl --shutdown` or restart Windows. And closing your last terminal no longer locks your folders: they stay unlocked until 15 minutes have passed without your input, with their keys in the memory of Precinto's background agent, so run `precinto lock` (or `precinto lock --end`) before you close it.

Under WSL 2, `precinto doctor` always shows the note `wsl-idle-shutdown`, because it does not read `.wslconfig`, which lives on the Windows side. Microsoft's reference for both files: [Advanced settings configuration in WSL](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).

### Use VS Code with the WSL extension

**What.** Install VS Code on Windows and its [WSL extension](https://learn.microsoft.com/en-us/windows/wsl/tutorials/wsl-vscode). Open your projects in WSL: from Ubuntu with `code .` (this needs interop), or from VS Code with Ctrl+Shift+P and one of the commands that start with "WSL".

**Why.** With the extension, VS Code's server, its terminal and its extensions run inside the distribution. Your files stay on the Linux disk, and the integrated terminal loads your shell integration, so `claude` typed there starts through Precinto as in any other terminal.

**Cost.** The chat panels of IDE extensions start Claude Code or Codex without Precinto's wrapper: the hooks still block prompts and tools while the folder is locked, but typing in the panel does not keep the folder unlocked, and a lock does not hide the conversation. Use the integrated terminal for sessions in protected folders. VS Code without the extension, opening files through `\\wsl.localhost`, is a Windows program, which Precinto does not see.

### Use Windows Terminal, without session restore

**What.** Run Ubuntu in Windows Terminal: it comes with Windows 11, and on Windows 10 you get it from the Microsoft Store, which keeps it up to date. In its *Settings*, under *Startup*, do not choose *Open windows from a previous session*; keep the default, a new tab with the default profile (`"firstWindowPreference": "defaultProfile"` in its settings file).

**Why.** Microsoft recommends Windows Terminal for WSL. Since version 1.21, restoring the previous session also saves the text of your terminals to disk, in Windows Terminal's own folder on the Windows drive, to show it again at the next start: a conversation that was on screen would be copied there, out of Precinto's reach.

**Cost.** Windows Terminal starts with a fresh tab instead of your previous windows.

### Encrypt the Windows drive

**What.** Turn on BitLocker (Windows Pro, Enterprise and Education) or Device encryption (on devices that support it, Windows Home included) for the drive that holds WSL's files, usually C:. Search for "BitLocker" or "Device encryption" in Windows Settings.

**Why.** The distribution's whole Linux disk is a single file, `ext4.vhdx`, on your Windows drive (under `%LocalAppData%` unless you chose another place). When Precinto seals a session it deletes the plain text, but old blocks can survive in that file and on the SSD. Encryption also covers WSL's swap file and Windows' hibernation file (see below). Linux cannot see whether the Windows drive is encrypted, so under WSL `precinto doctor` reports `disk-encryption` as a note, not as ok.

**Cost.** Keep the BitLocker recovery key safe. Device encryption protects the drive only once its recovery key has been backed up to a Microsoft account (or a work account): on a device with only local accounts, the drive stays unprotected even though its data is encrypted.

### Unlock with a YubiKey (optional)

**What.** WSL does not see USB devices on its own; [usbipd-win](https://learn.microsoft.com/en-us/windows/wsl/connect-usb), which Microsoft documents for Windows 11, attaches one to WSL:

1. In Windows, install it: `winget install --interactive --exact dorssel.usbipd-win`.
2. In PowerShell as administrator, find the YubiKey's bus ID with `usbipd list`, and share the device once with `usbipd bind --busid <busid>`.
3. With an Ubuntu terminal open, attach it from PowerShell: `usbipd attach --wsl --busid <busid>` (this needs no administrator). `lsusb` in Ubuntu now lists it.
4. In Ubuntu, install `age-plugin-yubikey` and create a key with it that asks for a touch every time, following its own instructions. Then add it to Precinto, in your own terminal: `precinto factor add plugin:<recipient> --identity-stub FILE --presence touch-always`.

**Why.** A passphrase can be watched while you type it, and on Windows a program running as you can record what you type. A YubiKey keeps its key inside the device and asks for a touch at each unlock.

**Cost.** While the YubiKey is attached to WSL, Windows cannot use it, for example to sign in to websites, and every WSL 2 distribution on the computer can. Attach it again each time you plug it in or WSL restarts. Sharing it with `usbipd bind` lasts until you run `usbipd unbind --busid <busid>` as administrator, across restarts, and it is not limited to WSL: usbipd-win's installer adds a firewall rule that lets the computers of your local network connect to the usbipd service, and USB/IP asks them for no password. So while the key is plugged in but not attached to WSL, another computer on the same network could attach it, then use whatever the key does without a touch, or use up its PIN retries. On networks you do not trust, restrict the `usbipd` rule in the Windows firewall, or unbind the key while you do not need it in WSL. Precinto has not been tested with a real YubiKey yet.

## What Precinto does not protect on Windows

On Windows, **your Windows account is the boundary**. Inside the distribution, Precinto protects your sessions as it does on Linux, with the same limits. Against your Windows account, it can only keep locked folders sealed.

- **Any Windows program running as you can become root in the distribution.** WSL opens a distribution as root for your Windows account without asking for a password: `wsl -u root`, which Microsoft documents for resetting a forgotten Linux password. As root, a program can read every file of the distribution and, from the memory of Precinto's background agent, the keys of the folders that are unlocked at that moment. With interop on, a program inside the distribution can do the same through `wsl.exe`; with interop off it can still get there later, while the Windows drives are mounted, through a file it leaves for Windows or WSL to run as you (see [Turn off Windows interoperability](#turn-off-windows-interoperability)). Locked folders stay sealed: their keys are not in memory. Lock your folders when you leave them, and treat malware in your Windows account as malware running as you, with root in the distribution on top.
- **Programs that run in Windows.** Claude Code or Codex for Windows, the Claude desktop app and Windows editors keep their data in Windows, where Precinto, running inside the distribution, can neither pause nor seal it. Precinto refuses to start a Windows `claude` or `codex`, and `precinto doctor --leaks` lists the Claude Code and Codex data it finds in Windows user folders.
- **Locking Windows.** Win+L, Windows' lock screen and how long you have been away from Windows are invisible from WSL, so they do not lock your folders. Folders still lock after 15 minutes without your keystrokes in a session that Precinto started, when Windows sleeps (at wake, once WSL has moved the distribution's clock forward), 8 hours after an unlock, and with `precinto lock`.
- **Unlocking happens in a terminal.** When a prompt is blocked because its folder is locked, run `precinto unlock` in a terminal, or press Enter on the lock screen of a session that Precinto started; do not wait for an unlock window.
- **When the distribution stops.** If WSL shuts the distribution down (when it is idle, unless you [keep it running](#keep-the-distribution-running); with `wsl --shutdown`; when Windows restarts or updates), every folder locks, but sessions that were running leave their plain text behind until Precinto runs again and seals it.
- **Copies on the Windows side.** A Windows backup that copies `ext4.vhdx` copies whatever the distribution held at that moment: sealed sessions, which are encrypted, but also the plain text of unlocked folders and running sessions, and possibly old blocks of plain text that Precinto deleted after sealing. Encrypt such backups, or leave the virtual disk out of them. Text you copy goes to the Windows clipboard, and to its history if you turned that on.
- **Swap and hibernation on the Windows drive.** WSL gives its virtual machine a swap file on the Windows drive (`%Temp%\swap.vhdx` by default, a quarter of your memory in size), and Windows' hibernation file holds a copy of memory. A running conversation can end up in either. [Encrypting the drive](#encrypt-the-windows-drive) covers both; `swap=0` under `[wsl2]` in `.wslconfig` turns WSL's swap file off if you have memory to spare.

Everything else in [What Precinto protects, and what it does not](../README.md#what-precinto-protects-and-what-it-does-not) applies too; the full list is in [THREAT_MODEL.md](THREAT_MODEL.md).

## Do not install the plugin in Claude Code for Windows

Precinto's plugin belongs in the Claude Code that runs inside the distribution: `precinto integrate claude-code` installs it there, and refuses a Claude Code for Windows. Do not add it to Claude Code for Windows by hand, for example from the `marketplace` folder in Precinto's directory. Its hooks are made for Linux and macOS and may not even start in Windows, and Precinto declares them to block when they fail: Claude Code for Windows could then refuse your prompts and tools in every folder, protected or not. They would protect nothing there anyway, since Precinto does not run in Windows.

## What Precinto refuses, and what to do

Each refusal names what Precinto found. The messages below are shown as Precinto prints them, with example paths.

### WSL 1

```text
precinto: this Linux distribution runs under WSL 1, where precinto can't protect folders: it needs WSL 2. Convert the distribution in Windows with: wsl --set-version Ubuntu-24.04 2
```

WSL 1 imitates Linux inside Windows, and Precinto needs WSL 2's real Linux kernel to see which processes still write a file. Run the command from the message in PowerShell (`wsl -l -v` lists your distributions and their WSL versions); Microsoft advises a backup before converting a distribution with large projects. Under WSL 1, `init`, `protect`, `unlock`, `run`, `resume`, `integrate`, `seal`, `sweep` and the background agent refuse to work; `lock`, `agent --stop`, `status` and `doctor` still work.

### A folder on a Windows drive

```text
precinto: /mnt/c/work/acme is on a Windows drive, where Windows programs change files without precinto seeing them, so precinto won't seal, restore or keep files there. Use a folder in the Linux file system of this WSL distribution (for example under /home), then try again.
```

Precinto checks where a folder really is, after following symbolic links, and from the Linux mount table, not from its name: `/mnt/c`, any other Windows drive and Windows network shares (SMB shares mounted with `drvfs` or `mount.cifs`) count, wherever they are mounted. It refuses them for the folders you protect, for the folders of Claude Code (its configuration folder, `CLAUDE_CONFIG_DIR` when set, and its temporary and cache folders) and of Codex (`CODEX_HOME` when set), and for Precinto's own folders. To fix it, move the project into your Linux home and protect it there; point `CLAUDE_CONFIG_DIR` or `CODEX_HOME` to the Linux file system, or unset them; keep `HOME`, `XDG_DATA_HOME` and `XDG_RUNTIME_DIR` in the Linux file system, and also `CLAUDE_CODE_TMPDIR`, `TMPDIR`, `TMP`, `TEMP` and `XDG_CACHE_HOME` when they are set, since Claude Code's temporary and cache folders follow them (a `WSLENV` that passes Windows' `TMP` or `TEMP` into Ubuntu puts them on `C:`).

When Precinto cannot tell where a folder is (a broken symbolic link, a folder it cannot read, …), it refuses it all the same, and says why in parentheses:

```text
precinto: precinto could not tell whether ~/.claude is on a Windows drive (it is a dangling symlink), so it won't seal, restore or keep files there. Fix that, or use a folder in the Linux file system of this WSL distribution, then try again.
```

A Claude Code session whose own files are on a Windows drive is blocked even while its folder is unlocked:

```text
precinto: this Claude Code session keeps its files on a Windows drive, where precinto can't seal them, so ~/work/acme stays locked to it. Keep Claude's folders in the Linux file system of this WSL distribution, then start Claude again.
```

### A Windows program

```text
precinto: /mnt/c/tools/npm/claude would run as a Windows program (is on a Windows drive), which precinto can't see or seal from WSL. Install claude inside this WSL distribution, then try again.
```

`precinto run` (and with it the `claude` and `codex` shell functions) and `precinto integrate` check the program they would start. They refuse one that is on a Windows drive or is a Windows executable, and a script whose interpreter is one of those, such as a `node` found on the Windows side; when Precinto cannot check the program, it refuses it too, with a message that starts "precinto: precinto could not check that". `precinto doctor` reports such a program under `claude-version` or `codex-version`. To fix it, install the harness inside Ubuntu ([step 4](#4-install-claude-code-or-codex-inside-ubuntu)), make sure `which claude` prints a Linux path, and consider `appendWindowsPath=false` ([above](#turn-off-windows-interoperability)).

### The recovery key on a Windows drive

```text
precinto: refusing to write the recovery key to /mnt/c/keys/recovery.txt: it is on a Windows drive, which Windows may sync or back up and Windows programs can read
```

`precinto init --recovery-out FILE` writes the recovery key to a file, but never to a Windows drive. Inside a Windows user folder the reason reads "it is inside the Users folder of a Windows drive, which OneDrive can sync", and when Precinto cannot tell, "precinto could not tell whether it is on a Windows drive". Let `precinto init` show the key on screen and write it down, or write it to a new file in your Linux home, outside protected folders, and move it offline yourself.

### Running as root

Precinto refuses to run as root, for example in a terminal opened with `wsl -u root` or with `sudo precinto`. Use the Linux user you created when you installed Ubuntu. If your distribution starts as root, because it was imported without a user, create one and make it the default (`[user]` `default=` in `/etc/wsl.conf`).

## Checks in `precinto doctor`

These checks appear only under WSL:

| Check | What it reports | What to do |
|---|---|---|
| `wsl` | fails under WSL 1, ok under WSL 2 | convert the distribution: `wsl --set-version <distro> 2` in PowerShell |
| `wsl-interop` | warns while Windows interoperability is on | [turn it off](#turn-off-windows-interoperability) in `/etc/wsl.conf`, then run `wsl --shutdown` |
| `wsl-idle-shutdown` | a note, always shown under WSL 2: WSL stops the distribution about 15 seconds after its last terminal closes, and Precinto's background agent with it | [keep the distribution running](#keep-the-distribution-running) with `instanceIdleTimeout=-1` |
| `windows-drive` | fails for each protected folder, Claude Code or Codex folder, or folder of Precinto that is on a Windows drive, or whose place it cannot tell | move it into the Linux file system |
| `windows-harness-data` (with `--leaks`) | warns for each `.claude` or `.codex` folder in a Windows user folder: data of Claude Code or Codex for Windows, which Precinto neither pauses nor seals | run them inside Ubuntu, through Precinto, and delete the Windows copy when you no longer need it |

Two other checks change under WSL:

- `disk-encryption` is a note: Linux cannot see whether BitLocker or Device encryption protects the drive that holds the virtual disk. See [Encrypt the Windows drive](#encrypt-the-windows-drive).
- `claude-version` and `codex-version` fail when the `claude` or `codex` that Precinto would run is a Windows program.

`precinto status` adds a `wsl` line with the WSL version, whether Windows interop is on and where the Windows drives are mounted, and lists WSL 1, interop and anything on a Windows drive among the items that need attention. `precinto status --json` has the same facts in its `wsl` object.

## FAQ

**Can I keep my projects on C:?** No. Precinto refuses folders on Windows drives, because Windows programs can change files there without Precinto seeing it. Keep them in the distribution's Linux file system; you can still reach them from Windows through `\\wsl.localhost\Ubuntu-24.04`.

**Can I use Claude Code for Windows, Codex for Windows or the Claude desktop app?** You can, but Precinto does not protect them: their data stays in Windows, out of its reach. For the folders you want protected, use Claude Code or Codex inside Ubuntu.

**Why did my folder lock while I was typing?** Under WSL, Precinto counts only your keystrokes in a session that it started, through the shell integration or `precinto run`. Prompts typed anywhere else, such as an IDE's chat panel, do not keep a folder unlocked, so it locks 15 minutes after your last keystroke in such a session, or after you unlocked it. Start sessions from a terminal, or unlock again with `precinto unlock`.

**Does locking Windows lock my folders?** No. Run `precinto lock` before you leave, or rely on the 15-minute idle lock.

**What happens when I close the last terminal, or restart Windows?** When Windows restarts, or when you close the last terminal without having [kept the distribution running](#keep-the-distribution-running), the distribution stops, and Precinto's background agent with it: its keys are wiped and every folder is locked. What running sessions left in plain text is sealed when the agent starts again; any unlock starts it.

**Where are my sealed sessions?** In Precinto's folder inside the distribution, `~/.local/share/precinto`, which is stored in the distribution's virtual disk on your Windows drive. Removing the distribution (`wsl --unregister`) deletes them along with everything else in it.

**Can I unlock with Windows Hello or a fingerprint?** No. Under WSL, Precinto unlocks with a passphrase, or with a [YubiKey](#unlock-with-a-yubikey-optional) attached through usbipd-win.

**Does Precinto work under WSL 1, or as a Windows program?** No. It refuses WSL 1 (see [WSL 1](#wsl-1)), and `precinto.exe` refuses to do anything.

**I have several distributions.** Precinto protects only the distribution it is installed in, and only the sessions of the harnesses that run there.

## Design notes

The design behind Windows support, including the reasons for each refusal, is recorded as decisions D155 to D157 in [DECISIONS.md](DECISIONS.md).
