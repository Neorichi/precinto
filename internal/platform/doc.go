// Package platform wraps every OS-specific facility precinto needs, cgo-free:
// process identity measured by precinto itself (pid + kernel start time),
// process-table scans by executable, open-file holders, race-free waits and
// signals, peer credentials on Unix sockets, screen-lock / HID-idle / sleep
// triggers, UI-context detection, process hardening and terminal scrubbing
// (SPEC §9, §12.5, §13, §15; D6, D18, D24, D27, D34).
//
// Owner: G2 (daemon). Imports: stdlib, golang.org/x/sys/unix, internal/paths,
// internal/fsx.
//
// Files: platform.go (exported API, shared types), *_darwin.go, *_linux.go
// (implementations), *_other.go (unsupported stubs so `go vet` builds).
// darwin: sysctl kern.proc.pid (kp_proc.p_starttime, p_stat), kern.procargs2
// (exe path), kqueue EVFILT_PROC NOTE_EXIT, getsockopt LOCAL_PEERCRED /
// LOCAL_PEERPID, PT_DENY_ATTACH, `/usr/sbin/ioreg` polling (IOConsoleLocked,
// HIDIdleTime), `lsof` for open-file holders. linux: /proc/<pid>/stat field
// 22 + /proc/sys/kernel/random/boot_id, /proc/<pid>/exe, pidfd_open /
// pidfd_send_signal, SO_PEERCRED, PR_SET_DUMPABLE, `loginctl show-session`
// (LockedHint, IdleSinceHint).
//
// ProcID.IsZero, Ancestors and Descendants are implemented in the scaffold
// (pure walks over a ProcTable); everything OS-specific is G2's.
package platform
