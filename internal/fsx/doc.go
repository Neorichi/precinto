// Package fsx is precinto's only path to the file system for plaintext and
// capsule data: directory-handle (openat) walking that never follows
// symlinks, atomic writes, no-replace renames, unlink-if-unchanged, staging
// directories on the target volume, permission and owner checks, free-space
// checks, flock-based locks and errno classification (SPEC §10–§12, §17;
// D12, D13; invariants I2, I3, I8, I9, I13).
//
// Owner: G1 (crypto core). Imports: stdlib, golang.org/x/sys/unix,
// internal/fsx/failpoint.
//
// Rules every implementation MUST follow:
//   - Below a trusted base, every component is opened with
//     O_NOFOLLOW|O_DIRECTORY relative to its parent fd (darwin may add
//     O_NOFOLLOW_ANY; linux may use openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS).
//     os.Root alone is not sufficient (it follows in-root symlinks).
//   - Every existing directory below a base must be owned by the current uid
//     and must not be group- or other-writable, else ErrUnsafe.
//   - Files are created O_CREAT|O_EXCL|O_NOFOLLOW with mode 0600; directories
//     0700. Restored modes are masked with 0700 (I8).
//   - Durability: File.Sync uses F_FULLFSYNC on darwin; every rename or
//     unlink that commits a state change is followed by a directory fsync.
//   - Every syscall that mutates state calls failpoint.Hit first.
//
// The scaffold implements the leaf helpers every group needs from day one
// (Lstat, Fstat, the Stat predicates, FullSync, SyncDir, WriteFileAtomic,
// AppendLine, TryLock, WaitLock, Lock.Unlock/File) in fsx.go, sys_unix.go
// and the per-OS files; everything else is G1's.
package fsx
