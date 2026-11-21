// Package ipc is the daemon protocol: length-prefixed frames (JSON control
// frames, binary secret frames), the request/response structs, the
// mutually-authenticated client, and the server-side listener used by
// internal/agent (SPEC §13; D4, D6, D39).
//
// Owner: G2 (daemon). Imports: stdlib, github.com/awnumar/memguard,
// internal/paths, internal/fsx, internal/platform.
//
// Wire format: every frame is
//
//	uint32 big-endian length (of kind+payload) | 1 byte kind | payload
//
// with kind 'J' (a JSON Request or Response) or 'S' (a secret blob that
// belongs to the preceding JSON frame, which states how many follow). Frames
// are at most MaxFrame bytes. Secrets (passphrases, PINs, per-capsule file
// keys) only ever travel in 'S' frames, are read into caller-owned buffers
// that are wiped, and are never JSON strings (D6). No operation returns an
// identity; Keys returns per-capsule file keys only to a verified precinto
// peer for logged capsules of unlocked vaults (D39).
//
// Client authentication of the server (D6): before sending anything, the
// client checks that RunDir is a directory owned by the uid with mode 0700
// and no symlink, connects, reads the server's peer credentials, and
// requires the server pid's executable to be the same file (dev+inode) as
// its own. The server checks the peer uid on every connection and requires
// a peer that runs the same executable (Conn.PeerSameExecutable) for keys,
// unlock, vault_create, factor_add, vault_repair and policy confirmation,
// for registrations with Wrapper=true, and for Input/Enter activity (whose
// peer must also be the session's registered wrapper, D54) (SPEC §13.2,
// §13.3).
//
// On linux (D65) every hardened precinto process is non-dumpable, so its
// /proc/<pid>/exe cannot be read and the executable check is best effort
// in both directions. The client requires of a hardened daemon the peer
// uid (SO_PEERCRED), that the peer pid holds the exclusive flock on
// run/agent.lock (/proc/locks, matched by inode) and the client's own
// kernel name (comm); the daemon requires of a hardened client the peer
// uid and the same comm (clients hold no lock), and re-verifies the peer
// incarnation for keys and unlock. This stops accidents and naive
// squatters, not a same-uid process that kills the daemon and takes the
// lock under a binary named like precinto (SPEC §19); darwin keeps the full
// executable check both ways.
//
// The daemon never trusts identity facts from a client: requests carry
// pids, which the daemon measures itself (SPEC §9.1), and prompt origins,
// which only the daemon computes (D54).
package ipc
