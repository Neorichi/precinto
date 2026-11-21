// Package generic implements experimental home-mode adapters from
// data-driven inventories (D33, HA20): wrapper-only (no hooks), relocation
// through each harness's env var where available, liveness by wrapper lease
// + open-file holders + lock specs + stability window. Per SPEC §7.3 an
// adapter seals only with `--experimental` through `precinto seal --dormant
// <id>`, and only when no matching process runs, no lock is held, the
// open-file check passes and no -wal/-shm file exists; there is no
// automatic restore in v0.2. verified_versions is informational for
// experimental inventories (doctor warns when the installed version is
// outside it); it never enables sealing by itself.
//
// Owner: G3 (harness adapters). Imports: stdlib, internal/harness and
// everything it may import, inventories.
package generic
