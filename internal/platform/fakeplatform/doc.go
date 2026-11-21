// Package fakeplatform provides deterministic fakes of platform.ProcTable and
// platform.Clock for liveness, state-machine and crash tests
// (docs/TESTPLAN.md "fakes").
//
// Owner: G2 (daemon). Imports: stdlib, internal/platform. Test-only: no
// production package may import it (enforced by internal/archtest).
package fakeplatform
