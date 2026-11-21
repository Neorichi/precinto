//go:build testing

package paths

import "strings"

// testingBuild is true in binaries built with -tags testing: PRECINTO_HOME
// and PRECINTO_RUNTIME_DIR are honoured unconditionally (D6).
const testingBuild = true

// testAncestryStop reads PRECINTO_TEST_ANCESTRY_STOP (D64): testkit sets it
// to the test process so a suite run inside an agent session can still
// exercise the human paths below it.
func testAncestryStop(e Env) (string, bool) {
	v := e.Get(EnvTestAncestryStop)
	if !validProcIDText(v) {
		return "", false
	}
	return v, true
}

// validProcIDText reports whether v is "PID:START" with a positive pid and
// a non-negative start time (decimal, no sign, no spaces); the caller
// parses it with platform.ParseProcID.
func validProcIDText(v string) bool {
	pid, start, ok := strings.Cut(v, ":")
	if !ok || pid == "" || start == "" || len(pid) > 10 || len(start) > 20 {
		return false
	}
	for _, part := range []string{pid, start} {
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return false
			}
		}
	}
	return strings.TrimLeft(pid, "0") != ""
}
