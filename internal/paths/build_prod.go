//go:build !testing

package paths

// testingBuild is false in production builds (D6).
const testingBuild = false

// testAncestryStop never reads PRECINTO_TEST_ANCESTRY_STOP outside -tags
// testing builds (D64).
func testAncestryStop(Env) (string, bool) { return "", false }
