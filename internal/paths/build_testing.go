//go:build testing

package paths

// testingBuild is true in binaries built with -tags testing: PRECINTO_HOME
// and PRECINTO_RUNTIME_DIR are honoured unconditionally (D6).
const testingBuild = true
