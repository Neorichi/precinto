//go:build !testing

package vault

// testingBuild marks -tags testing builds (D6: never shipped), which may
// enroll fast scrypt fixtures like test binaries.
const testingBuild = false
