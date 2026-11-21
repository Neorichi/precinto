//go:build linux

package platform

// linux process identity, process table, open-file holders, waits and signals
// are implemented here by G2 (see doc.go for the mechanisms).
const procImpl = "linux"
