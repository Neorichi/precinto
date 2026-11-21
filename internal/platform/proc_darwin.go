//go:build darwin

package platform

// darwin process identity, process table, open-file holders, waits and signals
// are implemented here by G2 (see doc.go for the mechanisms).
const procImpl = "darwin"
