// Command gopanic is a fake precinto binary for the shim tests: it reads
// its payload, then dies of a real Go runtime panic (exit status 2 and a
// stack trace on stderr), the failure the shim must not pass through.
package main

import (
	"io"
	"os"
)

func main() {
	_, _ = io.Copy(io.Discard, os.Stdin)
	var m map[string]int
	m["x"] = 1 // assignment to a nil map: runtime panic
}
