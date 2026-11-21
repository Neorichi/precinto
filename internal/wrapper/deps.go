package wrapper

// Pinned dependencies of this package (keeps go.mod/go.sum complete from day
// 0 so parallel implementers never edit them).
import (
	_ "github.com/creack/pty"
	_ "golang.org/x/term"
)
