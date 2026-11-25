package platform

// Pinned dependencies of this package (keeps go.mod/go.sum complete from day
// 0 so parallel implementers never edit them).
import (
	_ "golang.org/x/sys/unix"

	_ "github.com/Neorichi/precinto/internal/fsx"
)
