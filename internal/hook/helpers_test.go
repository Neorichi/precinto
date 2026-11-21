package hook_test

import (
	"os"

	"github.com/precinto/precinto/internal/fsx"
)

func mkdirAll(dir string) error { return os.MkdirAll(dir, 0o700) }

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }

// lockHeld takes an exclusive flock on path (flock locks conflict across
// open file descriptions, also within one process) and returns its release.
func lockHeld(path string) (release func(), err error) {
	l, err := fsx.TryLock(path, false)
	if err != nil {
		return nil, err
	}
	return func() { _ = l.Unlock() }, nil
}
