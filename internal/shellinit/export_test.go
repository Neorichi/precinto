package shellinit

// Test-only access to unexported seams (compiled into the test binary only;
// the external tests in package shellinit_test use these).

import (
	"context"

	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/paths"
)

// StatusFunc answers the daemon status query of OnEnter in tests.
type StatusFunc func(ctx context.Context) (ipc.StatusResp, error)

type fakeStatus struct{ f StatusFunc }

func (s fakeStatus) Status(ctx context.Context) (ipc.StatusResp, error) { return s.f(ctx) }
func (s fakeStatus) Close() error                                       { return nil }

// SetStatus replaces the daemon connection of OnEnter: f answers Status, a
// nil f is an unreachable daemon, and dialPanic makes the dial panic. It
// returns a function restoring the real dial.
func SetStatus(f StatusFunc, dialPanic bool) (restore func()) {
	old := dialStatus
	dialStatus = func(ctx context.Context, l paths.Layout) (statusClient, error) {
		if dialPanic {
			panic("dial")
		}
		if f == nil {
			return nil, ipc.ErrNoDaemon
		}
		return fakeStatus{f}, nil
	}
	return func() { dialStatus = old }
}
