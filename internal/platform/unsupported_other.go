//go:build !darwin && !linux

package platform

import (
	"context"
	"net"
	"os"
	"syscall"

	"github.com/precinto/precinto/internal/paths"
)

// Unsupported platforms (D34): every OS-specific function returns
// ErrUnsupported once implemented; this file keeps `go vet` building.
const (
	procImpl   = "unsupported"
	peerImpl   = "unsupported"
	screenImpl = "unsupported"
	hardenImpl = "unsupported"
)

func sysBootID() string { return "" }

func sysIdentifyState(int) (ProcID, ProcState, error) { return ProcID{}, StateUnknown, ErrUnsupported }

func sysLookup(int) (ProcInfo, error) { return ProcInfo{}, ErrUnsupported }

func sysList() ([]ProcInfo, error) { return nil, ErrUnsupported }

func sysCwd(ProcID) (string, error) { return "", ErrUnsupported }

func sysOpenFilesUnder(context.Context, []string) ([]Holder, error) { return nil, ErrUnsupported }

func isTerminal(*os.File) bool { return false }

func sysGUI(paths.Env) bool { return false }

func cloudRoots(home string) []string { return homeCloudRoots(home) }

func signalProc(ProcID, syscall.Signal) error { return ErrUnsupported }

func signalGroup(int, syscall.Signal) error { return ErrUnsupported }

func waitExit(context.Context, ProcID) error { return ErrUnsupported }

func spawn([]string, SpawnOptions) (ProcID, error) { return ProcID{}, ErrUnsupported }

func executable() (string, uint64, uint64, error) { return "", 0, 0, ErrUnsupported }

func sameExecutable(int) (bool, error) { return false, ErrUnsupported }

func peerOf(*net.UnixConn) (Peer, error) { return Peer{}, ErrUnsupported }

func harden() error { return ErrUnsupported }

func readScreen(context.Context) (ScreenState, error) { return ScreenState{}, ErrUnsupported }

func scrubTTY(string, ScrubOptions) error { return ErrUnsupported }

func diskEncryption(context.Context) (bool, bool, error) { return false, false, ErrUnsupported }

func excludeFromBackup(context.Context, string) error { return ErrUnsupported }

func spotlightIndexed(context.Context, string) (bool, bool, error) {
	return false, false, ErrUnsupported
}
