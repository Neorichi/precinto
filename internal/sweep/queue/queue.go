package queue

import (
	"time"

	"github.com/precinto/precinto/internal/platform"
)

// Version is the request format.
const Version = 1

// Request asks for one session (or unit) to be sealed once its writer is
// gone. It holds no content.
type Request struct {
	V         int             `json:"v"`
	ID        string          `json:"id"`
	Harness   string          `json:"harness"`
	SID       string          `json:"sid,omitempty"`
	UnitKey   string          `json:"unit_key,omitempty"`
	Reason    string          `json:"reason"`               // SessionEnd reason | "wrapper-exit" | "lock" | "codex-exit"
	WaitFor   platform.ProcID `json:"wait_for,omitempty"`   // process that must exit first (--wait-pid PID:START)
	Warm      bool            `json:"warm,omitempty"`       // clear/resume: seal when the registry no longer names the sid and it is quiet (HA16)
	ConfigDir string          `json:"config_dir,omitempty"` // harness home realpath (must be registered)
	Cwd       string          `json:"cwd,omitempty"`
	At        time.Time       `json:"at"`
	NotBefore time.Time       `json:"not_before,omitempty"` // retry backoff
	Attempts  int             `json:"attempts,omitempty"`
	Deadline  time.Time       `json:"deadline,omitempty"` // give up and report after (codex: ~6 h, HA17)
}

// Enqueue writes r atomically (ID assigned if empty) and returns its id.
func Enqueue(dir string, r Request) (string, error) { panic("unimplemented: queue.Enqueue") }

// List returns pending requests ordered by At.
func List(dir string) ([]Request, error) { panic("unimplemented: queue.List") }

// Update rewrites r (attempts, backoff).
func Update(dir string, r Request) error { panic("unimplemented: queue.Update") }

// Remove deletes a request.
func Remove(dir, id string) error { panic("unimplemented: queue.Remove") }
