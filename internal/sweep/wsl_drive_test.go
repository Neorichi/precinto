package sweep

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/paths"
)

// driveAdapter is the fake Claude adapter once its home lies on a Windows
// drive under WSL (D156): Homes leaves the home out, as the Claude adapter
// does; with registered, RegisteredHomes still names it
// (harness.RegisteredHomer), and Targets refuses it with its
// *paths.DriveError, as the Claude adapter's does.
type driveAdapter struct {
	*fakeAdapter
	drive error
}

func (a driveAdapter) Homes(context.Context, harness.Env) ([]harness.Home, error) { return nil, nil }

func (a driveAdapter) Targets(context.Context, harness.Env, harness.UnitRef, string) (harness.TargetRules, error) {
	return harness.TargetRules{}, a.drive
}

type registeredDriveAdapter struct{ driveAdapter }

func (a registeredDriveAdapter) RegisteredHomes(context.Context, harness.Env) ([]harness.Home, error) {
	return a.homes, nil
}

// D156 (F1): a capsule of a registered Claude home that now lies on a
// Windows drive (or whose drive check turned unknown) fails its restore
// with a code of its own, windows-drive, a configuration gap (exit 1):
// the unit key still authenticates against the registered home, and
// Targets refuses the home. Without RegisteredHomes the key matched no
// home (Homes drops it), which reads as a forged capsule (unit-key, 5).
func TestRestoreOfAHomeOnAWindowsDrive(t *testing.T) {
	for _, drive := range []error{
		&paths.DriveError{Path: "/mnt/c/Users/u/.claude"},
		&paths.DriveError{Path: "/home/u/.claude", Unknown: true, Why: "its symlinks loop", Err: syscall.ELOOP},
	} {
		te := newTestEnv(t)
		u, _ := te.sealedSession(sid1, nil)
		te.e.Adapters = []harness.Adapter{registeredDriveAdapter{driveAdapter{te.claude, drive}}}
		rep, _ := te.run().restore(tctx(t), te.keys, RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
		res := outcome(t, rep, u.Key)
		if res.Outcome != OutFailed || !strings.HasPrefix(res.Detail, codeWindowsDrive+": ") {
			t.Fatalf("%v: restore %+v, want failed with %s", drive, res, codeWindowsDrive)
		}
		rerr := rep.Err()
		if !errors.Is(rerr, paths.ErrWindowsDrive) || errors.Is(rerr, harness.ErrUnitKey) || errors.Is(rerr, capsule.ErrUnsafe) {
			t.Fatalf("%v: Report.Err = %v, want ErrWindowsDrive only", drive, rerr)
		}
		if strings.Contains(res.Detail, "/") {
			t.Fatalf("detail %q holds a path", res.Detail)
		}
	}
	// The adapter without RegisteredHomes: the old outcome, for contrast.
	te := newTestEnv(t)
	u, _ := te.sealedSession(sid1, nil)
	te.e.Adapters = []harness.Adapter{driveAdapter{te.claude, &paths.DriveError{Path: "/mnt/c/x"}}}
	rep, _ := te.run().restore(tctx(t), te.keys, RestoreRequest{Units: []harness.UnitRef{refOf(u)}})
	if res := outcome(t, rep, u.Key); !strings.HasPrefix(res.Detail, codeUnitKey+": ") {
		t.Fatalf("without RegisteredHomes: %+v", res)
	}
}

// D156 (F2): under WSL a protected folder on a Windows drive (protected
// with an earlier build, or config.toml edited) keeps its notes in
// plaintext: no seal, no marker, a windows-drive failure that says why;
// and nothing is restored into it once it is (or is found) on a drive.
func TestNotesOfAFolderOnAWindowsDrive(t *testing.T) {
	te := newTestEnv(t)
	p := te.note("docs/notes.md", "# notes\n")
	key := te.noteKey("docs/notes.md")
	onDrive := func(err error) { te.p.drive = func(q string) error { return err } }
	for _, de := range []error{&paths.DriveError{Path: te.h.Root}, &paths.DriveError{Path: te.h.Root, Unknown: true, Why: "the mount table can't be read"}} {
		onDrive(de)
		rep := te.sealNotes()
		if len(rep.Units) != 1 || rep.Units[0].Outcome != OutFailed || !strings.HasPrefix(rep.Units[0].Detail, codeWindowsDrive+": ") {
			t.Fatalf("seal on a drive: %+v", rep.Units)
		}
		if !exists(p) || exists(p+".precinto") || len(te.logged(key)) != 0 {
			t.Fatal("a note of a folder on a Windows drive was sealed")
		}
		if err := rep.Err(); !errors.Is(err, paths.ErrWindowsDrive) {
			t.Fatalf("report error %v", err)
		}
	}
	// Sealed while the folder was on the Linux disk, then found on a
	// drive: the restore refuses, the marker and the capsule stay.
	onDrive(nil)
	if res := outcome(t, te.sealNotes(), key); res.Outcome != OutSealed {
		t.Fatalf("seal off the drive %+v", res)
	}
	onDrive(&paths.DriveError{Path: te.h.Root})
	rep := te.restoreNotes()
	if res := outcome(t, rep, key); res.Outcome != OutFailed || !strings.HasPrefix(res.Detail, codeWindowsDrive+": ") {
		t.Fatalf("restore on a drive %+v", res)
	}
	if exists(p) || !exists(p+".precinto") {
		t.Fatal("a note was restored into a folder on a Windows drive")
	}
	onDrive(nil)
	if res := outcome(t, te.restoreNotes(), key); res.Outcome != OutRestored {
		t.Fatalf("restore off the drive %+v", res)
	}
}
