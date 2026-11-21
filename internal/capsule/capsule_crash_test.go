//go:build failpoints

package capsule_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"filippo.io/age"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/fsx/failpoint"
)

// Crash-matrix rows owned by capsule (TESTPLAN §4: capsule.tmp_written,
// capsule.verified, capsule.renamed; SEAL-4/SEAL-5/SEAL-12 capsule parts).

func arm(t *testing.T, spec string) {
	t.Helper()
	failpoint.Reset()
	failpoint.Set(spec)
	t.Cleanup(failpoint.Reset)
}

func TestErrnoAtCapsulePoints(t *testing.T) {
	for _, c := range []struct {
		point     string
		committed bool
	}{
		{"capsule.streamed", false},
		{"capsule.tmp_written", false},
		{"capsule.verified", false},
		{"capsule.renamed", true},
	} {
		t.Run(c.point, func(t *testing.T) {
			u := newUnit(t)
			k := newKeys(t)
			u.write("s.jsonl", randomBytes(t, 5000))
			arm(t, c.point+"=errno:EIO")
			_, err := seal(t, u, k, "g000001.pcap", u.inputs("s.jsonl"), nil, nil)
			if !errors.Is(err, syscall.EIO) {
				t.Fatalf("Seal = %v", err)
			}
			names := u.outNames()
			if c.committed {
				// Left for journal recovery (it removes an unlogged capsule, D58).
				if len(names) != 1 || names[0] != "g000001.pcap" {
					t.Fatalf("after %s: %v", c.point, names)
				}
			} else if len(names) != 0 {
				t.Fatalf("after %s: %v left", c.point, names)
			}
			u.assertPlaintext()
		})
	}
}

func TestErrnoFsxDuringSeal(t *testing.T) {
	for _, c := range []struct {
		spec  string
		class fsx.Class
	}{
		{"fsx.write=errno:ENOSPC", fsx.ClassNoSpace}, // SEAL-12: ENOSPC on the temporary
		{"fsx.write=errno:EDQUOT", fsx.ClassNoSpace},
		{"fsx.fsync=errno:EIO", fsx.ClassIO},
		{"fsx.rename=errno:EROFS", fsx.ClassReadOnly},
	} {
		t.Run(c.spec, func(t *testing.T) {
			u := newUnit(t)
			u.write("s.jsonl", randomBytes(t, 5000))
			arm(t, c.spec)
			_, err := seal(t, u, newKeys(t), "g000001.pcap", u.inputs("s.jsonl"), nil, nil)
			if fsx.Classify(err) != c.class {
				t.Fatalf("Seal = %v (class %q), want %q", err, fsx.Classify(err), c.class)
			}
			if n := u.outNames(); len(n) != 0 {
				t.Fatalf("left %v", n)
			}
			u.assertPlaintext()
		})
	}
}

// TestErrnoDuringExtract is the capsule part of REST-2: ENOSPC while
// staging fails the unit; staging is left for the caller to remove.
func TestErrnoDuringExtract(t *testing.T) {
	u := newUnit(t)
	k := newKeys(t)
	u.write("a", randomBytes(t, 3000))
	u.write("b", randomBytes(t, 3000))
	s, err := seal(t, u, k, "g000001.pcap", u.inputs("a", "b"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := newStaging(t, u.root)
	f, _, _ := u.out.Open(s.Name)
	defer f.Close()
	arm(t, "fsx.write=errno:ENOSPC:2")
	_, staged, err := capsule.Extract(context.Background(), f, capsule.ExtractOptions{FileKey: fileKey(t, u.out, s.Name, k.vault), Staging: st, Limits: capsule.Limits{MaxTotal: 1 << 20}, Check: allowAll})
	if fsx.Classify(err) != fsx.ClassNoSpace || staged != nil {
		t.Fatalf("Extract = %v, %d staged", err, len(staged))
	}
	if err := st.Remove(); err != nil {
		t.Fatalf("caller cleanup: %v", err)
	}
}

const (
	childPoint = "PRECINTO_CAPSULE_CRASH_POINT"
	childRoot  = "PRECINTO_CAPSULE_CRASH_ROOT"
	childOut   = "PRECINTO_CAPSULE_CRASH_OUT"
	childRcpt  = "PRECINTO_CAPSULE_CRASH_RCPT"
)

// TestCapsuleCrashChild runs only inside a re-executed test binary: it
// seals one file with a crash point armed and must die by SIGKILL.
func TestCapsuleCrashChild(t *testing.T) {
	point := os.Getenv(childPoint)
	if point == "" {
		t.Skip("crash child only")
	}
	base, err := fsx.OpenBase(os.Getenv(childRoot))
	if err != nil {
		t.Fatal(err)
	}
	out, err := fsx.OpenBase(os.Getenv(childOut))
	if err != nil {
		t.Fatal(err)
	}
	var rs []age.Recipient
	for _, s := range strings.Split(os.Getenv(childRcpt), ",") {
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			t.Fatal(err)
		}
		rs = append(rs, r)
	}
	var inputs []capsule.Input
	for _, rel := range []string{"s.jsonl", "t.jsonl"} {
		snap, err := base.Lstat(rel)
		if errors.Is(err, os.ErrNotExist) && rel != "s.jsonl" {
			continue // the second input is optional (SEAL-2 uses it)
		}
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, capsule.Input{Base: capsule.BaseClaudeConfig, Dir: base, Rel: rel, Snap: snap})
	}
	failpoint.Set(point)
	_, err = capsule.Seal(context.Background(), capsule.SealRequest{
		Manifest: manifest("crash"), Inputs: inputs,
		Recipients: rs, Out: out, Name: "g000001.pcap",
	})
	t.Fatalf("crash point %s not reached: %v", point, err)
}

// TestCrashDuringSeal SIGKILLs a sealer right after each capsule milestone
// and checks what journal recovery will find: before the rename only the
// temporary, after it a complete, decryptable generation; the plaintext is
// always intact.
func TestCrashDuringSeal(t *testing.T) {
	for _, c := range []struct {
		point string
		want  string
		two   bool // seal a second input (SEAL-2: kill between the inputs)
	}{
		{"capsule.streamed:1", ".g000001.pcap.tmp", true},
		{"capsule.tmp_written", ".g000001.pcap.tmp", false},
		{"capsule.verified", ".g000001.pcap.tmp", false},
		{"capsule.renamed", "g000001.pcap", false},
		{"fsx.rename", ".g000001.pcap.tmp", false},
	} {
		t.Run(c.point, func(t *testing.T) {
			u := newUnit(t)
			k := newKeys(t)
			content := randomBytes(t, 70000)
			u.write("s.jsonl", content)
			if c.two {
				u.write("t.jsonl", randomBytes(t, 70000))
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCapsuleCrashChild$", "-test.count=1")
			cmd.Env = []string{
				childPoint + "=" + c.point, childRoot + "=" + u.root, childOut + "=" + u.outP,
				childRcpt + "=" + k.vault.Recipient().String() + "," + k.recovery.Recipient().String(),
			}
			err := cmd.Run()
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("child: %v", err)
			}
			if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Fatalf("child ended with %v, want SIGKILL", ee)
			}
			u.assertPlaintext()
			names := u.outNames()
			if !reflect.DeepEqual(names, []string{c.want}) {
				t.Fatalf("capsule directory %v, want [%s]", names, c.want)
			}
			if c.want != "g000001.pcap" {
				return
			}
			st := newStaging(t, u.root)
			f, _, err := u.out.Open(c.want)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			_, staged, err := capsule.Extract(context.Background(), f, capsule.ExtractOptions{
				FileKey: fileKey(t, u.out, c.want, k.vault), Staging: st, Limits: capsule.Limits{MaxTotal: 1 << 20}, Check: allowAll,
			})
			if err != nil || len(staged) != 1 {
				t.Fatalf("committed capsule unreadable: %v", err)
			}
			if b, _ := os.ReadFile(filepath.Join(st.Path, staged[0].StagedRel)); !bytes.Equal(b, content) {
				t.Fatal("committed capsule content differs")
			}
		})
	}
}
