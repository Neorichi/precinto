//go:build failpoints

package capsule_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/fsx/failpoint"
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

// ENOSPC while the temporary is being written (after the first of two
// inputs was streamed, CC-01): Seal fails as no-space, removes its
// temporary, keeps the plaintext, and a retry is not blocked by a leftover.
func TestENOSPCWhileStreaming(t *testing.T) {
	u := newUnit(t)
	k := newKeys(t)
	u.write("s.jsonl", randomBytes(t, 3<<19))
	u.write("t.jsonl", randomBytes(t, 3<<19))
	arm(t, "capsule.streamed=errno:ENOSPC")
	_, err := seal(t, u, k, "g000001.pcap", u.inputs("s.jsonl", "t.jsonl"), nil, nil)
	if !errors.Is(err, syscall.ENOSPC) || fsx.Classify(err) != fsx.ClassNoSpace {
		t.Fatalf("Seal = %v (class %q), want ENOSPC", err, fsx.Classify(err))
	}
	if n := u.outNames(); len(n) != 0 {
		t.Fatalf("left %v", n)
	}
	u.assertPlaintext()
	failpoint.Reset()
	if _, err := seal(t, u, k, "g000001.pcap", u.inputs("s.jsonl", "t.jsonl"), nil, nil); err != nil {
		t.Fatalf("retry after ENOSPC: %v", err)
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
	// Lifeline: stdin is a pipe whose only write end the parent test holds;
	// EOF means the parent is gone (TESTPLAN §1 rule 8).
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(3)
	}()
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
	for _, rel := range []string{"s.jsonl", "t.jsonl", "u.jsonl"} {
		snap, err := base.Lstat(rel)
		if errors.Is(err, os.ErrNotExist) && rel != "s.jsonl" {
			continue // the later inputs are optional (SEAL-2 uses them)
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

// runSealChild runs TestCapsuleCrashChild with point armed and requires it
// to die by SIGKILL. The child holds a lifeline on stdin and a deadline,
// and is reaped before this returns.
func runSealChild(t *testing.T, u *unit, k keys, point string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCapsuleCrashChild$", "-test.count=1")
	cmd.Env = []string{
		childPoint + "=" + point, childRoot + "=" + u.root, childOut + "=" + u.outP,
		childRcpt + "=" + k.vault.Recipient().String() + "," + k.recovery.Recipient().String(),
	}
	life, lifeline, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer lifeline.Close()
	cmd.Stdin = life
	err = cmd.Start()
	life.Close()
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("child: %v", err)
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("child ended with %v, want SIGKILL", ee)
	}
}

// TestCrashDuringSeal SIGKILLs a sealer right after each capsule milestone
// and checks what journal recovery will find: before the rename only the
// temporary, after it a complete, decryptable generation; the plaintext is
// always intact.
func TestCrashDuringSeal(t *testing.T) {
	for _, c := range []struct {
		point string
		want  string
	}{
		{"capsule.tmp_written", ".g000001.pcap.tmp"},
		{"capsule.verified", ".g000001.pcap.tmp"},
		{"capsule.renamed", "g000001.pcap"},
		{"fsx.rename", ".g000001.pcap.tmp"},
	} {
		t.Run(c.point, func(t *testing.T) {
			u := newUnit(t)
			k := newKeys(t)
			content := randomBytes(t, 70000)
			u.write("s.jsonl", content)
			runSealChild(t, u, k, c.point)
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

// TestCrashMidStream is the capsule part of TESTPLAN SEAL-2: a sealer is
// SIGKILLed right after an input was streamed into the temporary
// (capsule.streamed:<n>) with more inputs to go, while the temporary is
// half written: after the first of two inputs, and after the middle one of
// three. The temporary is the only leftover, it holds part of the payload
// on disk but is not a readable capsule, and every plaintext file is
// intact.
func TestCrashMidStream(t *testing.T) {
	// Incompressible inputs larger than the 1 MiB write buffer, so the
	// kill lands with part of the payload already in the file.
	const each = 3 << 19
	const buffered = 1<<20 + 1<<18 // bufio, zstd block and age chunk at most
	for _, c := range []struct {
		inputs, killAfter int
	}{{2, 1}, {3, 2}} {
		t.Run(fmt.Sprintf("%d of %d", c.killAfter, c.inputs), func(t *testing.T) {
			u := newUnit(t)
			k := newKeys(t)
			for _, rel := range []string{"s.jsonl", "t.jsonl", "u.jsonl"}[:c.inputs] {
				u.write(rel, randomBytes(t, each))
			}
			runSealChild(t, u, k, fmt.Sprintf("capsule.streamed:%d", c.killAfter))
			u.assertPlaintext()
			tmp := capsule.TmpName("g000001.pcap")
			if names := u.outNames(); !reflect.DeepEqual(names, []string{tmp}) {
				t.Fatalf("capsule directory %v, want only the temporary %s", names, tmp)
			}
			fi, err := os.Lstat(filepath.Join(u.outP, tmp))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Size() < int64(c.killAfter*each-buffered) || fi.Size() >= int64(c.inputs*each) {
				t.Fatalf("temporary of %d bytes: the kill did not land in the middle of the write", fi.Size())
			}
			// Half a capsule never opens: the payload stream ends early.
			f, _, err := u.out.Open(tmp)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			st := newStaging(t, u.root)
			_, staged, err := capsule.Extract(context.Background(), f, capsule.ExtractOptions{
				FileKey: fileKey(t, u.out, tmp, k.vault), Staging: st, Limits: capsule.Limits{MaxTotal: 1 << 30}, Check: allowAll,
			})
			if err == nil || staged != nil {
				t.Fatalf("a partial temporary extracted: %v, %d staged", err, len(staged))
			}
		})
	}
}
