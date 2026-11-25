package doctor_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Neorichi/precinto/internal/doctor"
)

// Code-signature fixtures: minimal Mach-O files with an LC_CODE_SIGNATURE
// whose SuperBlob holds one CodeDirectory with the given flags.

const (
	csAdhoc         = 0x00000002
	csLinkerSigned  = 0x00020000
	csRuntime       = 0x00010000
	cpuARM64        = 0x0100000c
	cpuAMD64        = 0x01000007
	sigOffset       = 64
	codeDirFlagsOff = 12
)

// superBlob returns an embedded-signature SuperBlob with one code
// directory carrying flags.
func superBlob(flags uint32) []byte {
	be := binary.BigEndian
	cd := make([]byte, 44)
	be.PutUint32(cd[0:], 0xfade0c02)
	be.PutUint32(cd[4:], uint32(len(cd)))
	be.PutUint32(cd[8:], 0x20400)
	be.PutUint32(cd[codeDirFlagsOff:], flags)
	head := make([]byte, 20)
	be.PutUint32(head[0:], 0xfade0cc0)
	be.PutUint32(head[4:], uint32(len(head)+len(cd)))
	be.PutUint32(head[8:], 1)
	be.PutUint32(head[12:], 0)  // CSSLOT_CODEDIRECTORY
	be.PutUint32(head[16:], 20) // offset of the code directory
	return append(head, cd...)
}

// thinMachO returns a 64-bit Mach-O executable for cpu; with sig nil it is
// unsigned.
func thinMachO(cpu uint32, sig []byte) []byte {
	le := binary.LittleEndian
	hdr := make([]byte, 32)
	le.PutUint32(hdr[0:], 0xfeedfacf)
	le.PutUint32(hdr[4:], cpu)
	le.PutUint32(hdr[12:], 2) // MH_EXECUTE
	var b bytes.Buffer
	if sig == nil {
		b.Write(hdr)
		b.Write(make([]byte, 32))
		return b.Bytes()
	}
	le.PutUint32(hdr[16:], 1)  // ncmds
	le.PutUint32(hdr[20:], 16) // sizeofcmds
	b.Write(hdr)
	cmd := make([]byte, 16)
	le.PutUint32(cmd[0:], 0x1d) // LC_CODE_SIGNATURE
	le.PutUint32(cmd[4:], 16)
	le.PutUint32(cmd[8:], sigOffset)
	le.PutUint32(cmd[12:], uint32(len(sig)))
	b.Write(cmd)
	b.Write(make([]byte, sigOffset-b.Len()))
	b.Write(sig)
	return b.Bytes()
}

// fatMachO wraps slices in a universal binary.
func fatMachO(cpus []uint32, slices [][]byte) []byte {
	be := binary.BigEndian
	head := make([]byte, 8+20*len(slices))
	be.PutUint32(head[0:], 0xcafebabe)
	be.PutUint32(head[4:], uint32(len(slices)))
	off := 4096
	var body bytes.Buffer
	for i, s := range slices {
		e := head[8+20*i:]
		be.PutUint32(e[0:], cpus[i])
		be.PutUint32(e[8:], uint32(off))
		be.PutUint32(e[12:], uint32(len(s)))
		be.PutUint32(e[16:], 12) // 4 KiB alignment
		for body.Len()+len(head) < off {
			body.WriteByte(0)
		}
		body.Write(s)
		off = len(head) + body.Len()
		off = (off + 4095) &^ 4095
	}
	return append(head, body.Bytes()...)
}

func writeBinary(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHardenedRuntimeParser(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name                    string
		data                    []byte
		hardened, signed, known bool
		wantErr                 bool
	}{
		{"hardened", thinMachO(cpuARM64, superBlob(csRuntime)), true, true, true, false},
		{"ad-hoc linker signature (go build)", thinMachO(cpuARM64, superBlob(csAdhoc|csLinkerSigned)), false, true, true, false},
		{"unsigned", thinMachO(cpuAMD64, nil), false, false, true, false},
		{"universal, both hardened", fatMachO([]uint32{cpuARM64, cpuAMD64}, [][]byte{
			thinMachO(cpuARM64, superBlob(csRuntime)), thinMachO(cpuAMD64, superBlob(csRuntime))}), true, true, true, false},
		{"universal, one slice unhardened", fatMachO([]uint32{cpuARM64, cpuAMD64}, [][]byte{
			thinMachO(cpuARM64, superBlob(csRuntime)), thinMachO(cpuAMD64, superBlob(csAdhoc))}), false, true, true, false},
		{"not Mach-O", []byte("#!/bin/sh\necho hi\n"), false, false, false, false},
		{"signature beyond the file", func() []byte {
			b := thinMachO(cpuARM64, superBlob(csRuntime))
			return b[:sigOffset+8]
		}(), false, false, true, true},
		{"bad blob magic", thinMachO(cpuARM64, []byte("not a superblob at all....")), false, false, true, true},
		{"code directory offset out of range", func() []byte {
			sig := superBlob(csRuntime)
			binary.BigEndian.PutUint32(sig[16:], 4000)
			return thinMachO(cpuARM64, sig)
		}(), false, false, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := writeBinary(t, dir, filepath.Base(t.Name()), c.data)
			hardened, signed, known, err := doctor.HardenedRuntime(p)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, want error %v", err, c.wantErr)
			}
			if c.wantErr {
				return
			}
			if hardened != c.hardened || signed != c.signed || known != c.known {
				t.Errorf("hardened, signed, known = %v, %v, %v; want %v, %v, %v", hardened, signed, known, c.hardened, c.signed, c.known)
			}
		})
	}
	if _, _, _, err := doctor.HardenedRuntime(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file has no error")
	}
}

// The test binary itself: what `go build` produces is never hardened.
func TestHardenedRuntimeOfAGoBuild(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	hardened, signed, known, err := doctor.HardenedRuntime(exe)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "darwin" {
		if known {
			t.Errorf("a %s binary read as Mach-O", runtime.GOOS)
		}
		return
	}
	if !known || hardened {
		t.Errorf("test binary: known=%v hardened=%v signed=%v; want a known, unhardened Mach-O", known, hardened, signed)
	}
	if runtime.GOARCH == "arm64" && !signed {
		t.Error("darwin/arm64 Go binaries carry an ad-hoc linker signature")
	}
}
