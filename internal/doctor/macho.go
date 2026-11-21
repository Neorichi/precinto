package doctor

import (
	"debug/macho"
	"encoding/binary"
	"errors"
	"io"
)

// Code-signature constants (xnu osfmk/kern/cs_blobs.h).
const (
	lcCodeSignature   = 0x1d       // LC_CODE_SIGNATURE
	csMagicEmbedded   = 0xfade0cc0 // CSMAGIC_EMBEDDED_SIGNATURE (SuperBlob)
	csMagicCodeDir    = 0xfade0c02 // CSMAGIC_CODEDIRECTORY
	csSlotCodeDir     = 0          // CSSLOT_CODEDIRECTORY
	csSlotAltCodeDir  = 0x1000     // CSSLOT_ALTERNATE_CODEDIRECTORIES (first)
	csSlotAltCodeDirs = 5          // alternate code directory slots
	csRuntime         = 0x00010000 // CS_RUNTIME: the hardened runtime
	maxSignature      = 16 << 20   // refuse absurd signature sizes
)

var errBadSignature = errors.New("doctor: malformed code signature")

// hardenedRuntime reads the code signature of the Mach-O executable at path
// (thin or universal) and reports whether every architecture is signed
// with the hardened runtime (CS_RUNTIME in its CodeDirectory flags). known
// is false for a file that is not Mach-O (linux, a script). It only reads
// the file, with every offset bounds-checked.
func hardenedRuntime(path string) (hardened, signed, known bool, err error) {
	f, fi, err := openRegular(path)
	if err != nil {
		return false, false, false, err
	}
	defer f.Close()
	size := fi.Size()
	if fat, ferr := macho.NewFatFile(f); ferr == nil {
		defer fat.Close()
		if len(fat.Arches) == 0 {
			return false, false, false, nil
		}
		hardened, signed = true, true
		for _, a := range fat.Arches {
			h, s, err := sliceHardened(f, a.File, int64(a.Offset), int64(a.Size))
			if err != nil {
				return false, false, true, err
			}
			hardened, signed = hardened && h, signed && s
		}
		return hardened, signed, true, nil
	}
	m, merr := macho.NewFile(f)
	if merr != nil {
		return false, false, false, nil // not Mach-O
	}
	defer m.Close()
	h, s, err := sliceHardened(f, m, 0, size)
	return h, s, true, err
}

// sliceHardened checks one architecture whose bytes start at off (the
// offsets of its load commands are relative to it).
func sliceHardened(r io.ReaderAt, m *macho.File, off, size int64) (hardened, signed bool, err error) {
	for _, l := range m.Loads {
		raw := l.Raw()
		if len(raw) < 16 || m.ByteOrder.Uint32(raw[0:4]) != lcCodeSignature {
			continue
		}
		dataOff := int64(m.ByteOrder.Uint32(raw[8:12]))
		dataSize := int64(m.ByteOrder.Uint32(raw[12:16]))
		if dataSize <= 0 || dataSize > maxSignature || dataOff < 0 || dataOff+dataSize > size {
			return false, false, errBadSignature
		}
		blob := make([]byte, dataSize)
		if _, err := r.ReadAt(blob, off+dataOff); err != nil {
			return false, false, errBadSignature
		}
		flags, err := codeDirectoryFlags(blob)
		if err != nil {
			return false, false, err
		}
		return flags&csRuntime != 0, true, nil
	}
	return false, false, nil // unsigned
}

// codeDirectoryFlags returns the flags of the primary code directory of an
// embedded-signature SuperBlob (big-endian), with CS_RUNTIME set only when
// every code directory (primary and alternates) carries it.
func codeDirectoryFlags(b []byte) (uint32, error) {
	be := binary.BigEndian
	if len(b) < 12 || be.Uint32(b[0:4]) != csMagicEmbedded {
		return 0, errBadSignature
	}
	length := int(be.Uint32(b[4:8]))
	count := int(be.Uint32(b[8:12]))
	if length > len(b) || length < 12 || count < 0 || count > (length-12)/8 {
		return 0, errBadSignature
	}
	var flags uint32
	runtime := true
	found := false
	for i := 0; i < count; i++ {
		ent := b[12+8*i:]
		typ, at := be.Uint32(ent[0:4]), int(be.Uint32(ent[4:8]))
		isDir := typ == csSlotCodeDir || (typ >= csSlotAltCodeDir && typ < csSlotAltCodeDir+csSlotAltCodeDirs)
		if !isDir {
			continue
		}
		if at < 0 || at+16 > length {
			return 0, errBadSignature
		}
		cd := b[at:length]
		if be.Uint32(cd[0:4]) != csMagicCodeDir {
			return 0, errBadSignature
		}
		f := be.Uint32(cd[12:16])
		if typ == csSlotCodeDir {
			flags = f
		}
		runtime = runtime && f&csRuntime != 0
		found = true
	}
	if !found {
		return 0, errBadSignature
	}
	if runtime {
		return flags | csRuntime, nil
	}
	return flags &^ csRuntime, nil
}
