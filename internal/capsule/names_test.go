package capsule_test

import (
	"testing"

	"github.com/precinto/precinto/internal/capsule"
)

// Test vectors for D45 (also listed in docs/TESTPLAN.md §8); computed
// independently with Python's hmac module.
func TestUnitKeyVectors(t *testing.T) {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	for _, c := range []struct {
		parts []string
		want  string
	}{
		{[]string{"claude-code", "session", "0123456789abcdef", "11111111-2222-3333-4444-555555555555"}, "7c86bcb2589f2f6c00c44229522bb4e1"},
		{[]string{"md", "root-acme", "docs/notes.md"}, "b6e3dd30b5ea0f974ea7ecbfef058df8"},
		{[]string{"codex", "home", "root-acme"}, "0db03e41aa3423814ce99acb29c124a8"},
	} {
		if got := capsule.UnitKey(salt, c.parts...); got != c.want {
			t.Errorf("UnitKey(%q) = %s, want %s", c.parts, got, c.want)
		}
	}
}

func TestGenNames(t *testing.T) {
	if got := capsule.GenName(7); got != "g000007.pcap" {
		t.Fatalf("GenName(7) = %q", got)
	}
	if got := capsule.GenName(1234567); got != "g1234567.pcap" {
		t.Fatalf("GenName(1234567) = %q", got)
	}
	for name, want := range map[string]uint64{"g000007.pcap": 7, "g1234567.pcap": 1234567} {
		if n, ok := capsule.ParseGenName(name); !ok || n != want {
			t.Errorf("ParseGenName(%q) = %d, %v", name, n, ok)
		}
	}
	for _, bad := range []string{"g7.pcap", "g0000007.pcap", "g000000.pcap", "g00000a.pcap", "g000007.pcap.tmp", "x000007.pcap", "g-00007.pcap"} {
		if _, ok := capsule.ParseGenName(bad); ok {
			t.Errorf("ParseGenName(%q) accepted", bad)
		}
	}
}
