package testkit_test

import (
	"debug/buildinfo"
	"os"
	"runtime"
	"testing"

	"github.com/Neorichi/precinto/internal/testkit"
)

// TestBuildBinary builds the real cmd/precinto (the whole module must
// compile) and checks the build settings recorded in the binary, without
// running it.
func TestBuildBinary(t *testing.T) {
	bin := testkit.BuildBinary(t, "testing")
	if again := testkit.BuildBinary(t); again != bin {
		t.Errorf("BuildBinary() = %s, want the cached %s (testing is always on)", again, bin)
	}
	crash := testkit.BuildBinary(t, "testing", "failpoints")
	if crash == bin {
		t.Fatal("the failpoints build replaced the testing build")
	}
	for path, tags := range map[string]string{bin: "testing", crash: "testing,failpoints"} {
		fi, err := os.Stat(path)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o100 == 0 {
			t.Fatalf("%s: %v %v", path, fi, err)
		}
		info, err := buildinfo.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Path != "github.com/Neorichi/precinto/cmd/precinto" {
			t.Errorf("%s builds %s", path, info.Path)
		}
		settings := map[string]string{}
		for _, s := range info.Settings {
			settings[s.Key] = s.Value
		}
		if settings["-tags"] != tags || settings["GOOS"] != runtime.GOOS || settings["GOARCH"] != runtime.GOARCH {
			t.Errorf("%s settings: -tags=%q GOOS=%q GOARCH=%q, want %q", path, settings["-tags"], settings["GOOS"], settings["GOARCH"], tags)
		}
	}
}
