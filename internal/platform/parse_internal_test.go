package platform

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestScreenForFixtures(t *testing.T) {
	for _, tc := range []struct {
		file                     string
		uid                      int
		locked, known, onConsole bool
	}{
		{"ioreg-root-unlocked.txt", 501, false, true, true},
		{"ioreg-root-locked.txt", 501, true, true, true},         // CGSSessionScreenIsLocked
		{"ioreg-root-console-locked.txt", 501, true, true, true}, // IOConsoleLocked
		{"ioreg-root-switched.txt", 501, true, true, false},      // fast user switching: not at the console
		{"ioreg-root-switched.txt", 502, false, true, true},
		{"ioreg-root-unlocked.txt", 777, false, false, false},  // no session for this uid: unknown
		{"ioreg-root-headless.txt", 501, false, false, false},  // no console at all
		{"ioreg-root-malformed.txt", 501, false, false, false}, // unparseable sessions: unknown, never "unlocked"
	} {
		locked, known, on := parseIoregRoot(readFixture(t, tc.file)).screenFor(tc.uid)
		if locked != tc.locked || known != tc.known || on != tc.onConsole {
			t.Errorf("%s uid %d: locked=%v known=%v onConsole=%v, want %v %v %v",
				tc.file, tc.uid, locked, known, on, tc.locked, tc.known, tc.onConsole)
		}
	}
}

func TestParseIoregRootValues(t *testing.T) {
	c := parseIoregRoot(readFixture(t, "ioreg-root-unlocked.txt"))
	if !c.HasConsoleLocked || c.ConsoleLocked || len(c.Sessions) != 1 {
		t.Fatalf("parse = %+v", c)
	}
	s := c.Sessions[0]
	if !s.HasUID || s.UID != 501 || !s.OnConsole || s.Locked {
		t.Fatalf("session = %+v (a quoted comma or brace must not break the parser)", s)
	}
}

func TestParseHIDIdle(t *testing.T) {
	d, ok := parseHIDIdle(readFixture(t, "ioreg-hid.txt"))
	if !ok || d != 4250*time.Millisecond {
		t.Fatalf("HIDIdle = %v, %v", d, ok)
	}
	if _, ok := parseHIDIdle([]byte(`"HIDIdleTime" = -5`)); ok {
		t.Fatal("negative idle accepted")
	}
	if _, ok := parseHIDIdle(readFixture(t, "ioreg-root-headless.txt")); ok {
		t.Fatal("idle found where there is none")
	}
	// A value inside another property's string is not a property line.
	if _, ok := parseHIDIdle([]byte(`      "Note" = "x "HIDIdleTime" = 5"`)); ok {
		t.Fatal("embedded key accepted")
	}
}

func TestScreenFromLoginctl(t *testing.T) {
	since := time.UnixMicro(1795251600000000)
	now := since.Add(42 * time.Second)
	s := screenFromLoginctl(parseProps(readFixture(t, "loginctl-locked.txt")), now)
	if !s.Locked || !s.LockKnown || !s.IdleKnown || s.HIDIdle != 42*time.Second || !s.At.Equal(now) {
		t.Fatalf("locked fixture: %+v", s)
	}
	s = screenFromLoginctl(parseProps(readFixture(t, "loginctl-active.txt")), now)
	if s.Locked || !s.LockKnown || s.IdleKnown {
		t.Fatalf("active fixture: %+v (a non-idle session cannot prove the D37 bound: idle unknown)", s)
	}
	s = screenFromLoginctl(parseProps(readFixture(t, "loginctl-nohints.txt")), now)
	if s.LockKnown || s.IdleKnown {
		t.Fatalf("no hints: %+v", s)
	}
}

func TestPlistParserBounds(t *testing.T) {
	deep := make([]byte, 0, 200)
	for i := 0; i < 100; i++ {
		deep = append(deep, '(')
	}
	p := &plistParser{b: deep}
	if _, ok := p.value(); ok {
		t.Fatal("unbounded nesting accepted")
	}
	for _, in := range []string{`{"a"=}`, `{"a"`, `("x`, `{1=2}`, `<abc`, ``} {
		p := &plistParser{b: []byte(in)}
		if _, ok := p.value(); ok {
			t.Errorf("%q accepted", in)
		}
	}
	p = &plistParser{b: []byte(`{"k"="a\"b","n"=-3,"d"=<0a0b>,"t"=Yes,"l"=(1,2)}`)}
	v, ok := p.value()
	m, _ := v.(map[string]any)
	if !ok || m["k"] != `a"b` || m["n"] != int64(-3) || m["d"] != "<0a0b>" || m["t"] != true {
		t.Fatalf("parse = %#v %v", v, ok)
	}
}

func TestParseProcIDStrict(t *testing.T) {
	good, err := parseProcID("123:1795251600000000")
	if err != nil || good.PID != 123 || good.StartUS != 1795251600000000 || good.BootID != sysBootID() {
		t.Fatalf("parse = %+v, %v", good, err)
	}
	for _, s := range []string{"", "123", ":5", "5:", "-1:5", "+1:5", "1:-5", "0:5", "5:0", "01:5", "1:05",
		" 1:5", "1:5 ", "1:5:6", "1.5:6", "99999999999:5", "1:99999999999999999999", "a:b"} {
		if _, err := parseProcID(s); err == nil {
			t.Errorf("parseProcID(%q) accepted", s)
		}
	}
}

func TestCheckLoaderEnvTable(t *testing.T) {
	for _, tc := range []struct {
		env []string
		bad bool
	}{
		{nil, false},
		{[]string{"HOME=/x", "LDFLAGS=-O2", "LDAP=1", "PATH=/bin"}, false},
		{[]string{"DYLD_INSERT_LIBRARIES=/x.dylib"}, true},
		{[]string{"LD_PRELOAD=/x.so"}, true},
		{[]string{"LD_LIBRARY_PATH="}, true},
		{[]string{"X=DYLD_INSERT_LIBRARIES=1"}, false}, // only keys count
		{[]string{"DYLD_"}, true},
	} {
		err := checkLoaderEnv(tc.env)
		if (err != nil) != tc.bad {
			t.Errorf("checkLoaderEnv(%q) = %v, want bad=%v", tc.env, err, tc.bad)
		}
	}
}

func TestCloudSyncedIn(t *testing.T) {
	home := t.TempDir()
	mk := func(rel string) string {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	work := mk("work/acme")
	cs := mk("Library/CloudStorage/Dropbox/notes")
	drop := mk("OneDrive - Org/docs")
	if cloudSyncedIn(home, work) {
		t.Error("a plain folder reported as synced")
	}
	if !cloudSyncedIn(home, drop) {
		t.Error("~/OneDrive - Org not detected")
	}
	if !cloudSyncedIn(home, filepath.Join(home, "Dropbox", "x")) {
		t.Error("~/Dropbox not detected (even before it exists)")
	}
	if cloudSyncedIn(home, "relative/path") {
		t.Error("relative path reported as synced")
	}
	if got := cloudSyncedIn(home, cs); got != (len(cloudRoots(home)) > len(homeCloudRoots(home))) {
		t.Errorf("CloudStorage detection = %v on this OS", got)
	}
	// A symlink into a synced folder is synced.
	link := filepath.Join(home, "work", "link")
	if err := os.Symlink(drop, link); err != nil {
		t.Fatal(err)
	}
	if !cloudSyncedIn(home, link) {
		t.Error("symlink into a synced folder not detected")
	}
}

func TestToolOutputParsers(t *testing.T) {
	if on, known := parseFdesetup("FileVault is On.\n"); !on || !known {
		t.Error("FileVault on")
	}
	if on, known := parseFdesetup("FileVault is Off.\n"); on || !known {
		t.Error("FileVault off")
	}
	if _, known := parseFdesetup("Error: unexpected\n"); known {
		t.Error("garbage known")
	}
	if n, ok := parseCount(" 12\n"); !ok || n != 12 {
		t.Error("count")
	}
	if _, ok := parseCount("x"); ok {
		t.Error("garbage count")
	}
}
