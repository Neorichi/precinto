package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseInterspersed(t *testing.T) {
	f := newFlags("protect")
	md := f.String("md", "", "")
	cs := f.Bool("claude-settings", false, "")
	pos, err := f.parse([]string{"DIR", "--md", "all", "--claude-settings"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pos, []string{"DIR"}) || *md != "all" || !*cs {
		t.Fatalf("pos %v md %q cs %v", pos, *md, *cs)
	}
}

func TestParseTerminator(t *testing.T) {
	f := newFlags("cat")
	raw := f.Bool("raw", false, "")
	pos, err := f.parse([]string{"--raw", "--", "--to", "-x.md.precinto"})
	if err != nil {
		t.Fatal(err)
	}
	if !*raw || !reflect.DeepEqual(pos, []string{"--to", "-x.md.precinto"}) {
		t.Fatalf("raw %v pos %v", *raw, pos)
	}
}

// `--root --` names a folder called "--": it is the flag's value, not the
// terminator.
func TestParseDoubleDashAsValue(t *testing.T) {
	f := newFlags("lock")
	root := f.String("root", "", "")
	end := f.Bool("end", false, "")
	pos, err := f.parse([]string{"--root", "--", "--end"})
	if err != nil {
		t.Fatal(err)
	}
	if *root != "--" || !*end || len(pos) != 0 {
		t.Fatalf("root %q end %v pos %v", *root, *end, pos)
	}
}

func TestParseHeadKeepsCommandFlags(t *testing.T) {
	f := newFlags("run")
	h := f.String("harness", "", "")
	rest, err := f.parseHead([]string{"--harness", "claude-code", "--", "claude", "--resume", "x", "--harness", "y"})
	if err != nil {
		t.Fatal(err)
	}
	if *h != "claude-code" || !reflect.DeepEqual(rest, []string{"claude", "--resume", "x", "--harness", "y"}) {
		t.Fatalf("h %q rest %v", *h, rest)
	}
	f = newFlags("run")
	rest, err = f.parseHead([]string{"claude", "-p", "hi"})
	if err != nil || !reflect.DeepEqual(rest, []string{"claude", "-p", "hi"}) {
		t.Fatalf("rest %v err %v", rest, err)
	}
}

func TestParseHelp(t *testing.T) {
	f := newFlags("status")
	f.Bool("json", false, "")
	if _, err := f.parse([]string{"--json", "-h"}); !errors.Is(err, errHelp) {
		t.Fatalf("err %v", err)
	}
}

func TestStringList(t *testing.T) {
	f := newFlags("init")
	var l stringList
	f.Var(&l, "factor", "")
	if _, err := f.parse([]string{"--factor", "se", "--factor=passphrase"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual([]string(l), []string{"se", "passphrase"}) {
		t.Fatalf("%v", l)
	}
	if _, err := newFlagsWith(t).parse([]string{"--factor", ""}); err == nil {
		t.Fatal("empty value accepted")
	}
}

func newFlagsWith(t *testing.T) *flags {
	f := newFlags("init")
	var l stringList
	f.Var(&l, "factor", "")
	return f
}

func TestOptInt(t *testing.T) {
	f := newFlags("restore")
	var n optInt
	f.Var(&n, "recent", "")
	if _, err := f.parse([]string{"--recent", "3"}); err != nil || !n.set || n.v != 3 {
		t.Fatalf("n %+v err %v", n, err)
	}
	f = newFlags("restore")
	var m optInt
	f.Var(&m, "recent", "")
	if _, err := f.parse([]string{"--recent", "-1"}); err == nil {
		t.Fatal("negative accepted")
	}
}

func TestExclusive(t *testing.T) {
	if err := exclusive(map[string]bool{"root": true, "all": true}); err == nil || !strings.Contains(err.Error(), "--all, --root") {
		t.Fatalf("err %v", err)
	}
	if err := exclusive(map[string]bool{"root": true, "all": false}); err != nil {
		t.Fatal(err)
	}
}

func TestUsageShowsDoubleDashFlags(t *testing.T) {
	e := newEnv(t)
	e.run("unlock", "--help")
	if !strings.Contains(e.stdout(), "  --root DIR\n") || strings.Contains(e.stdout(), "default 0s") {
		t.Fatalf("usage %q", e.stdout())
	}
}
