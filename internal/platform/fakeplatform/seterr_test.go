package fakeplatform_test

import (
	"context"
	"errors"
	"testing"

	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
)

func TestSetErrInjectsAndClears(t *testing.T) {
	p := fakeplatform.NewProcs()
	id := platform.ProcID{PID: 42, StartUS: 1000}
	p.Add(platform.ProcInfo{ID: id, Exe: "/bin/x"})
	p.SetCwd(42, "/w")
	p.SetOpenFiles(42, "/w/f")
	boom := errors.New("boom")

	for _, op := range []string{fakeplatform.OpLookup, fakeplatform.OpList, fakeplatform.OpCwd, fakeplatform.OpOpenFilesUnder} {
		p.SetErr(op, boom)
	}
	if _, err := p.Lookup(42); !errors.Is(err, boom) {
		t.Errorf("Lookup err = %v, want boom", err)
	}
	if _, err := p.List(); !errors.Is(err, boom) {
		t.Errorf("List err = %v, want boom", err)
	}
	if _, err := p.Cwd(id); !errors.Is(err, boom) {
		t.Errorf("Cwd err = %v, want boom", err)
	}
	if _, err := p.OpenFilesUnder(context.Background(), []string{"/w"}); !errors.Is(err, boom) {
		t.Errorf("OpenFilesUnder err = %v, want boom", err)
	}
	if !p.Alive(id) {
		t.Error("Alive must not be affected by SetErr")
	}

	for _, op := range []string{fakeplatform.OpLookup, fakeplatform.OpList, fakeplatform.OpCwd, fakeplatform.OpOpenFilesUnder} {
		p.SetErr(op, nil)
	}
	if _, err := p.Lookup(42); err != nil {
		t.Errorf("Lookup after clear: %v", err)
	}
	if l, err := p.List(); err != nil || len(l) != 1 {
		t.Errorf("List after clear = %v, %v", l, err)
	}
	if c, err := p.Cwd(id); err != nil || c != "/w" {
		t.Errorf("Cwd after clear = %q, %v", c, err)
	}
	if h, err := p.OpenFilesUnder(context.Background(), []string{"/w"}); err != nil || len(h) != 1 {
		t.Errorf("OpenFilesUnder after clear = %v, %v", h, err)
	}
}

func TestSetErrUnknownOpPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("SetErr with an unknown op must panic")
		}
	}()
	fakeplatform.NewProcs().SetErr("Lookups", errors.New("x"))
}

func TestSetErrZeroValueProcs(t *testing.T) {
	var p fakeplatform.Procs
	p.SetErr(fakeplatform.OpList, errors.New("x"))
	if _, err := p.List(); err == nil {
		t.Fatal("want injected error on a zero-value Procs")
	}
}
