//go:build linux

package ipc_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

func init() {
	// listen-hardened <socket> <result> [lockfile]: a non-dumpable squatter
	// (optionally holding a flock on some other file) that counts the bytes
	// a client sends.
	helperModes["listen-hardened"] = func(args []string) {
		if err := platform.Harden(); err != nil {
			os.Exit(4)
		}
		if len(args) > 2 {
			held, err := fsx.TryLock(args[2], false)
			if err != nil {
				os.Exit(5)
			}
			defer runtime.KeepAlive(held) // the flock lives as long as its descriptor
		}
		ln, err := net.Listen("unix", args[0])
		if err != nil {
			os.Exit(2)
		}
		fmt.Println("ready")
		c, err := ln.Accept()
		if err != nil {
			os.Exit(3)
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := io.Copy(io.Discard, c)
		_ = os.WriteFile(args[1], []byte(strconv.FormatInt(n, 10)), 0o600)
	}
	// serve-hardened <base> <run>: a non-dumpable daemon of this binary that
	// holds run/agent.lock (ipc.Listen) and answers hello.
	helperModes["serve-hardened"] = func(args []string) {
		if err := platform.Harden(); err != nil {
			os.Exit(4)
		}
		l, err := paths.LayoutAt(args[0], args[1])
		if err != nil {
			os.Exit(2)
		}
		ln, err := ipc.Listen(l)
		if err != nil {
			os.Exit(3)
		}
		fmt.Println("ready")
		for {
			c, err := ln.Accept()
			if err != nil {
				os.Exit(6)
			}
			go func() {
				defer c.Close()
				for {
					req, sec, err := c.ReadRequest()
					for _, b := range sec {
						b.Destroy()
					}
					if err != nil {
						return
					}
					resp := ipc.Response{ID: req.ID, OK: true}
					if req.Op == ipc.OpHello {
						resp.Hello = &ipc.HelloResp{Version: "helper", PID: os.Getpid(), Protocol: ipc.Version}
					}
					if c.WriteResponse(resp) != nil {
						return
					}
				}
			}()
		}
	}
}

// requireHidden skips unless the helper is non-dumpable for this test
// process (its executable cannot be read): only then does the D65 path run.
func requireHidden(t *testing.T, h *helper) {
	t.Helper()
	if _, err := platform.SameExecutable(h.cmd.Process.Pid); !errors.Is(err, fs.ErrPermission) {
		t.Skipf("a hardened helper's executable is readable here (%v): the D65 fallback is not reached", err)
	}
}

// TestSocketSquatLinuxHardened is SEC-11's linux variant (D65): against a
// non-dumpable server the client cannot compare executables, so it
// requires the peer to hold run/agent.lock and to have its own kernel name.
// A squatter with another comm, one with the same comm that does not hold
// the lock, and one holding a lock on another file are refused before a
// single byte is sent; a hardened daemon of this binary that holds the
// lock is accepted.
func TestSocketSquatLinuxHardened(t *testing.T) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Skip("root reads every /proc/<pid>/exe (and platform.Harden refuses root)")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	type squat struct {
		name      string
		exe       string
		otherLock bool
	}
	for _, tc := range []squat{
		{"another comm", helperCopy(t), false},
		{"same comm without run/agent.lock", self, false},
		{"same comm holding another file's lock", self, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := layout(t)
			if err := os.Mkdir(l.RunDir, 0o700); err != nil {
				t.Fatal(err)
			}
			result := filepath.Join(t.TempDir(), "received")
			args := []string{"listen-hardened", l.Socket, result}
			if tc.otherLock {
				args = append(args, filepath.Join(t.TempDir(), "other.lock"))
			}
			h := runHelper(t, tc.exe, args...)
			h.waitReady(t)
			requireHidden(t, h)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l, Client: "cli"}); !errors.Is(err, ipc.ErrUntrustedServer) {
				t.Fatalf("Dial(%s) = %v, want ErrUntrustedServer", tc.name, err)
			}
			if err := h.wait(t); err != nil {
				t.Fatalf("helper: %v", err)
			}
			if b, err := os.ReadFile(result); err != nil || string(b) != "0" {
				t.Fatalf("squatter received %q bytes (%v): the client must send nothing", b, err)
			}
		})
	}
	t.Run("hardened daemon holding the lock", func(t *testing.T) {
		l := layout(t)
		h := runHelper(t, self, "serve-hardened", l.Base, l.RunDir)
		h.waitReady(t)
		requireHidden(t, h)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l, Client: "cli"})
		if err != nil {
			t.Fatalf("Dial(hardened daemon of this binary) = %v (D65 accepts the lock holder)", err)
		}
		c.Close()
	})
}
