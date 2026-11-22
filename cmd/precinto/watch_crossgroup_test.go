//go:build crossgroup

package main

import (
	"context"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/agent/agenttest"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

// D153 over a real daemon: a lock during an operation aborts it (REST-8)
// whether it watches its folders (restore in a folder, unprotect) or every
// folder (open, restore --session or --global outside a folder), although
// the daemon sends initial state events only for the folders a
// subscription names (D71).
func TestCrossgroupWatchLocksAbortsOnALock(t *testing.T) {
	for name, roots := range map[string][]string{"every folder": nil, "its folder": {lifecycleRoot}} {
		t.Run(name, func(t *testing.T) {
			h := realHome(t)
			fx := vaulttest.New(t, h.Layout.Base, lifecycleRoot)
			ag := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
			defer ag.Stop()
			ag.UnlockForTest(t, []string{lifecycleRoot}, fx.Recovery.String())
			a, e := realApp(t, h)
			fired := make(chan struct{})
			abort, stop := a.watchLocks(context.Background(), roots, func() { close(fired) })
			defer stop()
			select {
			case <-abort:
				t.Fatal("the folder's unlocked state aborted the operation")
			case <-time.After(300 * time.Millisecond):
			}
			if code := a.run([]string{"lock"}); code != exitOK {
				t.Fatalf("lock: exit %d (%s)", code, e.stderr())
			}
			select {
			case <-abort:
			case <-time.After(2 * time.Second):
				t.Fatal("the lock did not abort the operation within 2 s (REST-8)")
			}
			<-fired
		})
	}
}
