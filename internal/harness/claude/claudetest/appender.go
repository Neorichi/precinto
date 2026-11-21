package claudetest

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startAppender writes the first record synchronously (so the file exists
// when StartAppender returns and a bad path fails the test at once), then
// appends one record per interval until Stop. Like Claude's writer it keeps
// the uuid chain in memory: it continues from the last record found in an
// existing file, and when the file disappears it recreates it with a record
// whose parentUuid points into the vanished part (E8).
func startAppender(t testing.TB, path string, every time.Duration) *Appender {
	t.Helper()
	if path == "" || !filepath.IsAbs(path) {
		t.Fatalf("claudetest: StartAppender needs an absolute path, got %q", path)
	}
	if every <= 0 {
		every = defaultEvery
	}
	a := &Appender{
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		t:     t,
		path:  filepath.Clean(path),
		every: every,
		nonce: strconv.FormatInt(time.Now().UnixNano(), 10),
	}
	a.head = tailFacts(a.path)
	if a.head.SessionID == "" {
		a.head.SessionID = strings.TrimSuffix(filepath.Base(a.path), ".jsonl")
	}
	if err := a.appendOne(); err != nil {
		t.Fatalf("claudetest: appender: first record for %s: %v", a.path, err)
	}
	go a.run()
	t.Cleanup(func() { a.Stop() })
	return a
}

func (a *Appender) run() {
	defer close(a.done)
	tick := time.NewTicker(a.every)
	defer tick.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-tick.C:
			if err := a.appendOne(); err != nil {
				// A writer racing a sealer may find its directory gone; that is
				// part of the scenario, not a test failure. Stop reports it.
				a.failures++
				if a.firstErr == nil {
					a.firstErr = err
				}
			}
		}
	}
}

// appendOne opens the file (creating it if missing), appends one complete
// record with a single write, and closes it.
func (a *Appender) appendOne() error {
	uuid := fixtureUUID("appender", a.path, a.nonce, strconv.Itoa(a.seq))
	var parent *string
	if a.head.UUID != "" {
		p := a.head.UUID
		parent = &p
	}
	rec := convRecord{
		ParentUUID:  parent,
		IsSidechain: a.head.IsSidechain,
		UserType:    "external",
		Cwd:         a.head.Cwd,
		SessionID:   a.head.SessionID,
		Version:     claudeVersion,
		GitBranch:   gitBranch,
		AgentID:     a.head.AgentID,
		Slug:        a.head.Slug,
		UUID:        uuid,
		Timestamp:   isoMillis(time.Now()),
	}
	text := "claudetest appender record " + strconv.Itoa(a.seq)
	if a.seq%2 == 0 {
		rec.Type = "user"
		rec.Message = userTextMessage{Role: "user", Content: text}
	} else {
		rec.Type = "assistant"
		rec.Message = assistant("msg_"+fixtureHex(24, "appender-message", a.path, a.nonce, strconv.Itoa(a.seq)), "end_turn",
			textBlock{Type: "text", Text: text})
	}
	line, err := marshalLine(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, filePerm)
	if err != nil {
		return err
	}
	_, werr := f.Write(line)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	a.head.UUID = uuid
	a.seq++
	a.count++
	return nil
}

func (a *Appender) stopAppender() int {
	if a == nil || a.stop == nil {
		return 0
	}
	a.stopOnce.Do(func() { close(a.stop) })
	<-a.done
	a.reportOnce.Do(func() {
		if a.failures > 0 {
			a.t.Logf("claudetest: appender on %s: %d append(s) failed, first: %v", a.path, a.failures, a.firstErr)
		}
	})
	return a.count
}
