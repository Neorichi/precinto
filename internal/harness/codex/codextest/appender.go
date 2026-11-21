package codextest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// defaultEvery is the Appender interval when every <= 0 (TESTPLAN §4:
// writer simulators append every 10–50 ms).
const defaultEvery = 20 * time.Millisecond

// startAppender opens path the way Codex's rollout writer does
// (O_WRONLY|O_APPEND|O_CREATE, mode 0644, kept open until shutdown),
// writes the first record synchronously (so the file exists when
// StartAppender returns and a bad path fails the test at once), then one
// record per interval until Stop. A sealer that unlinks the rollout leaves
// the writer appending to the unlinked inode, as Codex does.
func startAppender(t testing.TB, path string, every time.Duration) *Appender {
	t.Helper()
	if path == "" || !filepath.IsAbs(path) {
		t.Fatalf("codextest: StartAppender needs an absolute path, got %q", path)
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
	}
	f, err := os.OpenFile(a.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, filePerm)
	if err != nil {
		t.Fatalf("codextest: appender: open %s: %v", a.path, err)
	}
	if err := a.appendOne(f); err != nil {
		f.Close()
		t.Fatalf("codextest: appender: first record for %s: %v", a.path, err)
	}
	go a.run(f)
	t.Cleanup(func() { a.Stop() })
	return a
}

func (a *Appender) run(f *os.File) {
	defer close(a.done)
	defer f.Close()
	tick := time.NewTicker(a.every)
	defer tick.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-tick.C:
			if err := a.appendOne(f); err != nil {
				a.failures++
				if a.firstErr == nil {
					a.firstErr = err
				}
			}
		}
	}
}

// appendOne writes one complete rollout record with a single write(2).
func (a *Appender) appendOne(f *os.File) error {
	n := a.count
	var line []byte
	var err error
	at := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	text := "codextest appender record " + strconv.Itoa(n)
	if n%2 == 0 {
		line, err = marshalRecord(rolloutLine{Timestamp: at, Ordinal: n, Type: "event_msg",
			Payload: eventMessage{Type: "agent_message", Message: text}})
	} else {
		line, err = marshalRecord(rolloutLine{Timestamp: at, Ordinal: n, Type: "response_item",
			Payload: messageItem{Type: "message", Role: "assistant", Content: []contentItem{{Type: "output_text", Text: text}}}})
	}
	if err != nil {
		return err
	}
	k, err := f.Write(line)
	if err != nil {
		return err
	}
	if k != len(line) {
		return fmt.Errorf("short write (%d of %d bytes)", k, len(line))
	}
	a.count++
	return nil
}

func (a *Appender) stopAppender() int {
	if a == nil || a.stop == nil {
		return 0
	}
	a.stopOnce.Do(func() { close(a.stop) })
	<-a.done
	if a.failures > 0 {
		a.t.Logf("codextest: appender on %s: %d append(s) failed, first: %v", a.path, a.failures, a.firstErr)
		a.failures = 0
	}
	return a.count
}

// marshalRecord renders one JSONL record with its '\n' (HTML escaping off,
// as serde_json writes). It never calls the test's Fatal: the writer runs
// on its own goroutine.
func marshalRecord(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
