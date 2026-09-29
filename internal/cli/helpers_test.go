package cli

import (
	"bytes"
	"sync"
)

// discard is a writer that throws everything away, for tests that only care
// about the exit code.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// testWriter is a concurrency-safe buffer, because some code paths log from
// background goroutines.
type testWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *testWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *testWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}
