package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSpoolRoundTrip(t *testing.T) {
	s, err := NewSpool(t.TempDir())
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	if err := s.Add("events", []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.Add("vulns", []byte(`{"b":2}`)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	raw, err := s.Read(entries[0].Path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(raw) != `{"a":1}` {
		t.Errorf("payload = %q", raw)
	}

	if err := s.Remove(entries[0].Path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	entries, _ = s.List()
	if len(entries) != 1 {
		t.Fatalf("after remove got %d, want 1", len(entries))
	}
}

// TestSpoolReplayAfterOutage simulates the offline-resilience path: payloads
// queued while the server is down are replayed in order once it returns.
func TestSpoolReplayAfterOutage(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, _ := NewSpool(t.TempDir())
	// Queue work as if the server had been unreachable.
	_ = s.Add("events", []byte(`{"n":1}`))
	_ = s.Add("events", []byte(`{"n":2}`))

	c := newTestClient(t, srv)
	entries, _ := s.List()
	for _, e := range entries {
		raw, _ := s.Read(e.Path)
		if err := c.PostRaw(context.Background(), "/api/edr/events", raw); err != nil {
			t.Fatalf("replay: %v", err)
		}
		_ = s.Remove(e.Path)
	}

	if got := atomic.LoadInt32(&received); got != 2 {
		t.Errorf("server received %d, want 2", got)
	}
	if left, _ := s.List(); len(left) != 0 {
		t.Errorf("spool not drained, %d left", len(left))
	}
}
