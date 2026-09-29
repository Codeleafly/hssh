package sessions

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNewIDIsUnpredictable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		if len(id) != IDLength*2 {
			t.Fatalf("id %q is not %d hex bytes", id, IDLength)
		}
		if seen[id] {
			t.Fatalf("duplicate session id %q", id)
		}
		seen[id] = true
	}
}

func TestCreateGetRemove(t *testing.T) {
	m := NewManager(0, 0)
	s, err := m.Create(Options{Client: "1.2.3.4", Cols: 100, Rows: 30, Auth: "none"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if m.Count() != 1 {
		t.Fatalf("count = %d", m.Count())
	}
	got, err := m.Get(s.ID())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID() != s.ID() {
		t.Fatalf("id mismatch")
	}
	if _, err := m.Get("does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := m.Remove(s.ID()); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if m.Count() != 0 {
		t.Fatalf("count after remove = %d", m.Count())
	}
	if _, err := m.Remove(s.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double remove should be ErrNotFound, got %v", err)
	}
}

func TestMaxSessionsEnforced(t *testing.T) {
	m := NewManager(3, 0)
	for i := 0; i < 3; i++ {
		if _, err := m.Create(Options{Client: "c"}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if _, err := m.Create(Options{Client: "overflow"}); !errors.Is(err, ErrFull) {
		t.Fatalf("want ErrFull, got %v", err)
	}
	// Freeing a slot must let a new session in.
	first := m.List()
	if len(first) != 3 {
		t.Fatalf("list len = %d", len(first))
	}
	if _, err := m.Remove(first[0].ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := m.Create(Options{Client: "after"}); err != nil {
		t.Fatalf("create after freeing a slot: %v", err)
	}
}

func TestUnlimitedSessions(t *testing.T) {
	m := NewManager(0, 0)
	for i := 0; i < 200; i++ {
		if _, err := m.Create(Options{Client: "c"}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if m.Count() != 200 {
		t.Fatalf("count = %d", m.Count())
	}
}

func TestCloseHookFiresOnce(t *testing.T) {
	m := NewManager(0, 0)
	var mu sync.Mutex
	fired := 0
	m.SetCloseHook(func(*Session) {
		mu.Lock()
		fired++
		mu.Unlock()
	})
	s, _ := m.Create(Options{Client: "c"})
	m.Remove(s.ID())
	m.Remove(s.ID()) // must not fire again
	mu.Lock()
	defer mu.Unlock()
	if fired != 1 {
		t.Fatalf("close hook fired %d times, want 1", fired)
	}
}

func TestStateTransitions(t *testing.T) {
	m := NewManager(0, 0)
	s, _ := m.Create(Options{Client: "c"})
	if s.Snapshot().State != StatePending {
		t.Fatalf("initial state = %s", s.Snapshot().State)
	}
	s.SetShell("bash", 1234)
	info := s.Snapshot()
	if info.State != StateRunning || info.Shell != "bash" || info.PID != 1234 {
		t.Fatalf("after SetShell: %+v", info)
	}
	s.SetSize(200, 50)
	if info := s.Snapshot(); info.Cols != 200 || info.Rows != 50 {
		t.Fatalf("after SetSize: %+v", info)
	}
	s.SetAuthenticated(true, "password")
	if info := s.Snapshot(); !info.Authenticated || info.Auth != "password" {
		t.Fatalf("after SetAuthenticated: %+v", info)
	}
	s.AddBytes(10, 20)
	s.AddBytes(5, 5)
	if info := s.Snapshot(); info.BytesIn != 15 || info.BytesOut != 25 {
		t.Fatalf("counters wrong: %+v", info)
	}
	s.SetState(StateClosing)
	if s.Snapshot().State != StateClosing {
		t.Fatal("state not updated")
	}
}

func TestListIsOrderedByCreation(t *testing.T) {
	m := NewManager(0, 0)
	var ids []string
	for i := 0; i < 5; i++ {
		s, err := m.Create(Options{Client: "c"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, s.ID())
		time.Sleep(time.Millisecond)
	}
	list := m.List()
	if len(list) != 5 {
		t.Fatalf("list len = %d", len(list))
	}
	for i, info := range list {
		if info.ID != ids[i] {
			t.Fatalf("list is not in creation order at %d: %s != %s", i, info.ID, ids[i])
		}
	}
}

func TestSweepRemovesOnlyIdleSessions(t *testing.T) {
	m := NewManager(0, 50*time.Millisecond)
	old, _ := m.Create(Options{Client: "old"})
	fresh, _ := m.Create(Options{Client: "fresh"})

	// The old one has not been touched since creation.
	time.Sleep(80 * time.Millisecond)
	fresh.Touch()

	ids := m.Sweep(time.Now())
	if len(ids) != 1 || ids[0] != old.ID() {
		t.Fatalf("sweep returned %v, want only the idle session %s", ids, old.ID())
	}
}

func TestSweepDisabledWithoutTTL(t *testing.T) {
	m := NewManager(0, 0)
	s, _ := m.Create(Options{Client: "c"})
	time.Sleep(20 * time.Millisecond)
	if got := m.Sweep(time.Now()); len(got) != 0 {
		t.Fatalf("sweep should be a no-op with a zero TTL, got %v", got)
	}
	_ = s
}

func TestSweepSkipsClosingSessions(t *testing.T) {
	m := NewManager(0, time.Millisecond)
	s, _ := m.Create(Options{Client: "c"})
	s.SetState(StateClosing)
	time.Sleep(5 * time.Millisecond)
	if got := m.Sweep(time.Now()); len(got) != 0 {
		t.Fatalf("a session already closing should not be swept again, got %v", got)
	}
}

func TestAllReturnsLiveSessions(t *testing.T) {
	m := NewManager(0, 0)
	for i := 0; i < 3; i++ {
		m.Create(Options{Client: "c"})
	}
	all := m.All()
	if len(all) != 3 {
		t.Fatalf("All() len = %d", len(all))
	}
	// The returned pointers must be usable after a concurrent remove.
	list := m.List()
	_, _ = m.Remove(list[0].ID)
	for _, s := range all {
		_ = s.Snapshot()
	}
}

func TestConcurrentCreateRemove(t *testing.T) {
	// The session manager is touched from every connection goroutine, so it
	// has to be race free under -race.
	m := NewManager(50, 0)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				s, err := m.Create(Options{Client: "c"})
				if err != nil {
					continue // ErrFull is a legitimate outcome under contention
				}
				s.Touch()
				s.AddBytes(1, 1)
				_ = m.List()
				_, _ = m.Remove(s.ID())
			}
		}()
	}
	wg.Wait()
	if m.Count() > 50 {
		t.Fatalf("count exceeded the limit: %d", m.Count())
	}
}
