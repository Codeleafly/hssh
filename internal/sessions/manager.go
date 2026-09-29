// Package sessions tracks live HSSH terminal sessions: their identity, the PTY
// and shell behind them, size, auth state and liveness. Every session owns its
// own PTY, so two clients can never end up sharing a shell.
package sessions

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
)

// IDLength is the number of random bytes in a session identifier. 16 bytes is
// 128 bits of entropy, so guessing or hijacking a session is not feasible.
const IDLength = 16

// State is the lifecycle of a session.
type State string

const (
	StatePending State = "pending" // authenticated, PTY not yet started
	StateRunning State = "running" // PTY and shell live
	StateClosing State = "closing" // shutting down
	StateClosed  State = "closed"  // resources released
)

// Errors from the manager.
var (
	ErrNotFound  = errors.New("session not found")
	ErrFull      = errors.New("session limit reached")
	ErrDuplicate = errors.New("session already exists")
)

// Info is a snapshot of a session, safe to copy and render.
type Info struct {
	ID            string
	Client        string
	Shell         string
	Cols          int
	Rows          int
	Auth          string
	State         State
	Created       time.Time
	LastSeen      time.Time
	PID           int
	BytesIn       int64
	BytesOut      int64
	Authenticated bool
}

// Session is the live record. Callers use it through the manager.
type Session struct {
	info Info

	mu   sync.Mutex
	idle bool
}

// ID returns the session identifier.
func (s *Session) ID() string { return s.info.ID }

// Snapshot returns a consistent copy of the session state.
func (s *Session) Snapshot() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}

// Touch updates the last-activity timestamp.
func (s *Session) Touch() {
	s.mu.Lock()
	s.info.LastSeen = time.Now()
	s.mu.Unlock()
}

// SetShell records which shell is backing the session.
func (s *Session) SetShell(name string, pid int) {
	s.mu.Lock()
	s.info.Shell = name
	s.info.PID = pid
	s.info.State = StateRunning
	s.mu.Unlock()
}

// SetSize records the PTY window size.
func (s *Session) SetSize(cols, rows int) {
	s.mu.Lock()
	s.info.Cols = cols
	s.info.Rows = rows
	s.mu.Unlock()
}

// SetState records the lifecycle transition.
func (s *Session) SetState(st State) {
	s.mu.Lock()
	s.info.State = st
	s.mu.Unlock()
}

// AddBytes updates the traffic counters used for slow-client detection.
func (s *Session) AddBytes(in, out int64) {
	s.mu.Lock()
	s.info.BytesIn += in
	s.info.BytesOut += out
	s.mu.Unlock()
}

// SetAuthenticated records the result of the auth exchange.
func (s *Session) SetAuthenticated(ok bool, method string) {
	s.mu.Lock()
	s.info.Authenticated = ok
	if method != "" {
		s.info.Auth = method
	}
	s.mu.Unlock()
}

// Snapshot registry state.
func (s *Session) SnapshotInfo() Info { return s.Snapshot() }

// NewID returns a cryptographically strong session identifier.
func NewID() (string, error) {
	buf := make([]byte, IDLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Options configure a new session.
type Options struct {
	Client string
	Cols   int
	Rows   int
	Auth   string
}

// Manager owns the live session set.
type Manager struct {
	mu    sync.RWMutex
	byID  map[string]*Session
	order []string // insertion order for stable listing

	max     int
	idleTTL time.Duration

	// onClose is invoked exactly once per session when it is removed.
	onClose func(*Session)
}

// NewManager builds a manager. max <= 0 means unlimited.
func NewManager(max int, idleTTL time.Duration) *Manager {
	if max < 0 {
		max = 0
	}
	return &Manager{byID: make(map[string]*Session), max: max, idleTTL: idleTTL}
}

// SetCloseHook installs a callback fired on removal.
func (m *Manager) SetCloseHook(fn func(*Session)) { m.onClose = fn }

// Create allocates a new session id and registers it.
func (m *Manager) Create(opts Options) (*Session, error) {
	m.mu.Lock()
	if m.max > 0 && len(m.byID) >= m.max {
		m.mu.Unlock()
		return nil, ErrFull
	}
	m.mu.Unlock()

	// Generate outside the lock; retry on the astronomically unlikely clash.
	for attempt := 0; attempt < 5; attempt++ {
		id, err := NewID()
		if err != nil {
			return nil, err
		}
		now := time.Now()
		s := &Session{info: Info{
			ID:            id,
			Client:        opts.Client,
			Cols:          opts.Cols,
			Rows:          opts.Rows,
			Auth:          opts.Auth,
			State:         StatePending,
			Created:       now,
			LastSeen:      now,
			Authenticated: false,
		}}
		m.mu.Lock()
		if _, exists := m.byID[id]; exists {
			m.mu.Unlock()
			continue
		}
		if m.max > 0 && len(m.byID) >= m.max {
			m.mu.Unlock()
			return nil, ErrFull
		}
		m.byID[id] = s
		m.order = append(m.order, id)
		m.mu.Unlock()
		return s, nil
	}
	return nil, errors.New("session: could not allocate a unique id")
}

// Get returns a session by id.
func (m *Manager) Get(id string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return s, nil
}

// Remove deletes a session and fires the close hook.
func (m *Manager) Remove(id string) (*Session, error) {
	m.mu.Lock()
	s, ok := m.byID[id]
	if !ok {
		m.mu.Unlock()
		return nil, ErrNotFound
	}
	delete(m.byID, id)
	for i, v := range m.order {
		if v == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	m.mu.Unlock()

	if s != nil {
		s.SetState(StateClosed)
	}
	if m.onClose != nil && s != nil {
		m.onClose(s)
	}
	return s, nil
}

// List returns snapshots ordered by creation time, which is stable and easy to
// read in the sessions table.
func (m *Manager) List() []Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Info, 0, len(m.order))
	for _, id := range m.order {
		if s, ok := m.byID[id]; ok {
			out = append(out, s.Snapshot())
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// Count returns the number of live sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byID)
}

// Sweep returns the ids of sessions idle for longer than the configured TTL.
// A TTL of zero disables the sweep.
func (m *Manager) Sweep(now time.Time) []string {
	if m.idleTTL <= 0 {
		return nil
	}
	m.mu.RLock()
	var out []string
	for id, s := range m.byID {
		info := s.Snapshot()
		if info.State == StateClosed || info.State == StateClosing {
			continue
		}
		if now.Sub(info.LastSeen) > m.idleTTL {
			out = append(out, id)
		}
	}
	m.mu.RUnlock()
	sort.Strings(out)
	return out
}

// All returns the live session objects, for shutdown.
func (m *Manager) All() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.order))
	for _, id := range m.order {
		if s, ok := m.byID[id]; ok {
			out = append(out, s)
		}
	}
	return out
}
