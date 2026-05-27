package status

import (
	"sort"
	"sync"
	"time"
)

type Session struct {
	ID        int64     `json:"id"`
	Protocol  string    `json:"protocol"`
	User      string    `json:"user,omitempty"`
	Remote    string    `json:"remote"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Secure    bool      `json:"secure,omitempty"`
	Mode      string    `json:"mode,omitempty"`
	Action    string    `json:"action,omitempty"`
	Path      string    `json:"path,omitempty"`
	Bytes     int64     `json:"bytes,omitempty"`
}

type Tracker struct {
	mu       sync.RWMutex
	nextID   int64
	sessions map[int64]Session
}

func New() *Tracker {
	return &Tracker{sessions: map[int64]Session{}}
}

func (t *Tracker) Add(protocol, remote string) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextID++
	now := time.Now().UTC()
	t.sessions[t.nextID] = Session{ID: t.nextID, Protocol: protocol, Remote: remote, StartedAt: now, UpdatedAt: now}
	return t.nextID
}

func (t *Tracker) Update(id int64, mutate func(*Session)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[id]
	if !ok {
		return
	}
	mutate(&s)
	s.UpdatedAt = time.Now().UTC()
	t.sessions[id] = s
}

func (t *Tracker) Remove(id int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, id)
}

func (t *Tracker) Snapshot() []Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Session, 0, len(t.sessions))
	for _, s := range t.sessions {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.Before(out[j].StartedAt) })
	return out
}
