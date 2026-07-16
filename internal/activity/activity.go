package activity

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Event struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Type     string    `json:"type"`
	Protocol string    `json:"protocol,omitempty"`
	Actor    string    `json:"actor,omitempty"`
	Remote   string    `json:"remote,omitempty"`
	Referrer string    `json:"referrer,omitempty"`
	Action   string    `json:"action,omitempty"`
	Outcome  string    `json:"outcome,omitempty"`
	Path     string    `json:"path,omitempty"`
	DestPath string    `json:"dest_path,omitempty"`
	Bytes    int64     `json:"bytes,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Message  string    `json:"message"`
}

type PathStats struct {
	Path           string         `json:"path"`
	Downloads      int            `json:"downloads"`
	LastDownloadAt time.Time      `json:"last_download_at,omitempty"`
	Referrers      map[string]int `json:"referrers,omitempty"`
	Recent         []Event        `json:"recent,omitempty"`
}

type Store struct {
	mu     sync.RWMutex
	nextID int64
	limit  int
	path   string
	events []Event
}

func New(limit int) *Store {
	if limit <= 0 {
		limit = 1000
	}
	return &Store{limit: limit}
}

func NewFile(limit int, path string) (*Store, error) {
	s := New(limit)
	s.path = strings.TrimSpace(path)
	if s.path == "" {
		return s, nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return nil, err
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Add(e Event) Event {
	if s == nil {
		return e
	}
	now := time.Now().UTC()
	if e.Time.IsZero() {
		e.Time = now
	}
	e.Type = strings.TrimSpace(e.Type)
	e.Protocol = strings.TrimSpace(e.Protocol)
	e.Actor = strings.TrimSpace(e.Actor)
	e.Remote = strings.TrimSpace(e.Remote)
	e.Referrer = strings.TrimSpace(e.Referrer)
	e.Action = strings.TrimSpace(e.Action)
	e.Outcome = strings.TrimSpace(e.Outcome)
	if e.Outcome == "" {
		e.Outcome = "ok"
	}
	if e.Message == "" {
		e.Message = e.humanMessage()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	e.ID = s.nextID
	s.events = append(s.events, e)
	if len(s.events) > s.limit {
		copy(s.events, s.events[len(s.events)-s.limit:])
		s.events = s.events[:s.limit]
	}
	if s.path != "" {
		_ = appendEvent(s.path, e)
	}
	return e
}

func (s *Store) Recent(limit int, afterID int64) []Event {
	if s == nil {
		return nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Event, 0, min(limit, len(s.events)))
	for i := len(s.events) - 1; i >= 0 && len(out) < limit; i-- {
		e := s.events[i]
		if afterID > 0 && e.ID <= afterID {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (s *Store) StatsForPath(path string, limit int) PathStats {
	stats := PathStats{Path: path, Referrers: map[string]int{}}
	if s == nil {
		return stats
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if e.Path != path || e.Outcome != "ok" || e.Action != "download" {
			continue
		}
		if e.Type != "public_download" && e.Type != "share_download" {
			continue
		}
		stats.Downloads++
		if stats.LastDownloadAt.IsZero() {
			stats.LastDownloadAt = e.Time
		}
		if e.Referrer != "" {
			stats.Referrers[e.Referrer]++
		}
		if len(stats.Recent) < limit {
			stats.Recent = append(stats.Recent, e)
		}
	}
	if len(stats.Referrers) == 0 {
		stats.Referrers = nil
	}
	return stats
}

func (s *Store) load() error {
	file, err := os.Open(s.path)
	if errorsIsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var e Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		if e.ID > s.nextID {
			s.nextID = e.ID
		}
		s.events = append(s.events, e)
		if len(s.events) > s.limit {
			copy(s.events, s.events[len(s.events)-s.limit:])
			s.events = s.events[:s.limit]
		}
	}
	return scanner.Err()
}

func appendEvent(path string, e Event) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- activity log path is constructed from the operator-controlled auth config directory.
	if err != nil {
		return err
	}
	defer file.Close()
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}

func (e Event) humanMessage() string {
	actor := e.Actor
	if actor == "" {
		actor = "someone"
	}
	action := e.Action
	if action == "" {
		action = e.Type
	}
	subject := e.Path
	if subject == "" {
		subject = e.Detail
	}
	switch e.Outcome {
	case "failed", "denied", "limited":
		if subject != "" {
			return fmt.Sprintf("%s %s failed for %s", actor, action, subject)
		}
		return fmt.Sprintf("%s %s failed", actor, action)
	case "canceled", "cancelled":
		if subject != "" {
			return fmt.Sprintf("%s %s canceled for %s", actor, action, subject)
		}
		return fmt.Sprintf("%s %s canceled", actor, action)
	}
	if e.DestPath != "" && subject != "" {
		return fmt.Sprintf("%s %s %s to %s", actor, action, subject, e.DestPath)
	}
	if subject != "" {
		return fmt.Sprintf("%s %s %s", actor, action, subject)
	}
	return fmt.Sprintf("%s %s", actor, action)
}
