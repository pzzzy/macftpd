package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu       sync.Mutex
	entries  map[string]entry
	limit    int
	window   time.Duration
	lockout  time.Duration
	lastTrim time.Time
}

type entry struct {
	Failures    int
	FirstFailed time.Time
	LockedUntil time.Time
	LastSeen    time.Time
}

func New(limit int, window, lockout time.Duration) *Limiter {
	if limit <= 0 {
		limit = 5
	}
	if window <= 0 {
		window = 10 * time.Minute
	}
	if lockout <= 0 {
		lockout = 5 * time.Minute
	}
	return &Limiter{entries: map[string]entry{}, limit: limit, window: window, lockout: lockout}
}

func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.trimLocked(now)
	e := l.entries[key]
	if now.After(e.LockedUntil) {
		return true
	}
	e.LastSeen = now
	l.entries[key] = e
	return false
}

func (l *Limiter) Fail(key string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.trimLocked(now)
	e := l.entries[key]
	if e.FirstFailed.IsZero() || now.Sub(e.FirstFailed) > l.window {
		e = entry{FirstFailed: now}
	}
	e.Failures++
	e.LastSeen = now
	if e.Failures >= l.limit {
		e.LockedUntil = now.Add(l.lockout)
	}
	l.entries[key] = e
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func (l *Limiter) trimLocked(now time.Time) {
	if now.Sub(l.lastTrim) < time.Minute {
		return
	}
	for key, e := range l.entries {
		if now.Sub(e.LastSeen) > l.window+l.lockout {
			delete(l.entries, key)
		}
	}
	l.lastTrim = now
}
