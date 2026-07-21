package activity

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFileStoreReloadsRecentEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity.jsonl")
	store, err := NewFile(10, path)
	if err != nil {
		t.Fatal(err)
	}
	first := store.Add(Event{Actor: "admin", Protocol: "http", Action: "copy", Path: "/incoming/a.txt", DestPath: "/public/a.txt"})
	store.Add(Event{Actor: "user", Protocol: "ftp", Action: "download", Path: "/public/a.txt"})

	reloaded, err := NewFile(10, path)
	if err != nil {
		t.Fatal(err)
	}
	events := reloaded.Recent(10, 0)
	if len(events) != 2 {
		t.Fatalf("events len = %d, want 2: %#v", len(events), events)
	}
	if events[1].ID != first.ID || events[1].Message == "" {
		t.Fatalf("first event did not reload cleanly: %#v", events[1])
	}
	next := reloaded.Add(Event{Actor: "admin", Action: "move", Path: "/public/a.txt", DestPath: "/public/b.txt"})
	if next.ID <= events[0].ID {
		t.Fatalf("next ID = %d, want greater than %d", next.ID, events[0].ID)
	}
}

func TestStateTracksBoundedHistory(t *testing.T) {
	store := New(2)
	firstTime := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	store.Add(Event{Time: firstTime, Action: "first"})
	second := store.Add(Event{Time: firstTime.Add(time.Minute), Action: "second"})
	third := store.Add(Event{Time: firstTime.Add(2 * time.Minute), Action: "third"})

	state := store.State()
	if state.Count != 2 || state.Capacity != 2 {
		t.Fatalf("state size = %#v, want 2/2", state)
	}
	if state.OldestID != second.ID || state.NewestID != third.ID {
		t.Fatalf("state IDs = %#v, want oldest=%d newest=%d", state, second.ID, third.ID)
	}
	if !state.OldestTime.Equal(firstTime.Add(time.Minute)) || !state.NewestTime.Equal(firstTime.Add(2*time.Minute)) {
		t.Fatalf("state times = %#v", state)
	}
}
