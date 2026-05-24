package activity

import (
	"path/filepath"
	"testing"
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
