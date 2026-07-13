package share

import (
	"errors"
	"testing"
)

func TestDownloadReservationEnforcesLimitAtomically(t *testing.T) {
	path := t.TempDir() + "/shares.json"
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(CreateRequest{Kind: KindDownload, Path: "/public/file.bin", CreatedBy: "admin", MaxDownloads: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReserveDownload(created.Link.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.ReserveDownload(created.Link.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("second concurrent reservation error = %v, want ErrExpired", err)
	}
	if err := store.FinishDownload(created.Link.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := store.ReserveDownload(created.Link.ID); err != nil {
		t.Fatalf("reservation after incomplete transfer: %v", err)
	}
	if err := store.FinishDownload(created.Link.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := store.ReserveDownload(created.Link.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("reservation after completed transfer error = %v, want ErrExpired", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	link, err := reopened.Public(created.Link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if link.DownloadCount != 1 || link.LastDownloadAt == nil {
		t.Fatalf("completed reservation was not persisted: %#v", link)
	}
}
