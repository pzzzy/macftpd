package storage

import (
	"errors"
	"os"
	"testing"

	"macftpd/internal/auth"
)

func TestResolveStaysInsideRootAndHome(t *testing.T) {
	root, err := New(t.TempDir(), "public", "dropboxes", []string{".DS_Store", "._*"})
	if err != nil {
		t.Fatal(err)
	}
	user := auth.User{Username: "sam", Home: "/sam"}
	if _, _, err := root.Resolve(user, "/sam", "../public"); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("expected home escape denial, got %v", err)
	}
	real, virtual, err := root.Resolve(user, "/sam", "inbox/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if virtual != "/sam/inbox/file.txt" {
		t.Fatalf("bad virtual path: %s", virtual)
	}
	if real == root.Base {
		t.Fatal("file resolved to root unexpectedly")
	}
}

func TestResolveAdminCleansTraversal(t *testing.T) {
	root, err := New(t.TempDir(), "public", "dropboxes", []string{".DS_Store", "._*"})
	if err != nil {
		t.Fatal(err)
	}
	_, virtual, err := root.ResolveAdmin("/public/../dropboxes")
	if err != nil {
		t.Fatal(err)
	}
	if virtual != "/dropboxes" {
		t.Fatalf("unexpected clean path: %s", virtual)
	}
}

func TestIgnoredPathsAreHiddenAndDenied(t *testing.T) {
	root, err := New(t.TempDir(), "public", "dropboxes", []string{".DS_Store", "._*"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root.Base+"/keep.txt", []byte("ok"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root.Base+"/.DS_Store", []byte("no"), 0o640); err != nil {
		t.Fatal(err)
	}
	entries, err := root.List(root.Base, "/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "keep.txt" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
	if _, _, err := root.ResolveAdmin("/.DS_Store"); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("expected ignored file denial, got %v", err)
	}
}

func TestRootOperationsRejectSymlinkEscape(t *testing.T) {
	root, err := New(t.TempDir(), "public", "dropboxes", nil)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(outside+"/secret.txt", []byte("secret"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside+"/secret.txt", root.Base+"/leak.txt"); err != nil {
		t.Fatal(err)
	}
	real, _, err := root.ResolveAdmin("/leak.txt")
	if err != nil {
		t.Fatal(err)
	}
	file, err := root.Open(real)
	if err == nil {
		file.Close()
		t.Fatal("expected symlink escape to be rejected")
	}
}

func TestPublicAndDropboxMountsResolveInsideUserHome(t *testing.T) {
	root, err := New(t.TempDir(), "public", "dropboxes", nil)
	if err != nil {
		t.Fatal(err)
	}
	user := auth.User{Username: "sam", Home: "/sam", Permissions: auth.PermissionSet{Public: true, Dropbox: true}}
	if err := os.MkdirAll(root.Base+"/public", 0o750); err != nil {
		t.Fatal(err)
	}
	if err := root.EnsureUserHome(user); err != nil {
		t.Fatal(err)
	}
	entries, err := root.ListForUser(user, root.Base+"/sam", "/sam")
	if err != nil {
		t.Fatal(err)
	}
	var sawPublic, sawDropbox bool
	for _, entry := range entries {
		sawPublic = sawPublic || entry.Name == "public"
		sawDropbox = sawDropbox || entry.Name == "dropbox"
	}
	if !sawPublic || !sawDropbox {
		t.Fatalf("expected virtual mounts in home listing: %#v", entries)
	}
	real, virtual, err := root.Resolve(user, "/sam", "public/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if virtual != "/sam/public/file.txt" || real != root.Base+"/public/file.txt" {
		t.Fatalf("bad public mapping real=%q virtual=%q", real, virtual)
	}
	real, _, err = root.Resolve(user, "/sam", "dropbox/upload.txt")
	if err != nil {
		t.Fatal(err)
	}
	if real != root.Base+"/dropboxes/sam/upload.txt" {
		t.Fatalf("bad dropbox mapping: %q", real)
	}
}
