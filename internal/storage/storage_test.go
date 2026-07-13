package storage

import (
	"errors"
	"os"
	"path/filepath"
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

func TestReplaceFilePreservesOriginalWhenVersioningFails(t *testing.T) {
	root, err := New(t.TempDir(), "public", "dropboxes", nil)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root.Base, "movie.mkv")
	staged := filepath.Join(root.Base, "staged.part")
	if err := os.WriteFile(dest, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root.Base, "._macftpd_versions"), []byte("block retention directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := root.ReplaceFile(staged, dest, "/movie.mkv", "tester", true); err == nil {
		t.Fatal("expected retention failure")
	}
	raw, err := os.ReadFile(dest)
	if err != nil || string(raw) != "original" {
		t.Fatalf("destination changed after failed retention: payload=%q err=%v", raw, err)
	}
	raw, err = os.ReadFile(staged)
	if err != nil || string(raw) != "replacement" {
		t.Fatalf("staged replacement was lost: payload=%q err=%v", raw, err)
	}
}

func TestInstallFileDoesNotReplaceExistingDestination(t *testing.T) {
	root, err := New(t.TempDir(), "public", "dropboxes", nil)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root.Base, "existing.txt")
	staged := filepath.Join(root.Base, "staged.part")
	if err := os.WriteFile(dest, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := root.InstallFile(staged, dest); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected destination-exists failure, got %v", err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil || string(raw) != "original" {
		t.Fatalf("destination changed: payload=%q err=%v", raw, err)
	}
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("staged file should remain for caller cleanup: %v", err)
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

func TestInternalStorageDirectoriesAreAlwaysHidden(t *testing.T) {
	root, err := New(t.TempDir(), "public", "dropboxes", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"._macftpd_uploads", "._macftpd_versions", "._macftpd_trash"} {
		if err := os.MkdirAll(root.Base+"/"+name, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, _, err := root.ResolveAdmin("/" + name); !errors.Is(err, ErrOutsideRoot) {
			t.Fatalf("internal path %s was addressable: %v", name, err)
		}
	}
	entries, err := root.List(root.Base, "/")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("internal directories leaked into listing: %#v", entries)
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
