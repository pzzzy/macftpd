package ftpserver

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	ftpclient "github.com/jlaffaye/ftp"

	"macftpd/internal/activity"
	"macftpd/internal/auth"
	"macftpd/internal/config"
	"macftpd/internal/storage"
)

func TestFTPStoreRetrieveAndDelete(t *testing.T) {
	dir := t.TempDir()
	store, err := auth.Open(dir + "/users.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapAdmin("admin", "secret"); err != nil {
		t.Fatal(err)
	}
	root, err := storage.New(dir+"/root", "public", "dropboxes", nil)
	if err != nil {
		t.Fatal(err)
	}
	activityLog := activity.New(100)
	server, err := New(config.FTPConfig{Listen: "127.0.0.1:0", PassivePorts: "", AllowActive: true, Welcome: "test"}, store, root, activityLog, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() { errs <- server.ListenAndServe(ctx) }()
	addr := waitAddr(t, server)

	conn, err := ftpclient.Dial(addr, ftpclient.DialWithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Quit()
	if err := conn.Login("admin", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := conn.MakeDir("incoming"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Stor("incoming/hello.txt", strings.NewReader("hello ftp")); err != nil {
		t.Fatal(err)
	}
	rc, err := conn.Retr("incoming/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "hello ftp" {
		t.Fatalf("unexpected payload: %q", string(raw))
	}
	if err := conn.Delete("incoming/hello.txt"); err != nil {
		t.Fatal(err)
	}
	events := activityLog.Recent(20, 0)
	var sawLogin, sawUpload, sawDownload, sawDelete bool
	for _, event := range events {
		sawLogin = sawLogin || event.Action == "login"
		sawUpload = sawUpload || event.Action == "upload"
		sawDownload = sawDownload || event.Action == "download"
		sawDelete = sawDelete || event.Action == "delete"
	}
	if !sawLogin || !sawUpload || !sawDownload || !sawDelete {
		t.Fatalf("missing FTP activity events: %#v", events)
	}
	cancel()
	select {
	case err := <-errs:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestFTPResumeStoreAndRetrieve(t *testing.T) {
	dir := t.TempDir()
	store, err := auth.Open(dir + "/users.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapAdmin("admin", "secret"); err != nil {
		t.Fatal(err)
	}
	root, err := storage.New(dir+"/root", "public", "dropboxes", nil)
	if err != nil {
		t.Fatal(err)
	}
	activityLog := activity.New(100)
	server, err := New(config.FTPConfig{Listen: "127.0.0.1:0", PassivePorts: "", AllowActive: true, Welcome: "test"}, store, root, activityLog, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() { errs <- server.ListenAndServe(ctx) }()
	addr := waitAddr(t, server)

	conn, err := ftpclient.Dial(addr, ftpclient.DialWithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Quit()
	if err := conn.Login("admin", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := conn.MakeDir("incoming"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Stor("incoming/resume.bin", bytes.NewReader([]byte("abcdef"))); err != nil {
		t.Fatal(err)
	}
	if err := conn.StorFrom("incoming/resume.bin", bytes.NewReader([]byte("XYZ")), 3); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dir + "/root/incoming/resume.bin")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "abcXYZ" {
		t.Fatalf("unexpected resumed payload: %q", raw)
	}
	if err := conn.StorFrom("incoming/resume.bin", bytes.NewReader([]byte("bad")), 99); err == nil {
		t.Fatal("resume past end succeeded")
	}
	raw, err = os.ReadFile(dir + "/root/incoming/resume.bin")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "abcXYZ" {
		t.Fatalf("failed resume changed payload: %q", raw)
	}
	rc, err := conn.RetrFrom("incoming/resume.bin", 3)
	if err != nil {
		t.Fatal(err)
	}
	tail, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(tail) != "XYZ" {
		t.Fatalf("unexpected resumed download payload: %q", tail)
	}
	events := activityLog.Recent(20, 0)
	var sawUploadResume, sawDownloadResume bool
	for _, event := range events {
		sawUploadResume = sawUploadResume || event.Action == "upload" && strings.Contains(event.Detail, "resumed at offset 3")
		sawDownloadResume = sawDownloadResume || event.Action == "download" && strings.Contains(event.Detail, "resumed at offset 3")
	}
	if !sawUploadResume || !sawDownloadResume {
		t.Fatalf("missing resume activity events: %#v", events)
	}
	cancel()
	select {
	case err := <-errs:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestFTPPublicDropboxMountsAndPublicDeleteProtection(t *testing.T) {
	dir := t.TempDir()
	store, err := auth.Open(dir + "/users.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertUser(auth.User{
		Username: "publisher",
		Home:     "/publisher",
		Permissions: auth.PermissionSet{
			List: true, Download: true, Upload: true, Delete: true, Rename: true, Mkdir: true, Public: true, Dropbox: true,
		},
	}, "secret"); err != nil {
		t.Fatal(err)
	}
	root, err := storage.New(dir+"/root", "public", "dropboxes", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir+"/root/public", 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/root/public/keep.txt", []byte("keep"), 0o640); err != nil {
		t.Fatal(err)
	}
	server, err := New(config.FTPConfig{Listen: "127.0.0.1:0", PassivePorts: "", AllowActive: true, Welcome: "test"}, store, root, activity.New(100), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() { errs <- server.ListenAndServe(ctx) }()
	addr := waitAddr(t, server)

	conn, err := ftpclient.Dial(addr, ftpclient.DialWithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Quit()
	if err := conn.Login("publisher", "secret"); err != nil {
		t.Fatal(err)
	}
	entries, err := conn.List("")
	if err != nil {
		t.Fatal(err)
	}
	var sawPublic, sawDropbox bool
	for _, entry := range entries {
		sawPublic = sawPublic || entry.Name == "public"
		sawDropbox = sawDropbox || entry.Name == "dropbox"
	}
	if !sawPublic || !sawDropbox {
		t.Fatalf("expected public and dropbox mounts, got %#v", entries)
	}
	if err := conn.Stor("dropbox/upload.txt", strings.NewReader("payload")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir + "/root/dropboxes/publisher/upload.txt"); err != nil {
		t.Fatalf("dropbox upload not mapped: %v", err)
	}
	if err := conn.Delete("public/keep.txt"); err == nil {
		t.Fatal("public delete succeeded for non-admin")
	}
	cancel()
	select {
	case err := <-errs:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}

func waitAddr(t *testing.T, server *Server) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		addr := server.Addr()
		if !strings.HasSuffix(addr, ":0") {
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not listen")
	return ""
}
