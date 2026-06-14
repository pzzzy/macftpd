package ftpserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
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

func TestFTPMonitorDeleteSkipsTrash(t *testing.T) {
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
	if err := conn.MakeDir("_monitor"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Stor("_monitor/probe.txt", strings.NewReader("probe")); err != nil {
		t.Fatal(err)
	}
	if err := conn.Delete("_monitor/probe.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir + "/root/_monitor/probe.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("monitor probe still exists or stat failed unexpectedly: %v", err)
	}
	retained, err := root.ListRetained("trash")
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 0 {
		t.Fatalf("monitor delete should not retain trash entries: %#v", retained)
	}
	events := activityLog.Recent(20, 0)
	var sawPermanentCleanup bool
	for _, event := range events {
		sawPermanentCleanup = sawPermanentCleanup || event.Action == "delete" && strings.Contains(event.Detail, "monitor cleanup")
	}
	if !sawPermanentCleanup {
		t.Fatalf("missing monitor cleanup activity event: %#v", events)
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

func TestFTPSResumeStoreAndRetrieve(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCert(t, dir)
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
	server, err := New(config.FTPConfig{Listen: "127.0.0.1:0", PassivePorts: "", AllowActive: true, TLSCertFile: certPath, TLSKeyFile: keyPath, Welcome: "test"}, store, root, activity.New(100), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() { errs <- server.ListenAndServe(ctx) }()
	addr := waitAddr(t, server)

	conn, err := ftpclient.Dial(addr, ftpclient.DialWithTimeout(5*time.Second), ftpclient.DialWithExplicitTLS(&tls.Config{InsecureSkipVerify: true})) // #nosec G402 -- test cert is self-signed.
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Quit()
	if err := conn.Login("admin", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := conn.MakeDir("secure"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Stor("secure/resume.bin", bytes.NewReader([]byte("abcdef"))); err != nil {
		t.Fatal(err)
	}
	if err := conn.StorFrom("secure/resume.bin", bytes.NewReader([]byte("XYZ")), 3); err != nil {
		t.Fatal(err)
	}
	rc, err := conn.RetrFrom("secure/resume.bin", 3)
	if err != nil {
		t.Fatal(err)
	}
	tail, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(tail) != "XYZ" {
		t.Fatalf("unexpected FTPS resumed download payload: %q", tail)
	}
	raw, err := os.ReadFile(dir + "/root/secure/resume.bin")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "abcXYZ" {
		t.Fatalf("unexpected FTPS resumed payload: %q", raw)
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

func TestFTPReadNoiseSuppression(t *testing.T) {
	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	}()

	server := &Server{readNoise: make(map[string]readNoiseEvent)}
	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 43210}
	err := errors.New("read tcp 203.0.113.10:2121->203.0.113.9:43210: read: connection reset by peer")
	server.logReadError(addr, err)
	server.logReadError(addr, err)
	if got := strings.Count(buf.String(), "connection_reset"); got != 1 {
		t.Fatalf("expected one immediate reset log, got %d in %q", got, buf.String())
	}

	server.readNoiseMu.Lock()
	for key, event := range server.readNoise {
		event.nextLog = time.Now().Add(-time.Second)
		server.readNoise[key] = event
	}
	server.readNoiseMu.Unlock()
	server.logReadError(addr, err)
	if !strings.Contains(buf.String(), "suppressed=2") {
		t.Fatalf("expected suppression summary, got %q", buf.String())
	}
}

func writeTestCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := dir + "/cert.pem"
	keyPath := dir + "/key.pem"
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
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
