package httpapi

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"macftpd/internal/activity"
	"macftpd/internal/auth"
	"macftpd/internal/cloudflare"
	"macftpd/internal/config"
	"macftpd/internal/share"
	"macftpd/internal/storage"
)

func TestPublicFileHeadersAndDirectoryListing(t *testing.T) {
	srv := testServer(t)
	if err := os.WriteFile(srv.root.Base+"/public/hello.txt", []byte("hello"), 0o640); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/public/hello.txt", nil)
	rr := httptest.NewRecorder()
	srv.public(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	for _, header := range []string{"Cache-Control", "CDN-Cache-Control", "Cloudflare-CDN-Cache-Control", "Cache-Tag"} {
		if rr.Header().Get(header) == "" {
			t.Fatalf("missing %s", header)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/public/", nil)
	rr = httptest.NewRecorder()
	srv.public(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("listing status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "hello.txt") || !strings.Contains(rr.Body.String(), "Public Files") {
		t.Fatalf("listing did not render expected content: %s", rr.Body.String())
	}
}

func TestPublicPathCannotEscapePublicDirectory(t *testing.T) {
	srv := testServer(t)
	if err := os.WriteFile(srv.root.Base+"/secret.txt", []byte("secret"), 0o640); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/public/../secret.txt", nil)
	rr := httptest.NewRecorder()
	srv.public(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for escaped public path, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestIgnoredPublicFileIsNotServed(t *testing.T) {
	srv := testServer(t)
	if err := os.WriteFile(srv.root.Base+"/public/.DS_Store", []byte("secret"), 0o640); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/public/.DS_Store", nil)
	rr := httptest.NewRecorder()
	srv.public(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected ignored file 404, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAdminFileDetailRenameAndDownload(t *testing.T) {
	srv := testServer(t)
	if err := os.WriteFile(srv.root.Base+"/public/info.txt", []byte("detail"), 0o640); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/files?path=/public/info.txt", nil)
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	srv.requireAdmin(srv.files)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("detail status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"size_text"`) || !strings.Contains(rr.Body.String(), `"mode"`) {
		t.Fatalf("detail response missing metadata: %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPatch, "/api/files?path=/public/info.txt", strings.NewReader(`{"dest_path":"/public/renamed.txt"}`))
	req.SetBasicAuth("admin", "secret")
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	srv.requireAdmin(srv.files)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rename status = %d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/download?path=/public/renamed.txt", nil)
	req.SetBasicAuth("admin", "secret")
	rr = httptest.NewRecorder()
	srv.requireAdmin(srv.download)(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "detail" {
		t.Fatalf("download status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestAdminFileActionCopyMoveAndActivity(t *testing.T) {
	srv := testServer(t)
	if err := os.MkdirAll(srv.root.Base+"/incoming", 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srv.root.Base+"/incoming/upload.txt", []byte("payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	body := strings.NewReader(`{"operation":"copy","paths":["/incoming/upload.txt"],"dest_path":"/public","deduplicate":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/files/action", body)
	req.SetBasicAuth("admin", "secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.requireAdmin(srv.fileAction)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("copy status = %d body=%s", rr.Code, rr.Body.String())
	}
	if raw, err := os.ReadFile(srv.root.Base + "/public/upload.txt"); err != nil || string(raw) != "payload" {
		t.Fatalf("copy missing payload=%q err=%v", string(raw), err)
	}

	body = strings.NewReader(`{"operation":"move","paths":["/incoming/upload.txt"],"dest_path":"/public/moved.txt"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/files/action", body)
	req.SetBasicAuth("admin", "secret")
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	srv.requireAdmin(srv.fileAction)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("move status = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(srv.root.Base + "/incoming/upload.txt"); !os.IsNotExist(err) {
		t.Fatalf("move left source behind err=%v", err)
	}
	if raw, err := os.ReadFile(srv.root.Base + "/public/moved.txt"); err != nil || string(raw) != "payload" {
		t.Fatalf("move missing payload=%q err=%v", string(raw), err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/activity?limit=20", nil)
	req.SetBasicAuth("admin", "secret")
	rr = httptest.NewRecorder()
	srv.requireAdmin(srv.activityFeed)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("activity status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"action":"copy"`) || !strings.Contains(rr.Body.String(), `"action":"move"`) {
		t.Fatalf("activity missing copy/move: %s", rr.Body.String())
	}
}

func TestUploadRejectsIgnoredDestination(t *testing.T) {
	srv := testServer(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("path", "/public"); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("file", ".DS_Store")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/upload", &body)
	req.SetBasicAuth("admin", "secret")
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	srv.requireAdmin(srv.upload)(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected ignored upload denial, got %d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(srv.root.Base + "/public/.DS_Store"); !os.IsNotExist(err) {
		t.Fatalf("ignored upload was written, stat err=%v", err)
	}
}

func TestUsersAPIRejectsPasswordHashMassAssignment(t *testing.T) {
	srv := testServer(t)
	body := strings.NewReader(`{"username":"hashonly","password_hash":"pbkdf2-sha256$1$bad$bad","home":"/hashonly","permissions":{"list":true}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/users", body)
	req.SetBasicAuth("admin", "secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.requireAdmin(srv.users)(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, _, ok := srv.store.Permissions("hashonly"); ok {
		t.Fatal("hash-only user was created")
	}
}

func TestUsersAPICreateListAndLastAdminProtection(t *testing.T) {
	srv := testServer(t)
	body := strings.NewReader(`{"username":"webuser","password":"secret123","home":"/webuser","permissions":{"list":true,"download":true}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/users", body)
	req.SetBasicAuth("admin", "secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.requireAdmin(srv.users)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status = %d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.SetBasicAuth("admin", "secret")
	rr = httptest.NewRecorder()
	srv.requireAdmin(srv.users)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status = %d", rr.Code)
	}
	var listed struct {
		Users []auth.User `json:"users"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	var sawAdmin, sawWebuser bool
	for _, user := range listed.Users {
		if user.PasswordHash != "" {
			t.Fatalf("password hash leaked for %s", user.Username)
		}
		sawAdmin = sawAdmin || user.Username == "admin"
		sawWebuser = sawWebuser || user.Username == "webuser"
	}
	if !sawAdmin || !sawWebuser {
		t.Fatalf("expected admin and webuser in list: %#v", listed.Users)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/users/admin", nil)
	req.SetBasicAuth("admin", "secret")
	rr = httptest.NewRecorder()
	srv.requireAdmin(srv.user)(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected last admin delete to fail, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAdminBasicAuthSetsSessionCookie(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.SetBasicAuth("admin", "secret")
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	srv.requireAdmin(srv.admin)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var session *http.Cookie
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "macftpd_session" {
			session = cookie
			break
		}
	}
	if session == nil {
		t.Fatal("admin page did not set session cookie")
	}
	if !session.HttpOnly || !session.Secure {
		t.Fatalf("session flags: HttpOnly=%v Secure=%v", session.HttpOnly, session.Secure)
	}
}

func TestAdminFileBrowserUsesHistoryState(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/?path=/public&selected=/public/info.txt", nil)
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	srv.requireAdmin(srv.admin)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, needle := range []string{"fileSearch", "history.pushState", "popstate", "Copy selected", "Activity", "uploadForm"} {
		if !strings.Contains(body, needle) {
			t.Fatalf("admin file browser missing %q", needle)
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	srv := testServer(t)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
		req.RemoteAddr = "203.0.113.9:12345"
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		srv.login(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	req.RemoteAddr = "203.0.113.9:12345"
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.login(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestBasicAuthRateLimit(t *testing.T) {
	srv := testServer(t)
	handler := srv.requireAdmin(func(w http.ResponseWriter, r *http.Request, _ principal) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		req.SetBasicAuth("admin", "wrong")
		rr := httptest.NewRecorder()
		handler(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSecurityHeadersForAdminAPI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})).ServeHTTP(rr, req)
	for _, header := range []string{"X-Content-Type-Options", "X-Frame-Options", "Permissions-Policy", "Content-Security-Policy", "Strict-Transport-Security"} {
		if rr.Header().Get(header) == "" {
			t.Fatalf("missing %s", header)
		}
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestUnsafeAdminAPIRejectsCrossOrigin(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(`{}`))
	req.Host = "ftp.example.com"
	req.Header.Set("Origin", "https://evil.example")
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	srv.requireAdmin(srv.users)(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(`{}`))
	req.Host = "ftp.example.com"
	req.Header.Set("Origin", "null")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.SetBasicAuth("admin", "secret")
	rr = httptest.NewRecorder()
	srv.requireAdmin(srv.users)(rr, req)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("same-origin null origin was rejected: %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(`{}`))
	req.Host = "ftp.example.com"
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.SetBasicAuth("admin", "secret")
	rr = httptest.NewRecorder()
	srv.requireAdmin(srv.users)(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-site fetch metadata status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUnsafeAdminAPIAllowsCloudflareForwardedPublicHost(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(`{"username":"cfuser","password":"secret123","home":"/cfuser","permissions":{"list":true}}`))
	req.Host = "macftpd-origin.example.com"
	req.Header.Set("Origin", "https://ftp.example.com")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-Forwarded-Host", "ftp.example.com")
	req.Header.Set("X-Macftpd-Public-Host", "ftp.example.com")
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	srv.requireAdmin(srv.users)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("forwarded public host status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func testServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	root, err := storage.New(dir, "public", "dropboxes", []string{".DS_Store", "._*"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir+"/public", 0o750); err != nil {
		t.Fatal(err)
	}
	store, err := auth.Open(dir + "/users.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BootstrapAdmin("admin", "secret"); err != nil {
		t.Fatal(err)
	}
	links, err := share.Open(dir + "/shares.json")
	if err != nil {
		t.Fatal(err)
	}
	return New(config.HTTPConfig{
		PublicCacheControl: "public, max-age=300",
		SessionKey:         "test",
	}, store, root, cloudflare.New(config.CloudflareConfig{CacheTag: "test-tag"}), activity.New(200), links, nil)
}
