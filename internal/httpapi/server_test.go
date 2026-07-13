package httpapi

import (
	"bytes"
	"encoding/json"
	"html/template"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"macftpd/internal/activity"
	"macftpd/internal/auth"
	"macftpd/internal/cloudflare"
	"macftpd/internal/config"
	"macftpd/internal/share"
	"macftpd/internal/storage"
)

func TestHTTPServerTimeoutsProtectHeadersWithoutCappingStreams(t *testing.T) {
	srv := testServer(t)
	built := srv.newHTTPServer(http.NewServeMux())
	if built.ReadHeaderTimeout != 10*time.Second || built.IdleTimeout != 60*time.Second {
		t.Fatalf("default header/idle timeouts = %s/%s", built.ReadHeaderTimeout, built.IdleTimeout)
	}
	if built.ReadTimeout != 0 || built.WriteTimeout != 0 {
		t.Fatalf("streaming body deadlines must default off, got read=%s write=%s", built.ReadTimeout, built.WriteTimeout)
	}

	srv.cfg.ReadHeaderTimeout = config.Duration(2 * time.Second)
	srv.cfg.ReadTimeout = config.Duration(3 * time.Second)
	srv.cfg.WriteTimeout = config.Duration(4 * time.Second)
	srv.cfg.IdleTimeout = config.Duration(5 * time.Second)
	built = srv.newHTTPServer(http.NewServeMux())
	if built.ReadHeaderTimeout != 2*time.Second || built.ReadTimeout != 3*time.Second || built.WriteTimeout != 4*time.Second || built.IdleTimeout != 5*time.Second {
		t.Fatalf("explicit HTTP timeouts were not preserved: %#v", built)
	}
}

func TestTinyTailProbeDoesNotCountAsCompletedLargeDownload(t *testing.T) {
	const size = int64(10_824_083_788)
	tinyTail := fileServeResult{Status: http.StatusPartialContent, Bytes: 122_704, Size: size, Method: http.MethodGet, Range: "bytes=10823961084-"}
	if tinyTail.RecordableDownload() {
		t.Fatal("tiny media tail probe counted as a completed large download")
	}
	completedResume := fileServeResult{Status: http.StatusPartialContent, Bytes: 168_078_615, Size: size, Method: http.MethodGet, Range: "bytes=10656005173-"}
	if !completedResume.RecordableDownload() {
		t.Fatal("substantial resume through EOF was not counted as a completed download")
	}
}

func TestAdminFilesURLRemainsSafeInTemplateURLContext(t *testing.T) {
	tmpl := template.Must(template.New("url").Funcs(templateFuncs()).Parse(`<a hx-push-url="{{adminFilesURL .Path .Selected}}">open</a>`))
	var rendered strings.Builder
	err := tmpl.Execute(&rendered, map[string]string{
		"Path":     `/public/a" onclick="alert(1)`,
		"Selected": `</a><script>alert(1)</script>`,
	})
	if err != nil {
		t.Fatal(err)
	}
	output := rendered.String()
	if strings.Contains(output, "<script") || strings.Contains(output, "onclick=") || strings.Contains(output, "#ZgotmplZ") {
		t.Fatalf("unsafe admin files URL rendering: %s", output)
	}
	if !strings.Contains(output, "%3Cscript%3E") {
		t.Fatalf("selected path was not URL-encoded: %s", output)
	}
}

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

func TestActivityDashboardSuppressesMonitorAndSeparatesSecurity(t *testing.T) {
	srv := testServer(t)
	srv.activity.Add(activity.Event{Type: "ftp_login", Protocol: "ftp", Actor: "admin", Remote: "127.0.0.1:50000", Action: "login", Path: "/", Detail: "FTP login"})
	srv.activity.Add(activity.Event{Type: "ftp_upload", Protocol: "ftp", Actor: "admin", Remote: "127.0.0.1:50000", Action: "upload", Path: "_monitor/probe.txt", Bytes: 12, Detail: "FTP upload"})
	srv.activity.Add(activity.Event{Type: "ftp_delete", Protocol: "ftp", Actor: "admin", Remote: "127.0.0.1:50000", Action: "delete", Path: "_monitor/probe.txt", Detail: "FTP monitor cleanup removed permanently"})
	srv.activity.Add(activity.Event{Type: "ftp_login", Protocol: "ftp", Actor: "anonymous", Remote: "203.0.113.10:4444", Action: "login", Outcome: "failed", Detail: "bad FTP credentials"})
	srv.activity.Add(activity.Event{Type: "http_login", Protocol: "http", Actor: "admin", Remote: "127.0.0.1:60000", Action: "login", Outcome: "failed", Path: "/admin/", Detail: "admin auth failed"})
	srv.activity.Add(activity.Event{Type: "http_login", Protocol: "http", Actor: "admin", Remote: "127.0.0.1:60001", Action: "login", Outcome: "failed", Path: "/api/activity", Detail: "admin auth failed"})
	srv.activity.Add(activity.Event{Type: "admin_file", Protocol: "http", Actor: "admin", Remote: "127.0.0.1:60000", Action: "download", Path: "/public/readme.txt", Detail: "admin download"})

	req := httptest.NewRequest(http.MethodGet, "/api/activity?limit=20", nil)
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	srv.requireAdmin(srv.activityFeed)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("activity status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Events           []activity.Event `json:"events"`
		ExternalFailures []activity.Event `json:"external_failures"`
		AdminMistakes    []activity.Event `json:"admin_mistakes"`
		Monitor          struct {
			Count int `json:"count"`
			OK    int `json:"ok"`
		} `json:"monitor"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode activity response: %v", err)
	}
	if body.Monitor.Count != 3 || body.Monitor.OK != 3 {
		t.Fatalf("unexpected monitor summary: %#v", body.Monitor)
	}
	for _, event := range body.Events {
		if strings.Contains(event.Path, "_monitor") || strings.Contains(event.Detail, "monitor") || event.Message == "admin login /" || event.Path == "/api/activity" {
			t.Fatalf("monitor event leaked into human feed: %#v", event)
		}
	}
	if len(body.ExternalFailures) != 1 || body.ExternalFailures[0].Remote != "203.0.113.10:4444" {
		t.Fatalf("unexpected external failures: %#v", body.ExternalFailures)
	}
	if len(body.AdminMistakes) != 1 || body.AdminMistakes[0].Path != "/admin/" {
		t.Fatalf("unexpected admin mistakes: %#v", body.AdminMistakes)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/partials/activity", nil)
	req.SetBasicAuth("admin", "secret")
	rr = httptest.NewRecorder()
	srv.requireAdmin(srv.adminActivityPartial)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("partial status = %d body=%s", rr.Code, rr.Body.String())
	}
	rendered := rr.Body.String()
	for _, needle := range []string{"Security and Events", "External Failures", "Admin and User Mistakes", "Monitor Checks", "total 3"} {
		if !strings.Contains(rendered, needle) {
			t.Fatalf("activity partial missing %q: %s", needle, rendered)
		}
	}
	if strings.Contains(rendered, "_monitor/probe.txt") {
		t.Fatalf("activity partial leaked monitor path: %s", rendered)
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

func TestChunkedUploadAssemblesAndVersions(t *testing.T) {
	srv := testServer(t)
	if err := os.WriteFile(srv.root.Base+"/public/movie.mp4", []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	chunks := []struct {
		offset int64
		data   string
	}{
		{0, "hello "},
		{6, "world"},
	}
	for _, chunk := range chunks {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fields := map[string]string{
			"path":       "/public",
			"filename":   "[1997-06-28] Glastonbury.MP4",
			"upload_id":  "upload-test-1234",
			"offset":     strconv.FormatInt(chunk.offset, 10),
			"total_size": "11",
		}
		for k, v := range fields {
			if err := mw.WriteField(k, v); err != nil {
				t.Fatal(err)
			}
		}
		part, err := mw.CreateFormFile("chunk", "[1997-06-28] Glastonbury.MP4")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(chunk.data)); err != nil {
			t.Fatal(err)
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk", &body)
		req.SetBasicAuth("admin", "secret")
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rr := httptest.NewRecorder()
		srv.requireAdmin(srv.uploadChunk)(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("chunk offset %d status = %d body=%s", chunk.offset, rr.Code, rr.Body.String())
		}
	}
	raw, err := os.ReadFile(srv.root.Base + "/public/[1997-06-28] Glastonbury.MP4")
	if err != nil || string(raw) != "hello world" {
		t.Fatalf("assembled payload=%q err=%v", string(raw), err)
	}
	if _, err := os.Stat(srv.root.Base + "/._macftpd_uploads/upload-test-1234.part"); !os.IsNotExist(err) {
		t.Fatalf("part file was not removed, err=%v", err)
	}
}

func TestChunkedUploadRejectsExcessBeforeGrowingPart(t *testing.T) {
	srv := testServer(t)
	send := func(data string) *httptest.ResponseRecorder {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		for key, value := range map[string]string{
			"path":       "/public",
			"filename":   "bounded.bin",
			"upload_id":  "bounded-upload-1234",
			"offset":     "0",
			"total_size": "3",
		} {
			if err := mw.WriteField(key, value); err != nil {
				t.Fatal(err)
			}
		}
		part, err := mw.CreateFormFile("chunk", "bounded.bin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk", &body)
		req.SetBasicAuth("admin", "secret")
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rr := httptest.NewRecorder()
		srv.requireAdmin(srv.uploadChunk)(rr, req)
		return rr
	}

	rr := send("abcdef")
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "chunk exceeds total size") {
		t.Fatalf("oversized chunk status=%d body=%s", rr.Code, rr.Body.String())
	}
	parts, err := os.ReadDir(srv.root.Base + "/._macftpd_uploads")
	if err != nil || len(parts) != 1 {
		t.Fatalf("part directory entries=%d err=%v", len(parts), err)
	}
	info, err := parts[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("oversized part retained %d bytes", info.Size())
	}

	rr = send("abc")
	if rr.Code != http.StatusOK {
		t.Fatalf("valid retry status=%d body=%s", rr.Code, rr.Body.String())
	}
	raw, err := os.ReadFile(srv.root.Base + "/public/bounded.bin")
	if err != nil || string(raw) != "abc" {
		t.Fatalf("bounded upload payload=%q err=%v", raw, err)
	}
}

func TestCleanupUploadPartsRemovesOnlyStaleParts(t *testing.T) {
	dir := t.TempDir()
	oldPart := dir + "/old.part"
	newPart := dir + "/new.part"
	other := dir + "/keep.txt"
	for _, name := range []string{oldPart, newPart, other} {
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldTime := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(oldPart, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	cleanupUploadParts(dir, time.Now().Add(-24*time.Hour))
	if _, err := os.Stat(oldPart); !os.IsNotExist(err) {
		t.Fatalf("stale part still exists: %v", err)
	}
	for _, name := range []string{newPart, other} {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("fresh/non-part file removed: %s: %v", name, err)
		}
	}
}

func TestShareLinkServesBareFileWithStatsAndExpiry(t *testing.T) {
	srv := testServer(t)
	name := "[1997-06-28] Glastonbury.MP4"
	if err := os.WriteFile(srv.root.Base+"/public/"+name, []byte("video"), 0o640); err != nil {
		t.Fatal(err)
	}
	created, err := srv.links.Create(share.CreateRequest{Kind: share.KindDownload, Path: "/public/" + name, CreatedBy: "admin", MaxDownloads: 1})
	if err != nil {
		t.Fatal(err)
	}
	sharePath := "/s/" + created.Link.ID + "/" + created.Token + "/" + url.PathEscape(name)
	req := httptest.NewRequest(http.MethodGet, sharePath, nil)
	req.Header.Set("Referer", "https://example.test/page")
	rr := httptest.NewRecorder()
	srv.shareLink(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "video" {
		t.Fatalf("share status=%d body=%q", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Disposition"); !strings.Contains(got, "inline") || !strings.Contains(got, "filename*=") {
		t.Fatalf("bad disposition %q", got)
	}
	req = httptest.NewRequest(http.MethodGet, sharePath, nil)
	rr = httptest.NewRecorder()
	srv.shareLink(rr, req)
	if rr.Code != http.StatusGone {
		t.Fatalf("one-download link should be gone, got %d", rr.Code)
	}
	stats := srv.activity.StatsForPath("/public/"+name, 10)
	if stats.Downloads != 1 || stats.Referrers["https://example.test/page"] != 1 {
		t.Fatalf("bad stats %#v", stats)
	}
}

func TestShareLinkRangeDownloadHeadersAndAccounting(t *testing.T) {
	srv := testServer(t)
	name := "movie.mkv"
	if err := os.WriteFile(srv.root.Base+"/public/"+name, []byte("0123456789"), 0o640); err != nil {
		t.Fatal(err)
	}
	created, err := srv.links.Create(share.CreateRequest{Kind: share.KindDownload, Path: "/public/" + name, CreatedBy: "admin", MaxDownloads: 1})
	if err != nil {
		t.Fatal(err)
	}
	sharePath := "/s/" + created.Link.ID + "/" + created.Token + "/" + url.PathEscape(name)
	req := httptest.NewRequest(http.MethodGet, sharePath, nil)
	req.Header.Set("Range", "bytes=2-5")
	rr := httptest.NewRecorder()
	srv.shareLink(rr, req)
	if rr.Code != http.StatusPartialContent || rr.Body.String() != "2345" {
		t.Fatalf("range status=%d body=%q", rr.Code, rr.Body.String())
	}
	for _, tc := range []struct {
		header string
		want   string
	}{
		{"Accept-Ranges", "bytes"},
		{"Cloudflare-CDN-Cache-Control", "no-store"},
		{"CDN-Cache-Control", "no-store"},
	} {
		if got := rr.Header().Get(tc.header); got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.header, got, tc.want)
		}
	}
	if got := rr.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") || !strings.Contains(got, "no-transform") {
		t.Fatalf("bad Cache-Control %q", got)
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes 2-5/10" {
		t.Fatalf("bad Content-Range %q", got)
	}
	stats := srv.activity.StatsForPath("/public/"+name, 10)
	if stats.Downloads != 0 || len(stats.Recent) != 0 {
		t.Fatalf("bounded range probe counted as a completed download: %#v", stats)
	}
	events := srv.activity.Recent(10, 0)
	if len(events) == 0 || events[0].Action != "download_probe" || events[0].Bytes != 4 || !strings.Contains(events[0].Detail, "status=206") || !strings.Contains(events[0].Detail, "range=bytes=2-5") {
		t.Fatalf("range probe diagnostic event missing: %#v", events)
	}
	publicLink, err := srv.links.Public(created.Link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if publicLink.DownloadCount != 0 {
		t.Fatalf("bounded probe range consumed download count: %#v", publicLink)
	}

	req = httptest.NewRequest(http.MethodGet, sharePath, nil)
	rr = httptest.NewRecorder()
	srv.shareLink(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "0123456789" {
		t.Fatalf("full download status=%d body=%q", rr.Code, rr.Body.String())
	}
	stats = srv.activity.StatsForPath("/public/"+name, 10)
	if stats.Downloads != 1 || len(stats.Recent) != 1 || stats.Recent[0].Bytes != 10 {
		t.Fatalf("full response was not counted once: %#v", stats)
	}
	req = httptest.NewRequest(http.MethodGet, sharePath, nil)
	rr = httptest.NewRecorder()
	srv.shareLink(rr, req)
	if rr.Code != http.StatusGone {
		t.Fatalf("one-download link should be gone after full response, got %d", rr.Code)
	}
}

func TestShareLinkResumeRangeToEOFConsumesOneDownload(t *testing.T) {
	srv := testServer(t)
	name := "resume.bin"
	if err := os.WriteFile(srv.root.Base+"/public/"+name, []byte("0123456789"), 0o640); err != nil {
		t.Fatal(err)
	}
	created, err := srv.links.Create(share.CreateRequest{Kind: share.KindDownload, Path: "/public/" + name, CreatedBy: "admin", MaxDownloads: 1})
	if err != nil {
		t.Fatal(err)
	}
	sharePath := "/s/" + created.Link.ID + "/" + created.Token + "/" + url.PathEscape(name)
	req := httptest.NewRequest(http.MethodGet, sharePath, nil)
	req.Header.Set("Range", "bytes=5-")
	rr := httptest.NewRecorder()
	srv.shareLink(rr, req)
	if rr.Code != http.StatusPartialContent || rr.Body.String() != "56789" {
		t.Fatalf("resume status=%d body=%q", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, sharePath, nil)
	rr = httptest.NewRecorder()
	srv.shareLink(rr, req)
	if rr.Code != http.StatusGone {
		t.Fatalf("resume-to-eof should consume one-download link, got %d", rr.Code)
	}
}

func TestShareLinkEmptyFileConsumesOneDownload(t *testing.T) {
	srv := testServer(t)
	name := "empty.txt"
	if err := os.WriteFile(srv.root.Base+"/public/"+name, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	created, err := srv.links.Create(share.CreateRequest{Kind: share.KindDownload, Path: "/public/" + name, CreatedBy: "admin", MaxDownloads: 1})
	if err != nil {
		t.Fatal(err)
	}
	sharePath := "/s/" + created.Link.ID + "/" + created.Token + "/" + url.PathEscape(name)
	req := httptest.NewRequest(http.MethodGet, sharePath, nil)
	rr := httptest.NewRecorder()
	srv.shareLink(rr, req)
	if rr.Code != http.StatusOK || rr.Body.Len() != 0 {
		t.Fatalf("empty download status=%d body=%q", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, sharePath, nil)
	rr = httptest.NewRecorder()
	srv.shareLink(rr, req)
	if rr.Code != http.StatusGone {
		t.Fatalf("empty file should consume one-download link, got %d", rr.Code)
	}
}

func TestDropLinkSupportsChunkedUpload(t *testing.T) {
	srv := testServer(t)
	created, err := srv.links.Create(share.CreateRequest{Kind: share.KindUpload, Path: "/public", CreatedBy: "admin", AllowOverwrite: true})
	if err != nil {
		t.Fatal(err)
	}
	chunks := []struct {
		offset int64
		data   string
	}{
		{0, "drop "},
		{5, "payload"},
	}
	for _, chunk := range chunks {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fields := map[string]string{
			"filename":   "upload.zip",
			"upload_id":  "drop-test-1234",
			"offset":     strconv.FormatInt(chunk.offset, 10),
			"total_size": "12",
		}
		for k, v := range fields {
			if err := mw.WriteField(k, v); err != nil {
				t.Fatal(err)
			}
		}
		part, err := mw.CreateFormFile("chunk", "upload.zip")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(chunk.data)); err != nil {
			t.Fatal(err)
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/d/"+created.Link.ID+"/"+created.Token, &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rr := httptest.NewRecorder()
		srv.dropLink(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("chunk offset %d status=%d body=%s", chunk.offset, rr.Code, rr.Body.String())
		}
	}
	raw, err := os.ReadFile(srv.root.Base + "/public/upload.zip")
	if err != nil || string(raw) != "drop payload" {
		t.Fatalf("drop payload=%q err=%v", string(raw), err)
	}
}

func TestPasswordProtectedDropPasswordFormSetsCookie(t *testing.T) {
	srv := testServer(t)
	created, err := srv.links.Create(share.CreateRequest{Kind: share.KindUpload, Path: "/public", CreatedBy: "admin", Password: "correct", AllowOverwrite: true})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/d/"+created.Link.ID+"/"+created.Token, strings.NewReader("password=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.dropLink(rr, req)
	if rr.Code == http.StatusBadRequest || strings.Contains(rr.Body.String(), "bad upload") {
		t.Fatalf("password form was parsed as upload: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Protected drop") {
		t.Fatalf("wrong password status=%d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/d/"+created.Link.ID+"/"+created.Token, strings.NewReader("password=correct"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	rr = httptest.NewRecorder()
	srv.dropLink(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("correct password status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Set-Cookie") == "" {
		t.Fatal("password form did not set share cookie")
	}
}

func TestSharePasswordAttemptsAreRateLimited(t *testing.T) {
	srv := testServer(t)
	if err := os.WriteFile(srv.root.Base+"/public/protected.txt", []byte("secret"), 0o640); err != nil {
		t.Fatal(err)
	}
	created, err := srv.links.Create(share.CreateRequest{Kind: share.KindDownload, Path: "/public/protected.txt", CreatedBy: "admin", Password: "correct"})
	if err != nil {
		t.Fatal(err)
	}
	sharePath := "/s/" + created.Link.ID + "/" + created.Token
	for attempt := 0; attempt < 5; attempt++ {
		req := httptest.NewRequest(http.MethodPost, sharePath, strings.NewReader("password=wrong"))
		req.RemoteAddr = "203.0.113.44:40000"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		srv.shareLink(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Protected share") {
			t.Fatalf("attempt %d status=%d body=%s", attempt+1, rr.Code, rr.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, sharePath, strings.NewReader("password=correct"))
	req.RemoteAddr = "203.0.113.44:40000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.shareLink(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected protected share rate limit, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestProtectedDropRejectsMultipartBeforeAuthorization(t *testing.T) {
	srv := testServer(t)
	created, err := srv.links.Create(share.CreateRequest{Kind: share.KindUpload, Path: "/public", CreatedBy: "admin", Password: "correct"})
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "blocked.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("blocked")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/d/"+created.Link.ID+"/"+created.Token, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	srv.dropLink(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized multipart status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(srv.root.Base + "/public/blocked.txt"); !os.IsNotExist(err) {
		t.Fatalf("unauthorized drop wrote a file: %v", err)
	}
}

func TestSharesAPIListIncludesPersistentURLAndNeverOmittedExpiry(t *testing.T) {
	srv := testServer(t)
	if err := os.WriteFile(srv.root.Base+"/public/keep.txt", []byte("keep"), 0o640); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/shares", strings.NewReader(`{"kind":"download","path":"/public/keep.txt","expires_in":"never"}`))
	req.SetBasicAuth("admin", "secret")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.requireAdmin(srv.sharesAPI)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/shares", nil)
	req.SetBasicAuth("admin", "secret")
	rr = httptest.NewRecorder()
	srv.requireAdmin(srv.sharesAPI)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"url_path":"/s/`) {
		t.Fatalf("share list missing url_path: %s", body)
	}
	if !strings.Contains(body, `"download_count":0`) {
		t.Fatalf("share list missing zero download_count: %s", body)
	}
	if strings.Contains(body, `"expires_at"`) {
		t.Fatalf("never-expiring share exposed zero expiry: %s", body)
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
	if err := os.WriteFile(srv.root.Base+"/public/info.txt", []byte("detail"), 0o640); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/?path=/public&selected=/public/info.txt", nil)
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	srv.requireAdmin(srv.admin)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, needle := range []string{"htmx.min.js", "app.js", "file-workspace", "hx-get=\"/admin/partials/files", "hx-trigger=\"load", "links-panel", "activity-panel"} {
		if !strings.Contains(body, needle) {
			t.Fatalf("admin shell missing %q", needle)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/partials/files?path=/public&selected=/public/info.txt", nil)
	req.SetBasicAuth("admin", "secret")
	rr = httptest.NewRecorder()
	srv.requireAdmin(srv.adminFilesPartial)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("partial status = %d body=%s", rr.Code, rr.Body.String())
	}
	body = rr.Body.String()
	for _, needle := range []string{"file-search", "hx-push-url", "Copy selected", "Move selected", "upload-files", "Inspector"} {
		if !strings.Contains(body, needle) {
			t.Fatalf("admin file partial missing %q", needle)
		}
	}
	if strings.Contains(body, "%252F") {
		t.Fatalf("admin file partial double-encoded history URL: %s", body)
	}
}

func TestAdminPartialsRenderHTMXDashboardSections(t *testing.T) {
	srv := testServer(t)
	for _, tc := range []struct {
		name    string
		target  func(http.ResponseWriter, *http.Request, principal)
		path    string
		needles []string
	}{
		{"users", srv.adminUsersPartial, "/admin/partials/users", []string{"hx-post=\"/admin/partials/users\"", "Save User", "Accounts"}},
		{"links", srv.adminLinksPartial, "/admin/partials/links", []string{"hx-post=\"/admin/partials/links\"", "Create Link", "Shares and Drops"}},
		{"activity", srv.adminActivityPartial, "/admin/partials/activity", []string{"Live Feed"}},
		{"status", srv.adminStatusPartial, "/admin/partials/status", []string{"Health", "Sessions"}},
		{"retention", srv.adminRetentionPartial, "/admin/partials/retention?kind=trash", []string{"Trash and Versions", "Restore"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.SetBasicAuth("admin", "secret")
			rr := httptest.NewRecorder()
			srv.requireAdmin(tc.target)(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
			}
			body := rr.Body.String()
			for _, needle := range tc.needles {
				if !strings.Contains(body, needle) {
					t.Fatalf("partial missing %q: %s", needle, body)
				}
			}
		})
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
