package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	ftpclient "github.com/jlaffaye/ftp"

	"macftpd/internal/activity"
	"macftpd/internal/auth"
	"macftpd/internal/cloudflare"
	"macftpd/internal/config"
	"macftpd/internal/ratelimit"
	"macftpd/internal/share"
	"macftpd/internal/status"
	"macftpd/internal/storage"
)

type Server struct {
	cfg        config.HTTPConfig
	store      *auth.Store
	root       *storage.Root
	cloudflare *cloudflare.Client
	server     *http.Server
	sessionKey []byte
	limiter    *ratelimit.Limiter
	activity   *activity.Store
	links      *share.Store
	tracker    *status.Tracker
}

type principal struct {
	User  auth.User
	Perms auth.PermissionSet
}

type activityMonitorSummary struct {
	Count      int            `json:"count"`
	OK         int            `json:"ok"`
	Failed     int            `json:"failed"`
	Last       activity.Event `json:"last,omitempty"`
	LastOK     activity.Event `json:"last_ok,omitempty"`
	LastFailed activity.Event `json:"last_failed,omitempty"`
}

type activityDashboard struct {
	Events           []activity.Event       `json:"events"`
	Security         []activity.Event       `json:"security"`
	ExternalFailures []activity.Event       `json:"external_failures"`
	AdminMistakes    []activity.Event       `json:"admin_mistakes"`
	Monitor          activityMonitorSummary `json:"monitor"`
}

type userRequest struct {
	Username    string             `json:"username"`
	Password    string             `json:"password"`
	Groups      []string           `json:"groups"`
	Home        string             `json:"home"`
	Disabled    bool               `json:"disabled"`
	Permissions auth.PermissionSet `json:"permissions"`
}

func (r userRequest) user() auth.User {
	groups := make([]string, 0, len(r.Groups))
	for _, group := range r.Groups {
		group = auth.NormalizeName(group)
		if group != "" {
			groups = append(groups, group)
		}
	}
	return auth.User{
		Username:    r.Username,
		Groups:      groups,
		Home:        r.Home,
		Disabled:    r.Disabled,
		Permissions: r.Permissions,
	}
}

func New(cfg config.HTTPConfig, store *auth.Store, root *storage.Root, cf *cloudflare.Client, activityLog *activity.Store, links *share.Store, tracker *status.Tracker) *Server {
	return &Server{cfg: cfg, store: store, root: root, cloudflare: cf, sessionKey: []byte(cfg.SessionKey), limiter: ratelimit.New(5, 10*time.Minute, 5*time.Minute), activity: activityLog, links: links, tracker: tracker}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/public/", s.public)
	mux.HandleFunc("/public-info/", s.publicInfo)
	mux.HandleFunc("/share/", s.shareLink)
	mux.HandleFunc("/s/", s.shareLink)
	mux.HandleFunc("/drop/", s.dropLink)
	mux.HandleFunc("/d/", s.dropLink)
	mux.Handle("/assets/", s.staticAssets())
	mux.HandleFunc("/admin", s.requireAdmin(s.admin))
	mux.HandleFunc("/admin/", s.requireAdmin(s.admin))
	mux.HandleFunc("/admin/partials/files", s.requireAdmin(s.adminFilesPartial))
	mux.HandleFunc("/admin/partials/users", s.requireAdmin(s.adminUsersPartial))
	mux.HandleFunc("/admin/partials/links", s.requireAdmin(s.adminLinksPartial))
	mux.HandleFunc("/admin/partials/activity", s.requireAdmin(s.adminActivityPartial))
	mux.HandleFunc("/admin/partials/status", s.requireAdmin(s.adminStatusPartial))
	mux.HandleFunc("/admin/partials/retention", s.requireAdmin(s.adminRetentionPartial))
	mux.HandleFunc("/api/login", s.login)
	mux.HandleFunc("/api/logout", s.logout)
	mux.HandleFunc("/api/me", s.requireAdmin(s.me))
	mux.HandleFunc("/api/users", s.requireAdmin(s.users))
	mux.HandleFunc("/api/users/", s.requireAdmin(s.user))
	mux.HandleFunc("/api/groups", s.requireAdmin(s.groups))
	mux.HandleFunc("/api/files", s.requireAdmin(s.files))
	mux.HandleFunc("/api/files/action", s.requireAdmin(s.fileAction))
	mux.HandleFunc("/api/download", s.requireAdmin(s.download))
	mux.HandleFunc("/api/upload", s.requireAdmin(s.upload))
	mux.HandleFunc("/api/upload/chunk", s.requireAdmin(s.uploadChunk))
	mux.HandleFunc("/api/fxp", s.requireAdmin(s.fxp))
	mux.HandleFunc("/api/activity", s.requireAdmin(s.activityFeed))
	mux.HandleFunc("/api/status", s.requireAdmin(s.statusAPI))
	mux.HandleFunc("/api/doctor", s.requireAdmin(s.doctorAPI))
	mux.HandleFunc("/api/stats", s.requireAdmin(s.statsAPI))
	mux.HandleFunc("/api/shares", s.requireAdmin(s.sharesAPI))
	mux.HandleFunc("/api/shares/", s.requireAdmin(s.shareAPI))
	mux.HandleFunc("/api/retention", s.requireAdmin(s.retentionAPI))
	mux.HandleFunc("/api/retention/restore", s.requireAdmin(s.restoreAPI))
	mux.HandleFunc("/api/cloudflare/purge", s.requireAdmin(s.purgeCloudflare))
	s.server = &http.Server{
		Addr:         s.cfg.Listen,
		Handler:      securityHeaders(mux),
		ReadTimeout:  s.cfg.ReadTimeout.Std(10 * time.Second),
		WriteTimeout: s.cfg.WriteTimeout.Std(60 * time.Second),
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()
	log.Printf("http listening on %s", s.cfg.Listen)
	err := s.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Addr() string {
	if s.server == nil {
		return s.cfg.Listen
	}
	return s.server.Addr
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "macftpd", "time": time.Now().UTC()})
}

func (s *Server) public(w http.ResponseWriter, r *http.Request) {
	realPath, virtual, err := s.publicPath(r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	info, err := s.root.Stat(realPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if info.IsDir() {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, (&url.URL{Path: r.URL.Path + "/", RawQuery: r.URL.RawQuery}).String(), http.StatusMovedPermanently)
			return
		}
		s.publicDirectory(w, r, realPath, virtual)
		return
	}
	s.setPublicCacheHeaders(w)
	s.logActivity(activity.Event{Type: "public_download", Protocol: "http", Actor: "public", Remote: remoteAddr(r), Referrer: r.Referer(), Action: "download", Path: virtual, Bytes: info.Size(), Detail: "public HTTP download"})
	s.serveStorageFile(w, r, realPath, info.Name())
}

func (s *Server) publicInfo(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/public-info/")
	realPath, virtual, err := s.publicPath("/public/" + rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	info, err := s.root.Stat(realPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	href := "/public/" + strings.TrimPrefix(strings.TrimPrefix(virtual, "/"+s.root.PublicDir), "/")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60, stale-while-revalidate=30")
	_ = fileInfoTemplate.Execute(w, map[string]any{
		"Title":   info.Name(),
		"Name":    info.Name(),
		"Path":    virtual,
		"Href":    href,
		"Size":    humanSize(info.Size(), info.IsDir()),
		"Type":    map[bool]string{true: "Folder", false: "File"}[info.IsDir()],
		"ModTime": info.ModTime().Format(time.RFC1123),
	})
}

func (s *Server) shareLink(w http.ResponseWriter, r *http.Request) {
	prefix := "/share/"
	if strings.HasPrefix(r.URL.Path, "/s/") {
		prefix = "/s/"
	}
	id, token, ok := linkParts(r.URL.Path, prefix)
	if !ok {
		http.NotFound(w, r)
		return
	}
	meta, err := s.links.Public(id)
	if err != nil || meta.Kind != share.KindDownload {
		http.NotFound(w, r)
		return
	}
	password := ""
	if r.Method == http.MethodPost {
		password = r.FormValue("password")
	} else if meta.HasPassword && s.verifyShareCookie(r, id, token) {
		password = "__cookie__"
	}
	if meta.HasPassword && password == "__cookie__" {
		meta, err = s.links.VerifyAuthorized(id, token)
	} else {
		meta, err = s.links.Verify(id, token, password)
	}
	if err != nil {
		if meta.HasPassword || errors.Is(err, share.ErrDenied) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = passwordTemplate.Execute(w, map[string]any{"Title": "Protected share"})
			return
		}
		http.Error(w, "share unavailable", http.StatusGone)
		return
	}
	if meta.HasPassword && r.Method == http.MethodPost {
		s.setShareCookie(w, r, id, token)
		redirectSamePath(w, r)
		return
	}
	realPath, clean, err := s.root.ResolveAdmin(meta.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	info, err := s.root.Stat(realPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !info.IsDir() {
		_ = s.links.RecordDownload(id)
		s.logActivity(activity.Event{Type: "share_download", Protocol: "http", Actor: "share-link", Remote: remoteAddr(r), Referrer: r.Referer(), Action: "download", Path: clean, Bytes: info.Size(), Detail: "public share download"})
		setFileDisposition(w, r, info.Name())
		s.serveStorageFile(w, r, realPath, info.Name())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = fileInfoTemplate.Execute(w, map[string]any{
		"Title":   "Shared " + info.Name(),
		"Name":    info.Name(),
		"Path":    clean,
		"Href":    r.URL.Path + "?download=1",
		"Size":    humanSize(info.Size(), info.IsDir()),
		"Type":    map[bool]string{true: "Folder", false: "File"}[info.IsDir()],
		"ModTime": info.ModTime().Format(time.RFC1123),
	})
}

func (s *Server) dropLink(w http.ResponseWriter, r *http.Request) {
	prefix := "/drop/"
	if strings.HasPrefix(r.URL.Path, "/d/") {
		prefix = "/d/"
	}
	id, token, ok := linkParts(r.URL.Path, prefix)
	if !ok {
		http.NotFound(w, r)
		return
	}
	meta, err := s.links.Public(id)
	if err != nil || meta.Kind != share.KindUpload {
		http.Error(w, "drop link unavailable", http.StatusGone)
		return
	}
	if r.Method == http.MethodGet {
		if meta.HasPassword && !s.verifyShareCookie(r, id, token) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = passwordTemplate.Execute(w, map[string]any{"Title": "Protected drop"})
			return
		}
		if meta.HasPassword {
			meta, err = s.links.VerifyAuthorized(id, token)
		} else {
			meta, err = s.links.Verify(id, token, "")
		}
		if err != nil {
			http.Error(w, "drop link unavailable", http.StatusGone)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = dropTemplate.Execute(w, map[string]any{"Path": meta.Path, "HasPassword": meta.HasPassword})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if meta.HasPassword && !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/") {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad password form", http.StatusBadRequest)
			return
		}
		if _, err := s.links.Verify(id, token, r.FormValue("password")); err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = passwordTemplate.Execute(w, map[string]any{"Title": "Protected drop"})
			return
		}
		s.setShareCookie(w, r, id, token)
		redirectSamePath(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 20<<30)
	// #nosec G120 -- MaxBytesReader caps the request; multipart spools file parts above maxMemory.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}
	if meta.HasPassword && s.verifyShareCookie(r, id, token) {
		meta, err = s.links.VerifyAuthorized(id, token)
	} else {
		meta, err = s.links.Verify(id, token, r.FormValue("password"))
	}
	if err != nil || meta.Kind != share.KindUpload {
		if meta.HasPassword && r.FormValue("password") != "" && r.FormValue("upload_id") == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = passwordTemplate.Execute(w, map[string]any{"Title": "Protected drop"})
			return
		}
		http.Error(w, "drop link unavailable", http.StatusGone)
		return
	}
	if r.FormValue("upload_id") != "" {
		s.dropChunk(w, r, meta)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()
	name := filepath.Base(header.Filename)
	if name == "" || name == "." || name == string(os.PathSeparator) {
		http.Error(w, "bad filename", http.StatusBadRequest)
		return
	}
	destVirtual := path.Join(meta.Path, name)
	dest, _, err := s.root.ResolveAdmin(destVirtual)
	if err != nil {
		http.Error(w, "bad destination", http.StatusBadRequest)
		return
	}
	if !meta.AllowOverwrite {
		if _, err := s.root.Stat(dest); err == nil {
			http.Error(w, "destination exists", http.StatusConflict)
			return
		}
	} else if info, err := s.root.Stat(dest); err == nil && !info.IsDir() {
		_, _ = s.root.Version(dest, destVirtual, "drop-link")
	}
	if err := s.root.MkdirAllParent(dest, 0o750); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out, err := s.root.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n, err := io.Copy(out, file)
	_ = out.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.logActivity(activity.Event{Type: "public_drop", Protocol: "http", Actor: "drop-link", Remote: remoteAddr(r), Action: "upload", Path: destVirtual, Bytes: n, Detail: "public drop link upload"})
	writeJSON(w, http.StatusOK, dropUploadResponse(s.root, destVirtual, n, true))
}

func (s *Server) dropChunk(w http.ResponseWriter, r *http.Request, meta share.PublicLink) {
	filename := filepath.Base(r.FormValue("filename"))
	if filename == "" || filename == "." || filename == string(os.PathSeparator) {
		writeJSON(w, http.StatusBadRequest, errorBody("bad filename"))
		return
	}
	uploadID := r.FormValue("upload_id")
	if !safeUploadID(uploadID) {
		writeJSON(w, http.StatusBadRequest, errorBody("bad upload id"))
		return
	}
	offset, err := strconv.ParseInt(r.FormValue("offset"), 10, 64)
	if err != nil || offset < 0 {
		writeJSON(w, http.StatusBadRequest, errorBody("bad offset"))
		return
	}
	total, err := strconv.ParseInt(r.FormValue("total_size"), 10, 64)
	if err != nil || total < 0 || offset > total {
		writeJSON(w, http.StatusBadRequest, errorBody("bad total size"))
		return
	}
	chunk, _, err := r.FormFile("chunk")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("chunk is required"))
		return
	}
	defer chunk.Close()
	destVirtual := path.Join(meta.Path, filename)
	dest, _, err := s.root.ResolveAdmin(destVirtual)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad destination"))
		return
	}
	tmpDir := filepath.Join(s.root.Base, "._macftpd_uploads")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	partPath := filepath.Join(tmpDir, "drop-"+uploadID+".part")
	partPath = filepath.Clean(partPath)
	if !strings.HasPrefix(partPath, tmpDir+string(os.PathSeparator)) {
		writeJSON(w, http.StatusBadRequest, errorBody("bad upload id"))
		return
	}
	if offset == 0 {
		_ = os.Remove(partPath)
	}
	part, err := os.OpenFile(partPath, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- uploadID is constrained to a safe basename above.
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	defer part.Close()
	info, err := part.Stat()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	if info.Size() != offset {
		writeJSON(w, http.StatusConflict, errorBody(fmt.Sprintf("offset mismatch: have %d bytes", info.Size())))
		return
	}
	if _, err := part.Seek(offset, io.SeekStart); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	n, err := io.Copy(part, chunk)
	if err != nil {
		s.logActivity(activity.Event{Type: "public_drop", Protocol: "http", Actor: "drop-link", Remote: remoteAddr(r), Action: "upload", Outcome: "failed", Path: destVirtual, Bytes: offset + n, Detail: err.Error()})
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	written := offset + n
	if written > total {
		writeJSON(w, http.StatusBadRequest, errorBody("chunk exceeds total size"))
		return
	}
	if written < total {
		writeJSON(w, http.StatusOK, dropUploadResponse(s.root, destVirtual, written, false))
		return
	}
	if err := part.Close(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	if !meta.AllowOverwrite {
		if _, err := s.root.Stat(dest); err == nil {
			writeJSON(w, http.StatusConflict, errorBody("destination exists"))
			return
		}
	} else if info, err := s.root.Stat(dest); err == nil && !info.IsDir() {
		_, _ = s.root.Version(dest, destVirtual, "drop-link")
	}
	if err := s.root.MkdirAllParent(dest, 0o750); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	if err := s.root.Rename(partPath, dest); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	if err := s.root.Chmod(dest, 0o640); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	s.logActivity(activity.Event{Type: "public_drop", Protocol: "http", Actor: "drop-link", Remote: remoteAddr(r), Action: "upload", Path: destVirtual, Bytes: written, Detail: "public drop link chunked upload"})
	writeJSON(w, http.StatusOK, dropUploadResponse(s.root, destVirtual, written, true))
}

func dropUploadResponse(root *storage.Root, virtual string, received int64, complete bool) map[string]any {
	body := map[string]any{"path": virtual, "received": received, "complete": complete}
	if complete {
		if publicURL := publicURLForShare(root, virtual); publicURL != "" {
			body["public_url"] = publicURL
		}
	}
	return body
}

func (s *Server) publicPath(urlPath string) (string, string, error) {
	rel := strings.TrimPrefix(urlPath, "/public/")
	virtual := path.Clean("/" + s.root.PublicDir + "/" + rel)
	publicRoot := path.Clean("/" + s.root.PublicDir)
	if virtual != publicRoot && !strings.HasPrefix(virtual, publicRoot+"/") {
		return "", "", storage.ErrOutsideRoot
	}
	return s.root.ResolveAdmin(virtual)
}

func (s *Server) setPublicCacheHeaders(w http.ResponseWriter) {
	cache := s.cfg.PublicCacheControl
	if cache == "" {
		cache = "public, max-age=300, stale-while-revalidate=60"
	}
	w.Header().Set("Cache-Control", cache)
	w.Header().Set("CDN-Cache-Control", cache)
	w.Header().Set("Cloudflare-CDN-Cache-Control", cache)
	s.cloudflare.AddCacheHeaders(w)
}

func (s *Server) publicDirectory(w http.ResponseWriter, r *http.Request, realPath, virtual string) {
	entries, err := s.root.List(realPath, virtual)
	if err != nil {
		http.Error(w, "directory unavailable", http.StatusInternalServerError)
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	publicRoot := "/" + s.root.PublicDir
	displayPath := strings.TrimPrefix(virtual, publicRoot)
	if displayPath == "" {
		displayPath = "/"
	}
	rows := make([]publicEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name, ".") {
			continue
		}
		href := path.Join("/public", strings.TrimPrefix(entry.Path, publicRoot))
		if entry.IsDir {
			href += "/"
		}
		infoHref := path.Join("/public-info", strings.TrimPrefix(entry.Path, publicRoot))
		rows = append(rows, publicEntry{
			Name:     entry.Name,
			Href:     href,
			InfoHref: infoHref,
			Size:     entry.Size,
			SizeText: humanSize(entry.Size, entry.IsDir),
			IsDir:    entry.IsDir,
			ModTime:  entry.ModTime,
			ModText:  entry.ModTime.Format("2006-01-02 15:04"),
		})
	}
	parent := ""
	if virtual != publicRoot {
		parentVirtual := path.Dir(virtual)
		parent = path.Join("/public", strings.TrimPrefix(parentVirtual, publicRoot)) + "/"
	}
	w.Header().Set("Cache-Control", "public, max-age=60, stale-while-revalidate=30")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = publicListingTemplate.Execute(w, map[string]any{
		"Path":    displayPath,
		"Rows":    rows,
		"Parent":  parent,
		"Updated": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request, p principal) {
	if _, _, ok := r.BasicAuth(); ok {
		s.setSession(w, r, p.User.Username)
		s.logActivity(activity.Event{Type: "http_login", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "login", Outcome: "ok", Detail: "admin Basic auth login"})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	initialPath := r.URL.Query().Get("path")
	if initialPath == "" {
		initialPath = "/"
	}
	selected := r.URL.Query().Get("selected")
	_ = adminTemplate.Execute(w, map[string]any{
		"Username":    p.User.Username,
		"InitialPath": initialPath,
		"Selected":    selected,
	})
}

func (s *Server) adminFilesPartial(w http.ResponseWriter, r *http.Request, _ principal) {
	if r.Method != http.MethodGet {
		writeHTML(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	requested := r.URL.Query().Get("path")
	if requested == "" {
		requested = "/"
	}
	selected := r.URL.Query().Get("selected")
	realPath, clean, err := s.root.ResolveAdmin(requested)
	if err != nil {
		writeHTML(w, http.StatusBadRequest, "bad path")
		return
	}
	info, err := s.root.Stat(realPath)
	if err != nil {
		writeHTML(w, http.StatusNotFound, "path not found")
		return
	}
	if !info.IsDir() {
		selected = clean
		clean = parentVirtual(clean)
		realPath, _, err = s.root.ResolveAdmin(clean)
		if err != nil {
			writeHTML(w, http.StatusBadRequest, "bad path")
			return
		}
	}
	entries, err := s.root.List(realPath, clean)
	if err != nil {
		writeHTML(w, http.StatusInternalServerError, err.Error())
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	var selectedEntry *storage.Entry
	if selected != "" {
		if realSelected, cleanSelected, err := s.root.ResolveAdmin(selected); err == nil {
			if selectedInfo, err := s.root.Stat(realSelected); err == nil {
				entry := storage.Entry{
					Name:    selectedInfo.Name(),
					Path:    cleanSelected,
					Size:    selectedInfo.Size(),
					Mode:    selectedInfo.Mode().String(),
					IsDir:   selectedInfo.IsDir(),
					ModTime: selectedInfo.ModTime(),
				}
				selectedEntry = &entry
				selected = cleanSelected
			}
		}
	}
	data := adminFileView{
		Path:        clean,
		Parent:      parentVirtual(clean),
		Entries:     entries,
		Selected:    selectedEntry,
		Breadcrumbs: breadcrumbs(clean),
		PublicDir:   "/" + s.root.PublicDir,
		DropboxDir:  "/" + s.root.DropboxDir,
	}
	if selectedEntry != nil {
		data.SelectedStats = s.activity.StatsForPath(selectedEntry.Path, 8)
		data.PublicURL = publicURLForShare(s.root, selectedEntry.Path)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = filesPartialTemplate.Execute(w, data)
}

func (s *Server) adminUsersPartial(w http.ResponseWriter, r *http.Request, p principal) {
	data := adminUsersView{Users: s.store.ListUsers()}
	editName := r.URL.Query().Get("edit")
	if editName != "" {
		if user, _, ok := s.store.Permissions(editName); ok {
			data.Edit = sanitizeUser(user)
		}
	}
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			data.Error = "bad form"
			break
		}
		user := auth.User{
			Username:    r.FormValue("username"),
			Groups:      splitCSV(r.FormValue("groups")),
			Home:        r.FormValue("home"),
			Disabled:    r.FormValue("disabled") == "on",
			Permissions: permissionSetFromForm(r),
		}
		if err := s.store.UpsertUser(user, r.FormValue("password")); err != nil {
			data.Error = err.Error()
			break
		}
		user, _, _ = s.store.Permissions(user.Username)
		_ = s.root.EnsureUserHome(user)
		s.logActivity(activity.Event{Type: "admin_user", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "saved user", Path: user.Username, Detail: "user created or updated"})
		data.Users = s.store.ListUsers()
		data.Edit = sanitizeUser(user)
		data.Status = "Saved " + user.Username
	case http.MethodDelete:
		username := r.URL.Query().Get("username")
		if username == "" {
			data.Error = "username is required"
			break
		}
		if err := s.store.DeleteUser(username); err != nil {
			data.Error = err.Error()
			break
		}
		s.logActivity(activity.Event{Type: "admin_user", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "deleted user", Path: username, Detail: "user deleted"})
		data.Users = s.store.ListUsers()
		data.Status = "Deleted " + username
	default:
		writeHTML(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = usersPartialTemplate.Execute(w, data)
}

func (s *Server) adminLinksPartial(w http.ResponseWriter, r *http.Request, p principal) {
	data := adminLinksView{Links: s.links.List()}
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			data.Error = "bad form"
			break
		}
		created, url, err := s.createPublicLinkFromForm(r, p)
		if err != nil {
			data.Error = err.Error()
			break
		}
		data.Links = s.links.List()
		data.CreatedURL = url
		data.Status = "Created " + string(created.Link.Kind) + " link"
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			data.Error = "id is required"
			break
		}
		if err := s.links.Delete(id); err != nil {
			data.Error = err.Error()
			break
		}
		s.logActivity(activity.Event{Type: "admin_share", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "delete", Path: id, Detail: "deleted public link"})
		data.Links = s.links.List()
		data.Status = "Revoked " + id
	default:
		writeHTML(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	data.Now = time.Now()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = linksPartialTemplate.Execute(w, data)
}

func (s *Server) adminActivityPartial(w http.ResponseWriter, r *http.Request, _ principal) {
	if r.Method != http.MethodGet {
		writeHTML(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 80
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = activityPartialTemplate.Execute(w, s.activityDashboard(limit, 0))
}

func (s *Server) adminStatusPartial(w http.ResponseWriter, r *http.Request, _ principal) {
	if r.Method != http.MethodGet {
		writeHTML(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	sessions := []status.Session{}
	if s.tracker != nil {
		sessions = s.tracker.Snapshot()
	}
	checks := s.doctorChecks()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = statusPartialTemplate.Execute(w, map[string]any{"Sessions": sessions, "Checks": checks, "Time": time.Now().UTC()})
}

func (s *Server) adminRetentionPartial(w http.ResponseWriter, r *http.Request, p principal) {
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "trash"
	}
	data := adminRetentionView{Kind: kind}
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			data.Error = "bad form"
			break
		}
		dest, err := s.root.Restore(kind, r.FormValue("id"), r.FormValue("dest_path"), r.FormValue("overwrite") == "on")
		if err != nil {
			data.Error = err.Error()
			break
		}
		s.logActivity(activity.Event{Type: "admin_retention", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "restore", Path: dest, Detail: "restored retained file"})
		data.Status = "Restored " + dest
	default:
		writeHTML(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	items, err := s.root.ListRetained(kind)
	if err != nil {
		data.Error = err.Error()
	} else {
		data.Items = items
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = retentionPartialTemplate.Execute(w, data)
}

func (s *Server) createPublicLinkFromForm(r *http.Request, p principal) (share.Created, string, error) {
	kind := r.FormValue("kind")
	if kind == "" {
		kind = string(share.KindDownload)
	}
	realPath, clean, err := s.root.ResolveAdmin(r.FormValue("path"))
	if err != nil {
		return share.Created{}, "", errors.New("bad path")
	}
	if kind == string(share.KindDownload) {
		if _, err := s.root.Stat(realPath); err != nil {
			return share.Created{}, "", errors.New("path not found")
		}
	} else if err := s.root.MkdirAll(realPath, 0o750); err != nil {
		return share.Created{}, "", err
	}
	maxDownloads, _ := strconv.Atoi(r.FormValue("max_downloads"))
	var expires time.Time
	switch r.FormValue("expires_in") {
	case "1download":
		maxDownloads = 1
	case "", "never":
	default:
		d, err := time.ParseDuration(r.FormValue("expires_in"))
		if err != nil {
			return share.Created{}, "", errors.New("bad expiry")
		}
		expires = time.Now().Add(d)
	}
	created, err := s.links.Create(share.CreateRequest{
		Kind:           share.Kind(kind),
		Path:           clean,
		Label:          r.FormValue("label"),
		CreatedBy:      p.User.Username,
		ExpiresAt:      expires,
		MaxDownloads:   maxDownloads,
		Password:       r.FormValue("password"),
		AllowOverwrite: r.FormValue("allow_overwrite") == "on",
	})
	if err != nil {
		return share.Created{}, "", err
	}
	prefix := "/s/"
	if created.Link.Kind == share.KindUpload {
		prefix = "/d/"
	}
	urlPath := prefix + created.Link.ID + "/" + created.Token
	if created.Link.Kind == share.KindDownload {
		if info, err := s.root.Stat(realPath); err == nil && !info.IsDir() {
			urlPath += "/" + info.Name()
		}
	}
	created.Link.URLPath = urlPath
	_ = s.links.SetURLPath(created.Link.ID, urlPath)
	s.logActivity(activity.Event{Type: "admin_share", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "create " + string(created.Link.Kind), Path: clean, Detail: "created public link"})
	return created, absoluteURL(r, urlPath), nil
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	if !sameOriginUnsafe(r) {
		writeJSON(w, http.StatusForbidden, errorBody("cross-origin login denied"))
		return
	}
	var req struct {
		Username       string `json:"username"`
		Password       string `json:"password"`
		TurnstileToken string `json:"turnstile_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad json"))
		return
	}
	if err := s.verifyTurnstile(r, req.TurnstileToken); err != nil {
		s.logActivity(activity.Event{Type: "http_login", Protocol: "http", Actor: auth.NormalizeName(req.Username), Remote: remoteAddr(r), Action: "login", Outcome: "denied", Detail: err.Error()})
		writeJSON(w, http.StatusForbidden, errorBody("turnstile verification failed"))
		return
	}
	limitKey := loginLimitKey(r, req.Username)
	if !s.limiter.Allow(limitKey) {
		s.logActivity(activity.Event{Type: "http_login", Protocol: "http", Actor: auth.NormalizeName(req.Username), Remote: remoteAddr(r), Action: "login", Outcome: "limited", Detail: "too many failed admin login attempts"})
		writeJSON(w, http.StatusTooManyRequests, errorBody("too many failed login attempts; try again later"))
		return
	}
	user, perms, ok := s.store.Authenticate(req.Username, req.Password)
	if !ok || !perms.Admin {
		s.limiter.Fail(limitKey)
		s.logActivity(activity.Event{Type: "http_login", Protocol: "http", Actor: auth.NormalizeName(req.Username), Remote: remoteAddr(r), Action: "login", Outcome: "failed", Detail: "bad admin credentials"})
		writeJSON(w, http.StatusUnauthorized, errorBody("bad credentials"))
		return
	}
	s.limiter.Reset(limitKey)
	s.setSession(w, r, user.Username)
	s.logActivity(activity.Event{Type: "http_login", Protocol: "http", Actor: user.Username, Remote: remoteAddr(r), Action: "login", Outcome: "ok", Detail: "admin login"})
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !sameOriginUnsafe(r) {
		writeJSON(w, http.StatusForbidden, errorBody("cross-origin logout denied"))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "macftpd_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	s.logActivity(activity.Event{Type: "http_logout", Protocol: "http", Remote: remoteAddr(r), Action: "logout", Detail: "admin logout"})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, _ *http.Request, p principal) {
	writeJSON(w, http.StatusOK, map[string]any{"user": sanitizeUser(p.User), "permissions": p.Perms})
}

func (s *Server) users(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"users": s.store.ListUsers()})
	case http.MethodPost:
		var req userRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody("bad json"))
			return
		}
		user := req.user()
		if err := s.store.UpsertUser(user, req.Password); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
			return
		}
		user, _, _ = s.store.Permissions(user.Username)
		_ = s.root.EnsureUserHome(user)
		s.logActivity(activity.Event{Type: "admin_user", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "saved user", Path: user.Username, Detail: "user created or updated"})
		writeJSON(w, http.StatusOK, map[string]any{"user": sanitizeUser(user)})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
	}
}

func (s *Server) user(w http.ResponseWriter, r *http.Request, p principal) {
	username := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	if username == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("username is required"))
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req userRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody("bad json"))
			return
		}
		req.Username = username
		user := req.user()
		if err := s.store.UpsertUser(user, req.Password); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
			return
		}
		user, _, _ = s.store.Permissions(username)
		_ = s.root.EnsureUserHome(user)
		s.logActivity(activity.Event{Type: "admin_user", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "saved user", Path: username, Detail: "user updated"})
		writeJSON(w, http.StatusOK, map[string]any{"user": sanitizeUser(user)})
	case http.MethodDelete:
		if err := s.store.DeleteUser(username); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
			return
		}
		s.logActivity(activity.Event{Type: "admin_user", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "deleted user", Path: username, Detail: "user deleted"})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
	}
}

func (s *Server) groups(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"groups": s.store.ListGroups()})
	case http.MethodPost:
		var req auth.Group
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody("bad json"))
			return
		}
		if err := s.store.UpsertGroup(req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
			return
		}
		s.logActivity(activity.Event{Type: "admin_group", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "saved group", Path: req.Name, Detail: "group created or updated"})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
	}
}

func (s *Server) files(w http.ResponseWriter, r *http.Request, p principal) {
	virtual := r.URL.Query().Get("path")
	realPath, clean, err := s.root.ResolveAdmin(virtual)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad path"))
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if clean == "/" {
			writeJSON(w, http.StatusBadRequest, errorBody("refusing to delete storage root"))
			return
		}
		if _, err := s.root.Trash(realPath, clean, p.User.Username); err != nil {
			s.logActivity(activity.Event{Type: "admin_file", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "delete", Outcome: "failed", Path: clean, Detail: err.Error()})
			writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
			return
		}
		s.logActivity(activity.Event{Type: "admin_file", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "delete", Path: clean, Detail: "admin moved file or folder to trash"})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	case http.MethodPatch:
		if clean == "/" {
			writeJSON(w, http.StatusBadRequest, errorBody("refusing to rename storage root"))
			return
		}
		var req struct {
			DestPath string `json:"dest_path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody("bad json"))
			return
		}
		destReal, destClean, err := s.root.ResolveAdmin(req.DestPath)
		if err != nil || destClean == "/" {
			writeJSON(w, http.StatusBadRequest, errorBody("bad destination"))
			return
		}
		if err := s.root.MkdirAllParent(destReal, 0o750); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
			return
		}
		if info, err := s.root.Stat(destReal); err == nil && !info.IsDir() {
			_, _ = s.root.Version(destReal, destClean, p.User.Username)
		}
		if err := s.root.Rename(realPath, destReal); err != nil {
			s.logActivity(activity.Event{Type: "admin_file", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "move", Outcome: "failed", Path: clean, DestPath: destClean, Detail: err.Error()})
			writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
			return
		}
		info, err := s.root.Stat(destReal)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
			return
		}
		s.logActivity(activity.Event{Type: "admin_file", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "move", Path: clean, DestPath: destClean, Detail: "admin renamed or moved file"})
		writeJSON(w, http.StatusOK, map[string]any{"entry": storageEntry(info, destClean)})
		return
	case http.MethodPost:
		if err := s.root.MkdirAll(realPath, 0o750); err != nil {
			s.logActivity(activity.Event{Type: "admin_file", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "mkdir", Outcome: "failed", Path: clean, Detail: err.Error()})
			writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
			return
		}
		s.logActivity(activity.Event{Type: "admin_file", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "mkdir", Path: clean, Detail: "admin created folder"})
		writeJSON(w, http.StatusOK, map[string]any{"path": clean})
		return
	case http.MethodGet:
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	info, err := s.root.Stat(realPath)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorBody("not found"))
		return
	}
	if !info.IsDir() {
		writeJSON(w, http.StatusOK, map[string]any{"entry": storageEntry(info, clean)})
		return
	}
	entries, err := s.root.List(realPath, clean)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": clean, "entries": entries})
}

func (s *Server) fileAction(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	var req struct {
		Operation   string   `json:"operation"`
		Paths       []string `json:"paths"`
		DestPath    string   `json:"dest_path"`
		Deduplicate bool     `json:"deduplicate"`
		Overwrite   bool     `json:"overwrite"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad json"))
		return
	}
	req.Operation = strings.ToLower(strings.TrimSpace(req.Operation))
	if req.Operation != "copy" && req.Operation != "move" {
		writeJSON(w, http.StatusBadRequest, errorBody("operation must be copy or move"))
		return
	}
	if len(req.Paths) == 0 || len(req.Paths) > 100 {
		writeJSON(w, http.StatusBadRequest, errorBody("paths must contain 1-100 items"))
		return
	}
	destReal, destClean, err := s.root.ResolveAdmin(req.DestPath)
	if err != nil || destClean == "/" {
		writeJSON(w, http.StatusBadRequest, errorBody("bad destination"))
		return
	}
	if len(req.Paths) > 1 {
		if err := s.root.MkdirAll(destReal, 0o750); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
			return
		}
	}
	type resultItem struct {
		Path      string `json:"path"`
		DestPath  string `json:"dest_path"`
		Files     int    `json:"files,omitempty"`
		Bytes     int64  `json:"bytes,omitempty"`
		Strategy  string `json:"strategy,omitempty"`
		Operation string `json:"operation"`
	}
	items := make([]resultItem, 0, len(req.Paths))
	var totalFiles int
	var totalBytes int64
	for _, srcVirtual := range req.Paths {
		srcReal, srcClean, err := s.root.ResolveAdmin(srcVirtual)
		if err != nil || srcClean == "/" {
			writeJSON(w, http.StatusBadRequest, errorBody("bad source path"))
			return
		}
		targetReal, targetClean, err := s.actionTarget(srcClean, destClean, len(req.Paths) > 1)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
			return
		}
		if targetClean == srcClean || strings.HasPrefix(targetClean, srcClean+"/") {
			writeJSON(w, http.StatusBadRequest, errorBody("destination cannot be inside source"))
			return
		}
		if req.Operation == "move" {
			if !req.Overwrite {
				if _, err := s.root.Stat(targetReal); err == nil {
					writeJSON(w, http.StatusBadRequest, errorBody("destination exists"))
					return
				}
			}
			if err := s.root.MkdirAllParent(targetReal, 0o750); err != nil {
				writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
				return
			}
			if req.Overwrite {
				if info, err := s.root.Stat(targetReal); err == nil && !info.IsDir() {
					_, _ = s.root.Version(targetReal, targetClean, p.User.Username)
				}
			}
			if err := s.root.Rename(srcReal, targetReal); err != nil {
				s.logActivity(activity.Event{Type: "admin_file", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "move", Outcome: "failed", Path: srcClean, DestPath: targetClean, Detail: err.Error()})
				writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
				return
			}
			items = append(items, resultItem{Path: srcClean, DestPath: targetClean, Operation: "move"})
			s.logActivity(activity.Event{Type: "admin_file", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "move", Path: srcClean, DestPath: targetClean, Detail: "admin moved file or folder"})
			continue
		}
		if req.Overwrite {
			if info, err := s.root.Stat(targetReal); err == nil && !info.IsDir() {
				_, _ = s.root.Version(targetReal, targetClean, p.User.Username)
			}
		}
		result, err := s.root.Copy(srcReal, targetReal, storage.CopyOptions{Deduplicate: req.Deduplicate, Overwrite: req.Overwrite})
		if err != nil {
			s.logActivity(activity.Event{Type: "admin_file", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "copy", Outcome: "failed", Path: srcClean, DestPath: targetClean, Detail: err.Error()})
			writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
			return
		}
		totalFiles += result.Files
		totalBytes += result.Bytes
		items = append(items, resultItem{Path: srcClean, DestPath: targetClean, Files: result.Files, Bytes: result.Bytes, Strategy: result.Strategy, Operation: "copy"})
		s.logActivity(activity.Event{Type: "admin_file", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "copy", Path: srcClean, DestPath: targetClean, Bytes: result.Bytes, Detail: "admin copied file or folder using " + result.Strategy})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "operation": req.Operation, "items": items, "files": totalFiles, "bytes": totalBytes})
}

func (s *Server) actionTarget(srcClean, destClean string, multi bool) (string, string, error) {
	srcName := path.Base(srcClean)
	if srcName == "/" || srcName == "." {
		return "", "", errors.New("bad source path")
	}
	destReal, _, err := s.root.ResolveAdmin(destClean)
	if err != nil {
		return "", "", err
	}
	if multi {
		targetClean := path.Join(destClean, srcName)
		targetReal, _, err := s.root.ResolveAdmin(targetClean)
		return targetReal, targetClean, err
	}
	if info, err := s.root.Stat(destReal); err == nil && info.IsDir() {
		targetClean := path.Join(destClean, srcName)
		targetReal, _, err := s.root.ResolveAdmin(targetClean)
		return targetReal, targetClean, err
	}
	return destReal, destClean, nil
}

func (s *Server) download(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	realPath, _, err := s.root.ResolveAdmin(r.URL.Query().Get("path"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad path"))
		return
	}
	info, err := s.root.Stat(realPath)
	if err != nil || info.IsDir() {
		writeJSON(w, http.StatusNotFound, errorBody("not found"))
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(realPath)))
	s.logActivity(activity.Event{Type: "admin_download", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "download", Path: r.URL.Query().Get("path"), Bytes: info.Size(), Detail: "admin download"})
	s.serveStorageFile(w, r, realPath, info.Name())
}

func (s *Server) serveStorageFile(w http.ResponseWriter, r *http.Request, realPath, name string) {
	file, err := s.root.Open(realPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 20<<30)
	// #nosec G120 -- MaxBytesReader caps the request; multipart spools file parts above maxMemory.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad multipart form"))
		return
	}
	dir := r.FormValue("path")
	_, cleanDir, err := s.root.ResolveAdmin(dir)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad path"))
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("file is required"))
		return
	}
	defer file.Close()
	filename := filepath.Base(header.Filename)
	if filename == "" || filename == "." || filename == string(os.PathSeparator) {
		writeJSON(w, http.StatusBadRequest, errorBody("bad filename"))
		return
	}
	destVirtual := path.Join(cleanDir, filename)
	dest, _, err := s.root.ResolveAdmin(destVirtual)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad destination"))
		return
	}
	if info, err := s.root.Stat(dest); err == nil && !info.IsDir() {
		_, _ = s.root.Version(dest, destVirtual, p.User.Username)
	}
	out, err := s.root.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	defer out.Close()
	n, err := io.Copy(out, file)
	if err != nil {
		s.logActivity(activity.Event{Type: "admin_upload", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "upload", Outcome: "failed", Path: destVirtual, Bytes: n, Detail: err.Error()})
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	s.logActivity(activity.Event{Type: "admin_upload", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "upload", Path: destVirtual, Bytes: n, Detail: "admin upload"})
	writeJSON(w, http.StatusOK, map[string]any{"path": filepath.ToSlash(filepath.Join(dir, filename))})
}

func (s *Server) uploadChunk(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 96<<20)
	// #nosec G120 -- MaxBytesReader caps chunk requests; multipart spools file parts above maxMemory.
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad multipart form"))
		return
	}
	dir := r.FormValue("path")
	_, cleanDir, err := s.root.ResolveAdmin(dir)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad path"))
		return
	}
	filename := filepath.Base(r.FormValue("filename"))
	if filename == "" || filename == "." || filename == string(os.PathSeparator) {
		writeJSON(w, http.StatusBadRequest, errorBody("bad filename"))
		return
	}
	uploadID := r.FormValue("upload_id")
	if !safeUploadID(uploadID) {
		writeJSON(w, http.StatusBadRequest, errorBody("bad upload id"))
		return
	}
	offset, err := strconv.ParseInt(r.FormValue("offset"), 10, 64)
	if err != nil || offset < 0 {
		writeJSON(w, http.StatusBadRequest, errorBody("bad offset"))
		return
	}
	total, err := strconv.ParseInt(r.FormValue("total_size"), 10, 64)
	if err != nil || total < 0 || offset > total {
		writeJSON(w, http.StatusBadRequest, errorBody("bad total size"))
		return
	}
	chunk, _, err := r.FormFile("chunk")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("chunk is required"))
		return
	}
	defer chunk.Close()

	destVirtual := path.Join(cleanDir, filename)
	dest, _, err := s.root.ResolveAdmin(destVirtual)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad destination"))
		return
	}
	tmpDir := filepath.Join(s.root.Base, "._macftpd_uploads")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	partPath := filepath.Join(tmpDir, uploadID+".part")
	partPath = filepath.Clean(partPath)
	if !strings.HasPrefix(partPath, tmpDir+string(os.PathSeparator)) {
		writeJSON(w, http.StatusBadRequest, errorBody("bad upload id"))
		return
	}
	if offset == 0 {
		_ = os.Remove(partPath)
	}
	part, err := os.OpenFile(partPath, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- uploadID is constrained to a safe basename above.
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	defer part.Close()
	info, err := part.Stat()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	if info.Size() != offset {
		writeJSON(w, http.StatusConflict, errorBody(fmt.Sprintf("offset mismatch: have %d bytes", info.Size())))
		return
	}
	if _, err := part.Seek(offset, io.SeekStart); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	n, err := io.Copy(part, chunk)
	if err != nil {
		s.logActivity(activity.Event{Type: "admin_upload", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "upload", Outcome: "failed", Path: destVirtual, Bytes: offset + n, Detail: err.Error()})
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	written := offset + n
	if written > total {
		writeJSON(w, http.StatusBadRequest, errorBody("chunk exceeds total size"))
		return
	}
	if written < total {
		writeJSON(w, http.StatusOK, map[string]any{"path": destVirtual, "received": written, "complete": false})
		return
	}
	if err := part.Close(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	if info, err := s.root.Stat(dest); err == nil && !info.IsDir() {
		_, _ = s.root.Version(dest, destVirtual, p.User.Username)
	}
	if err := s.root.MkdirAllParent(dest, 0o750); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	if err := s.root.Rename(partPath, dest); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	if err := s.root.Chmod(dest, 0o640); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	s.logActivity(activity.Event{Type: "admin_upload", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "upload", Path: destVirtual, Bytes: written, Detail: "admin chunked upload"})
	writeJSON(w, http.StatusOK, map[string]any{"path": destVirtual, "received": written, "complete": true})
}

func safeUploadID(id string) bool {
	if len(id) < 8 || len(id) > 96 {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func (s *Server) fxp(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	var req struct {
		Host       string `json:"host"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		RemotePath string `json:"remote_path"`
		DestPath   string `json:"dest_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad json"))
		return
	}
	if req.Host == "" || req.RemotePath == "" || req.DestPath == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("host, remote_path, and dest_path are required"))
		return
	}
	realDest, _, err := s.root.ResolveAdmin(req.DestPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad destination"))
		return
	}
	if err := s.root.MkdirAllParent(realDest, 0o750); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	conn, err := ftpclient.Dial(req.Host, ftpclient.DialWithTimeout(30*time.Second))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorBody(err.Error()))
		return
	}
	defer conn.Quit()
	if err := conn.Login(req.Username, req.Password); err != nil {
		writeJSON(w, http.StatusBadGateway, errorBody(err.Error()))
		return
	}
	rc, err := conn.Retr(req.RemotePath)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorBody(err.Error()))
		return
	}
	defer rc.Close()
	out, err := s.root.OpenFile(realDest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	defer out.Close()
	n, err := io.Copy(out, rc)
	if err != nil {
		s.logActivity(activity.Event{Type: "admin_fxp", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "pull", Outcome: "failed", Path: req.RemotePath, DestPath: req.DestPath, Detail: err.Error()})
		writeJSON(w, http.StatusBadGateway, errorBody(err.Error()))
		return
	}
	s.logActivity(activity.Event{Type: "admin_fxp", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "pull", Path: req.RemotePath, DestPath: req.DestPath, Bytes: n, Detail: "admin FTP pull"})
	writeJSON(w, http.StatusOK, map[string]any{"bytes": n, "dest_path": req.DestPath})
}

func (s *Server) purgeCloudflare(w http.ResponseWriter, r *http.Request, _ principal) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	var req struct {
		Files []string `json:"files"`
		Paths []string `json:"paths"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var err error
	if len(req.Files) > 0 || len(req.Paths) > 0 {
		files := append([]string{}, req.Files...)
		for _, p := range req.Paths {
			files = append(files, absoluteURL(r, publicURLForVirtual(s.root, p)))
		}
		err = s.cloudflare.PurgeFiles(r.Context(), files)
	} else {
		err = s.cloudflare.PurgeEverything(r.Context())
	}
	if err != nil {
		if errors.Is(err, cloudflare.ErrNotConfigured) {
			writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
			return
		}
		writeJSON(w, http.StatusBadGateway, errorBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) purgePublicPath(ctx context.Context, r *http.Request, virtual string) {
	if !strings.HasPrefix(path.Clean(virtual), "/"+s.root.PublicDir) {
		return
	}
	_ = s.cloudflare.PurgeFiles(ctx, []string{absoluteURL(r, publicURLForVirtual(s.root, virtual))})
}

func (s *Server) activityFeed(w http.ResponseWriter, r *http.Request, _ principal) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	writeJSON(w, http.StatusOK, s.activityDashboard(limit, after))
}

func (s *Server) activityDashboard(limit int, after int64) activityDashboard {
	if limit <= 0 || limit > 200 {
		limit = 80
	}
	scanLimit := limit * 6
	if scanLimit < 200 {
		scanLimit = 200
	}
	if scanLimit > 500 {
		scanLimit = 500
	}
	dashboard := activityDashboard{
		Events:           []activity.Event{},
		Security:         []activity.Event{},
		ExternalFailures: []activity.Event{},
		AdminMistakes:    []activity.Event{},
	}
	for _, event := range s.activity.Recent(scanLimit, after) {
		if isMonitorActivity(event) {
			dashboard.Monitor.Count++
			if dashboard.Monitor.Last.ID == 0 {
				dashboard.Monitor.Last = event
			}
			if isSecurityActivity(event) {
				dashboard.Monitor.Failed++
				if dashboard.Monitor.LastFailed.ID == 0 {
					dashboard.Monitor.LastFailed = event
				}
			} else {
				dashboard.Monitor.OK++
				if dashboard.Monitor.LastOK.ID == 0 {
					dashboard.Monitor.LastOK = event
				}
			}
			continue
		}
		if isSecurityActivity(event) {
			if len(dashboard.Security) < 12 {
				dashboard.Security = append(dashboard.Security, event)
			}
			if isLocalOrKnownAdminActivity(event) {
				if len(dashboard.AdminMistakes) < 8 {
					dashboard.AdminMistakes = append(dashboard.AdminMistakes, event)
				}
			} else if len(dashboard.ExternalFailures) < 8 {
				dashboard.ExternalFailures = append(dashboard.ExternalFailures, event)
			}
		}
		if len(dashboard.Events) < limit {
			dashboard.Events = append(dashboard.Events, event)
		}
	}
	return dashboard
}

func isMonitorActivity(event activity.Event) bool {
	pathValue := strings.TrimPrefix(event.Path, "/")
	destValue := strings.TrimPrefix(event.DestPath, "/")
	if pathValue == "_monitor" || strings.HasPrefix(pathValue, "_monitor/") {
		return true
	}
	if destValue == "_monitor" || strings.HasPrefix(destValue, "_monitor/") {
		return true
	}
	detail := strings.ToLower(event.Detail + " " + event.Message)
	return strings.Contains(detail, "monitor")
}

func isSecurityActivity(event activity.Event) bool {
	switch strings.ToLower(event.Outcome) {
	case "failed", "denied", "limited":
		return true
	}
	return event.Type == "http_security"
}

func isLocalOrKnownAdminActivity(event activity.Event) bool {
	if isLoopbackRemote(event.Remote) {
		return true
	}
	actor := strings.ToLower(strings.TrimSpace(event.Actor))
	if actor == "" || actor == "anonymous" || actor == "someone" {
		return false
	}
	if strings.HasPrefix(event.Type, "admin_") || event.Type == "http_login" || event.Type == "http_logout" {
		return true
	}
	return actor == "admin"
}

func isLoopbackRemote(remote string) bool {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) statusAPI(w http.ResponseWriter, r *http.Request, _ principal) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	sessions := []status.Session{}
	if s.tracker != nil {
		sessions = s.tracker.Snapshot()
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions, "time": time.Now().UTC()})
}

func (s *Server) doctorAPI(w http.ResponseWriter, r *http.Request, _ principal) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": s.doctorChecks(), "time": time.Now().UTC()})
}

func (s *Server) doctorChecks() []map[string]any {
	checks := []map[string]any{}
	add := func(name string, ok bool, detail string) {
		checks = append(checks, map[string]any{"name": name, "ok": ok, "detail": detail})
	}
	if info, err := os.Stat(s.root.Base); err == nil && info.IsDir() {
		add("storage root", true, s.root.Base)
	} else {
		add("storage root", false, fmt.Sprint(err))
	}
	for _, dir := range []string{s.root.PublicDir, s.root.DropboxDir, "._macftpd_trash", "._macftpd_versions"} {
		real := filepath.Join(s.root.Base, dir)
		if err := os.MkdirAll(real, 0o750); err != nil {
			add("storage "+dir, false, err.Error())
		} else {
			add("storage "+dir, true, real)
		}
	}
	add("cloudflare client", s.cloudflare.Enabled(), "configured="+strconv.FormatBool(s.cloudflare.Enabled()))
	add("share store", s.links != nil, strconv.Itoa(len(s.links.List()))+" links")
	add("activity store", s.activity != nil, "ready")
	add("turnstile", s.cfg.TurnstileSecret != "", "configured="+strconv.FormatBool(s.cfg.TurnstileSecret != ""))
	return checks
}

func (s *Server) sharesAPI(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"links": s.links.List()})
	case http.MethodPost:
		var req struct {
			Kind           string `json:"kind"`
			Path           string `json:"path"`
			Label          string `json:"label"`
			ExpiresIn      string `json:"expires_in"`
			Password       string `json:"password"`
			MaxDownloads   int    `json:"max_downloads"`
			AllowOverwrite bool   `json:"allow_overwrite"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody("bad json"))
			return
		}
		if req.Kind == "" {
			req.Kind = string(share.KindDownload)
		}
		realPath, clean, err := s.root.ResolveAdmin(req.Path)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody("bad path"))
			return
		}
		if req.Kind == string(share.KindDownload) {
			if _, err := s.root.Stat(realPath); err != nil {
				writeJSON(w, http.StatusNotFound, errorBody("path not found"))
				return
			}
		} else if err := s.root.MkdirAll(realPath, 0o750); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
			return
		}
		var expires time.Time
		if req.ExpiresIn == "1download" {
			req.MaxDownloads = 1
		} else if req.ExpiresIn != "" && req.ExpiresIn != "never" {
			d, err := time.ParseDuration(req.ExpiresIn)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, errorBody("bad expires_in duration"))
				return
			}
			expires = time.Now().Add(d)
		}
		created, err := s.links.Create(share.CreateRequest{Kind: share.Kind(req.Kind), Path: clean, Label: req.Label, CreatedBy: p.User.Username, ExpiresAt: expires, MaxDownloads: req.MaxDownloads, Password: req.Password, AllowOverwrite: req.AllowOverwrite})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
			return
		}
		prefix := "/s/"
		if created.Link.Kind == share.KindUpload {
			prefix = "/d/"
		}
		urlPath := prefix + created.Link.ID + "/" + created.Token
		if created.Link.Kind == share.KindDownload {
			if info, err := s.root.Stat(realPath); err == nil && !info.IsDir() {
				urlPath += "/" + info.Name()
			}
		}
		created.Link.URLPath = urlPath
		_ = s.links.SetURLPath(created.Link.ID, urlPath)
		url := absoluteURL(r, urlPath)
		s.logActivity(activity.Event{Type: "admin_share", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "create " + string(created.Link.Kind), Path: clean, Detail: "created public link"})
		writeJSON(w, http.StatusOK, map[string]any{"link": created.Link, "url": url})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
	}
}

func (s *Server) statsAPI(w http.ResponseWriter, r *http.Request, _ principal) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	_, clean, err := s.root.ResolveAdmin(r.URL.Query().Get("path"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad path"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stats": s.activity.StatsForPath(clean, 20)})
}

func (s *Server) shareAPI(w http.ResponseWriter, r *http.Request, p principal) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/shares/"), "/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("id is required"))
		return
	}
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	if err := s.links.Delete(id); err != nil {
		writeJSON(w, http.StatusNotFound, errorBody(err.Error()))
		return
	}
	s.logActivity(activity.Event{Type: "admin_share", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "delete", Path: id, Detail: "deleted public link"})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) retentionAPI(w http.ResponseWriter, r *http.Request, _ principal) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	kind := r.URL.Query().Get("kind")
	items, err := s.root.ListRetained(kind)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) restoreAPI(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
		return
	}
	var req struct {
		Kind      string `json:"kind"`
		ID        string `json:"id"`
		DestPath  string `json:"dest_path"`
		Overwrite bool   `json:"overwrite"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad json"))
		return
	}
	dest, err := s.root.Restore(req.Kind, req.ID, req.DestPath, req.Overwrite)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}
	s.logActivity(activity.Event{Type: "admin_retention", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "restore", Path: dest, Detail: "restored retained file"})
	writeJSON(w, http.StatusOK, map[string]any{"path": dest})
}

func (s *Server) requireAdmin(next func(http.ResponseWriter, *http.Request, principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOriginUnsafe(r) {
			s.logActivity(activity.Event{Type: "http_security", Protocol: "http", Remote: remoteAddr(r), Action: "request", Outcome: "denied", Path: r.URL.Path, Detail: "cross-origin admin request denied"})
			writeJSON(w, http.StatusForbidden, errorBody("cross-origin admin request denied"))
			return
		}
		p, ok, limited := s.authenticateRequest(r)
		if limited {
			s.logActivity(activity.Event{Type: "http_login", Protocol: "http", Remote: remoteAddr(r), Action: "login", Outcome: "limited", Path: r.URL.Path, Detail: "admin auth rate-limited"})
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, http.StatusTooManyRequests, errorBody("too many failed login attempts; try again later"))
				return
			}
			http.Error(w, "too many failed login attempts; try again later", http.StatusTooManyRequests)
			return
		}
		if !ok || !p.Perms.Admin {
			s.logActivity(activity.Event{Type: "http_login", Protocol: "http", Remote: remoteAddr(r), Action: "login", Outcome: "failed", Path: r.URL.Path, Detail: "admin auth failed"})
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, http.StatusUnauthorized, errorBody("unauthorized"))
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="macftpd"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, p)
	}
}

func (s *Server) authenticateRequest(r *http.Request) (principal, bool, bool) {
	if username, password, ok := r.BasicAuth(); ok {
		limitKey := loginLimitKey(r, username)
		if !s.limiter.Allow(limitKey) {
			return principal{}, false, true
		}
		user, perms, ok := s.store.Authenticate(username, password)
		if !ok || !perms.Admin {
			s.limiter.Fail(limitKey)
		} else {
			s.limiter.Reset(limitKey)
		}
		return principal{User: user, Perms: perms}, ok, false
	}
	cookie, err := r.Cookie("macftpd_session")
	if err != nil {
		return principal{}, false, false
	}
	username, ok := s.verifySession(cookie.Value)
	if !ok {
		return principal{}, false, false
	}
	user, perms, ok := s.store.Permissions(username)
	return principal{User: user, Perms: perms}, ok, false
}

func (s *Server) logActivity(e activity.Event) {
	if e.Actor == "" {
		e.Actor = "admin"
	}
	s.activity.Add(e)
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, username string) {
	nonce := make([]byte, 18)
	_, _ = rand.Read(nonce)
	exp := time.Now().Add(12 * time.Hour).Unix()
	payload := fmt.Sprintf("%s|%d|%s", username, exp, base64.RawURLEncoding.EncodeToString(nonce))
	mac := hmac.New(sha256.New, s.sessionKey)
	_, _ = mac.Write([]byte(payload))
	token := payload + "|" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{Name: "macftpd_session", Value: base64.RawURLEncoding.EncodeToString([]byte(token)), Path: "/", Expires: time.Unix(exp, 0), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func (s *Server) verifySession(raw string) (string, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", false
	}
	parts := strings.Split(string(decoded), "|")
	if len(parts) != 4 {
		return "", false
	}
	payload := strings.Join(parts[:3], "|")
	mac := hmac.New(sha256.New, s.sessionKey)
	_, _ = mac.Write([]byte(payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[3])) {
		return "", false
	}
	var unix int64
	if _, err := fmt.Sscanf(parts[1], "%d", &unix); err != nil || time.Now().After(time.Unix(unix, 0)) {
		return "", false
	}
	return parts[0], true
}

func (s *Server) verifyTurnstile(r *http.Request, token string) error {
	if s.cfg.TurnstileSecret == "" {
		return nil
	}
	if token == "" {
		return errors.New("missing Turnstile token")
	}
	form := url.Values{}
	form.Set("secret", s.cfg.TurnstileSecret)
	form.Set("response", token)
	form.Set("remoteip", remoteAddr(r))
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://challenges.cloudflare.com/turnstile/v0/siteverify", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var body struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return err
	}
	if !body.Success {
		return errors.New("Turnstile denied token")
	}
	return nil
}

func sanitizeUser(user auth.User) auth.User {
	user.PasswordHash = ""
	return user
}

type publicEntry struct {
	Name     string
	Href     string
	InfoHref string
	Size     int64
	SizeText string
	IsDir    bool
	ModTime  time.Time
	ModText  string
}

type adminCrumb struct {
	Name string
	Path string
}

type adminFileView struct {
	Path          string
	Parent        string
	Entries       []storage.Entry
	Selected      *storage.Entry
	SelectedStats activity.PathStats
	Breadcrumbs   []adminCrumb
	PublicDir     string
	DropboxDir    string
	PublicURL     string
}

type adminUsersView struct {
	Users  []auth.User
	Edit   auth.User
	Status string
	Error  string
}

type adminLinksView struct {
	Links      []share.PublicLink
	CreatedURL string
	Status     string
	Error      string
	Now        time.Time
}

type adminRetentionView struct {
	Kind   string
	Items  []storage.RetainedEntry
	Status string
	Error  string
}

func storageEntry(info os.FileInfo, virtual string) map[string]any {
	return map[string]any{
		"name":      info.Name(),
		"path":      virtual,
		"size":      info.Size(),
		"size_text": humanSize(info.Size(), info.IsDir()),
		"mode":      info.Mode().String(),
		"mod_time":  info.ModTime(),
		"is_dir":    info.IsDir(),
	}
}

func humanSize(size int64, isDir bool) string {
	if isDir {
		return "folder"
	}
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	value := float64(size)
	for _, suffix := range []string{"KB", "MB", "GB", "TB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f PB", value/unit)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`<div class="alert alert-error text-sm">` + html.EscapeString(body) + `</div>`))
}

func permissionSetFromForm(r *http.Request) auth.PermissionSet {
	return auth.PermissionSet{
		List:     r.FormValue("perm_list") == "on",
		Download: r.FormValue("perm_download") == "on",
		Upload:   r.FormValue("perm_upload") == "on",
		Delete:   r.FormValue("perm_delete") == "on",
		Mkdir:    r.FormValue("perm_mkdir") == "on",
		Rename:   r.FormValue("perm_rename") == "on",
		Admin:    r.FormValue("perm_admin") == "on",
		Public:   r.FormValue("perm_public") == "on",
		Dropbox:  r.FormValue("perm_dropbox") == "on",
	}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parentVirtual(p string) string {
	p = path.Clean("/" + strings.TrimPrefix(p, "/"))
	if p == "/" {
		return "/"
	}
	parent := path.Dir(p)
	if parent == "." {
		return "/"
	}
	return parent
}

func breadcrumbs(p string) []adminCrumb {
	p = path.Clean("/" + strings.TrimPrefix(p, "/"))
	crumbs := []adminCrumb{{Name: "root", Path: "/"}}
	if p == "/" {
		return crumbs
	}
	current := ""
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if part == "" {
			continue
		}
		current = path.Join(current, part)
		crumbs = append(crumbs, adminCrumb{Name: part, Path: "/" + strings.TrimPrefix(current, "/")})
	}
	return crumbs
}

func sameOriginUnsafe(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	fetchSite := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
	if fetchSite == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if origin == "null" {
		return fetchSite == "same-origin" || fetchSite == "same-site"
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	for _, host := range requestHosts(r) {
		if strings.EqualFold(parsed.Host, host) {
			return true
		}
	}
	return false
}

func requestHosts(r *http.Request) []string {
	hosts := []string{r.Host}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwarded != "" {
		hosts = append(hosts, forwarded)
	}
	if publicHost := strings.TrimSpace(r.Header.Get("X-Macftpd-Public-Host")); publicHost != "" {
		hosts = append(hosts, publicHost)
	}
	return hosts
}

func loginLimitKey(r *http.Request, username string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	return host + "|" + auth.NormalizeName(username)
}

func remoteAddr(r *http.Request) string {
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		return cf
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	return host
}

func setFileDisposition(w http.ResponseWriter, r *http.Request, name string) {
	ctype := mime.TypeByExtension(strings.ToLower(filepath.Ext(name)))
	inline := strings.HasPrefix(ctype, "image/") || strings.HasPrefix(ctype, "video/") || strings.HasPrefix(ctype, "audio/") || ctype == "application/pdf" || strings.HasPrefix(ctype, "text/")
	if r.URL.Query().Get("download") == "1" {
		inline = false
	}
	disposition := "attachment"
	if inline {
		disposition = "inline"
	}
	w.Header().Set("Content-Disposition", dispositionHeader(disposition, name))
}

func dispositionHeader(disposition, name string) string {
	fallback := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' || r > 0x7e {
			return '_'
		}
		return r
	}, name)
	if fallback == "" {
		fallback = "download"
	}
	return fmt.Sprintf("%s; filename=%q; filename*=UTF-8''%s", disposition, fallback, url.PathEscape(name))
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || strings.EqualFold(r.Header.Get("CF-Visitor"), `{"scheme":"https"}`)
}

func (s *Server) setShareCookie(w http.ResponseWriter, r *http.Request, id, token string) {
	exp := time.Now().Add(12 * time.Hour).Unix()
	payload := fmt.Sprintf("%s|%d", id, exp)
	mac := hmac.New(sha256.New, s.sessionKey)
	_, _ = mac.Write([]byte(payload + "|" + token))
	value := payload + "|" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	cookiePath := r.URL.EscapedPath()
	if cookiePath == "" {
		cookiePath = "/"
	}
	http.SetCookie(w, &http.Cookie{Name: shareCookieName(id), Value: base64.RawURLEncoding.EncodeToString([]byte(value)), Path: cookiePath, Expires: time.Unix(exp, 0), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func (s *Server) verifyShareCookie(r *http.Request, id, token string) bool {
	cookie, err := r.Cookie(shareCookieName(id))
	if err != nil {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return false
	}
	parts := strings.Split(string(decoded), "|")
	if len(parts) != 3 || parts[0] != id {
		return false
	}
	var unix int64
	if _, err := fmt.Sscanf(parts[1], "%d", &unix); err != nil || time.Now().After(time.Unix(unix, 0)) {
		return false
	}
	payload := strings.Join(parts[:2], "|")
	mac := hmac.New(sha256.New, s.sessionKey)
	_, _ = mac.Write([]byte(payload + "|" + token))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(parts[2]))
}

func shareCookieName(id string) string {
	return "macftpd_share_" + strings.NewReplacer("-", "_").Replace(id)
}

func redirectSamePath(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", (&url.URL{Path: r.URL.Path}).String())
	w.WriteHeader(http.StatusSeeOther)
}

func linkParts(urlPath, prefix string) (string, string, bool) {
	rest := strings.Trim(strings.TrimPrefix(urlPath, prefix), "/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func absoluteURL(r *http.Request, p string) string {
	scheme := "http"
	if requestIsHTTPS(r) {
		scheme = "https"
	}
	host := r.Host
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwarded != "" {
		host = forwarded
	}
	if publicHost := strings.TrimSpace(r.Header.Get("X-Macftpd-Public-Host")); publicHost != "" {
		host = publicHost
	}
	return (&url.URL{Scheme: scheme, Host: host, Path: p}).String()
}

func publicURLForVirtual(root *storage.Root, virtual string) string {
	virtual = path.Clean("/" + strings.TrimPrefix(virtual, "/"))
	publicRoot := "/" + root.PublicDir
	if virtual == publicRoot {
		return "/public/"
	}
	if strings.HasPrefix(virtual, publicRoot+"/") {
		return "/public/" + strings.TrimPrefix(virtual, publicRoot+"/")
	}
	return "/public/"
}

func publicURLForShare(root *storage.Root, virtual string) string {
	virtual = path.Clean("/" + strings.TrimPrefix(virtual, "/"))
	publicRoot := "/" + root.PublicDir
	if virtual == publicRoot || !strings.HasPrefix(virtual, publicRoot+"/") {
		return ""
	}
	rel := strings.TrimPrefix(virtual, publicRoot+"/")
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return "/public/" + strings.Join(parts, "/")
}

func errorBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if requestIsHTTPS(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
