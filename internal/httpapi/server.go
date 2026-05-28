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
	"html/template"
	"io"
	"log"
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
	mux.HandleFunc("/drop/", s.dropLink)
	mux.HandleFunc("/admin", s.requireAdmin(s.admin))
	mux.HandleFunc("/admin/", s.requireAdmin(s.admin))
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
	s.logActivity(activity.Event{Type: "public_download", Protocol: "http", Actor: "public", Remote: remoteAddr(r), Action: "download", Path: virtual, Detail: "public HTTP download"})
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
	id, token, ok := linkParts(r.URL.Path, "/share/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	meta, err := s.links.Public(id)
	if err != nil || meta.Kind != share.KindDownload {
		http.NotFound(w, r)
		return
	}
	needsPassword := meta.HasPassword
	password := ""
	if r.Method == http.MethodPost {
		password = r.FormValue("password")
	}
	meta, err = s.links.Verify(id, token, password)
	if err != nil {
		if needsPassword || errors.Is(err, share.ErrDenied) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = passwordTemplate.Execute(w, map[string]any{"Title": "Protected share"})
			return
		}
		http.Error(w, "share unavailable", http.StatusGone)
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
	if r.URL.Query().Get("download") == "1" && !info.IsDir() {
		_ = s.links.RecordDownload(id)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", info.Name()))
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
	id, token, ok := linkParts(r.URL.Path, "/drop/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	meta, err := s.links.Verify(id, token, r.FormValue("password"))
	if err != nil || meta.Kind != share.KindUpload {
		http.Error(w, "drop link unavailable", http.StatusGone)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = dropTemplate.Execute(w, meta)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 20<<30)
	// #nosec G120 -- MaxBytesReader caps the request; multipart spools file parts above maxMemory.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()
	name := filepath.Base(header.Filename)
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("Upload complete"))
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
	_ = adminTemplate.Execute(w, map[string]any{"Username": p.User.Username})
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
	events := s.activity.Recent(limit, after)
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
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
	writeJSON(w, http.StatusOK, map[string]any{"checks": checks, "time": time.Now().UTC()})
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
		if req.ExpiresIn != "" {
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
		prefix := "/share/"
		if created.Link.Kind == share.KindUpload {
			prefix = "/drop/"
		}
		url := absoluteURL(r, prefix+created.Link.ID+"/"+created.Token)
		s.logActivity(activity.Event{Type: "admin_share", Protocol: "http", Actor: p.User.Username, Remote: remoteAddr(r), Action: "create " + string(created.Link.Kind), Path: clean, Detail: "created public link"})
		writeJSON(w, http.StatusOK, map[string]any{"link": created.Link, "url": url})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method not allowed"))
	}
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

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || strings.EqualFold(r.Header.Get("CF-Visitor"), `{"scheme":"https"}`)
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

var fileInfoTemplate = template.Must(template.New("fileInfo").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f6f7f4;color:#151716}main{max-width:760px;margin:8vh auto;padding:24px}.panel{background:#fff;border:1px solid #d9dfdb;border-radius:8px;padding:22px}dl{display:grid;grid-template-columns:120px 1fr;gap:10px}dt{color:#68716b}a.button{display:inline-block;margin-top:16px;background:#17645b;color:#fff;text-decoration:none;padding:10px 14px;border-radius:6px}.mono{font-family:ui-monospace,Menlo,monospace;word-break:break-all}</style></head>
<body><main><section class="panel"><h1>{{.Name}}</h1><dl><dt>Path</dt><dd class="mono">{{.Path}}</dd><dt>Type</dt><dd>{{.Type}}</dd><dt>Size</dt><dd>{{.Size}}</dd><dt>Modified</dt><dd>{{.ModTime}}</dd></dl><a class="button" href="{{.Href}}">Download</a></section></main></body></html>`))

var passwordTemplate = template.Must(template.New("sharePassword").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{.Title}}</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f6f7f4;margin:0}main{max-width:420px;margin:12vh auto;background:#fff;border:1px solid #d9dfdb;border-radius:8px;padding:22px}input,button{font:inherit;padding:10px;width:100%;box-sizing:border-box}button{margin-top:10px;background:#17645b;color:#fff;border:0;border-radius:6px}</style></head>
<body><main><h1>{{.Title}}</h1><form method="post"><input type="password" name="password" autocomplete="current-password" placeholder="Password"><button>Open</button></form></main></body></html>`))

var dropTemplate = template.Must(template.New("drop").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Upload drop</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f6f7f4;margin:0}main{max-width:520px;margin:10vh auto;background:#fff;border:1px solid #d9dfdb;border-radius:8px;padding:22px}input,button{font:inherit;padding:10px;width:100%;box-sizing:border-box}button{margin-top:10px;background:#17645b;color:#fff;border:0;border-radius:6px}.mono{font-family:ui-monospace,Menlo,monospace}</style></head>
<body><main><h1>Upload Drop</h1><p class="mono">{{.Path}}</p><form method="post" enctype="multipart/form-data"><input type="file" name="file" required><button>Upload</button></form></main></body></html>`))

var adminTemplate = template.Must(template.New("admin").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>macftpd admin</title>
<style>
:root{color-scheme:light dark;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f4f6f5;color:#161819;--panel:#fff;--line:#d9dfdb;--line2:#edf0ee;--muted:#66706a;--accent:#17645b;--danger:#8f1d1d;--ok:#256a3f;--soft:#f7f8f6}
body{margin:0}header{height:52px;display:flex;align-items:center;justify-content:space-between;padding:0 20px;border-bottom:1px solid #cfd5d0;background:var(--panel)}
main{display:grid;grid-template-columns:minmax(280px,320px) minmax(0,1fr);gap:20px;padding:20px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}.wide{grid-column:1/-1}
h1{font-size:18px;margin:0}h2{font-size:15px;margin:0 0 12px}button,input,select{font:inherit}button{border:1px solid #aeb7b1;background:var(--soft);border-radius:6px;padding:7px 10px;cursor:pointer;white-space:nowrap}button:hover{border-color:#7f8a83}button.primary{background:#17645b;color:#fff;border-color:#17645b}button.danger{color:var(--danger);border-color:#c8a5a5}button.icon{width:34px;min-width:34px;padding:7px 0;text-align:center}
input{box-sizing:border-box;width:100%;border:1px solid #bac3bc;border-radius:6px;padding:8px;background:#fff;color:inherit}label{display:block;font-size:12px;margin:10px 0 4px;color:#4c5550}
table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line2);padding:8px;font-size:13px}th button{border:0;background:transparent;padding:0;font-weight:700;color:inherit}pre{white-space:pre-wrap}
.row{display:flex;gap:8px;align-items:end}.row>*{flex:1}.muted{color:var(--muted)}.danger-text{color:var(--danger)}.ok{color:var(--ok)}.mono{font-family:"SFMono-Regular",Consolas,monospace}.right{text-align:right}.actions{display:flex;gap:6px;justify-content:flex-end}.toolbar{display:flex;gap:8px;align-items:center;justify-content:space-between;margin-bottom:10px}
.file-shell{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:14px}.file-top{display:grid;grid-template-columns:auto auto minmax(180px,1fr) auto;gap:8px;align-items:center;margin-bottom:10px}.file-path-wrap{position:relative}.file-path-wrap input{padding-left:34px}.file-path-wrap span{position:absolute;left:10px;top:8px;color:var(--muted)}.crumbs{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 10px}.crumbs button{padding:5px 8px}.file-tools{display:grid;grid-template-columns:minmax(180px,1fr) auto auto auto auto;gap:8px;align-items:center;margin-bottom:10px}.file-summary{font-size:12px;color:var(--muted);margin:2px 0 10px}.file-list-wrap{border:1px solid var(--line);border-radius:8px;overflow:auto;min-height:360px}.file-table th{position:sticky;top:0;background:var(--soft);z-index:1}.file-table tr{height:42px}.file-table tbody tr{cursor:pointer}.file-table tbody tr:hover{background:#f8faf8}.file-table tbody tr.selected{background:#e8f2ef}.file-table td{vertical-align:middle}.file-name{display:flex;gap:8px;align-items:center;min-width:0}.file-name strong{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.file-icon{display:inline-flex;width:24px;height:24px;align-items:center;justify-content:center;border-radius:5px;background:#e8eeeb;color:#40504a;font-size:13px}.file-check{width:34px}.empty-state{padding:36px 20px;text-align:center;color:var(--muted)}
.file-card{border:1px solid var(--line);border-radius:8px;padding:14px;min-height:360px}.file-card h2{font-size:16px}.file-card dl{display:grid;grid-template-columns:86px 1fr;gap:7px 12px;margin:0 0 14px}.file-card dt{color:var(--muted)}.file-card dd{margin:0;word-break:break-word}.inspector-actions{display:grid;grid-template-columns:1fr 1fr;gap:8px}.inspector-actions .wide-action{grid-column:1/-1}.dropzone{border:1px dashed #9aa59e;border-radius:8px;padding:12px;margin-top:12px;background:#fafbf9}.dropzone.drag{border-color:var(--accent);background:#edf7f4}.dropzone label{margin-top:0}.toast{min-height:20px;font-size:13px;margin-top:10px}.sort-mark{color:var(--accent);font-weight:700}
.activity-feed{display:grid;gap:8px;max-height:360px;overflow:auto}.activity-item{display:grid;grid-template-columns:118px 1fr auto;gap:10px;align-items:start;border-bottom:1px solid var(--line2);padding:8px 0}.activity-item:last-child{border-bottom:0}.activity-time,.activity-meta{font-size:12px;color:var(--muted)}.activity-msg{font-size:13px}.activity-pill{font-size:11px;border:1px solid var(--line);border-radius:999px;padding:2px 7px;color:var(--muted)}.activity-pill.failed,.activity-pill.denied,.activity-pill.limited{color:var(--danger);border-color:#c8a5a5}.activity-pill.ok{color:var(--ok);border-color:#9fc9ae}
@media (max-width:980px){main{grid-template-columns:1fr}.file-shell{grid-template-columns:1fr}.file-card{min-height:0}.file-top,.file-tools{grid-template-columns:1fr 1fr}.file-top .file-path-wrap,.file-tools input{grid-column:1/-1}}
@media (max-width:640px){header{height:auto;align-items:flex-start;gap:8px;flex-direction:column;padding:12px 16px}main{padding:14px}.row{flex-direction:column;align-items:stretch}.file-table th:nth-child(4),.file-table td:nth-child(4),.file-table th:nth-child(5),.file-table td:nth-child(5){display:none}.file-tools{grid-template-columns:1fr 1fr}.file-tools input{grid-column:1/-1}.inspector-actions{grid-template-columns:1fr}}
@media (prefers-color-scheme:dark){:root{background:#151716;color:#eef1ed;--panel:#1f2320;--line:#3b423d;--line2:#333a35;--muted:#a8b1ab;--soft:#2a302c;--accent:#7bd8ca}input{background:#151716;border-color:#48514b}button{color:#eef1ed;border-color:#59645d}.file-table tbody tr:hover{background:#252b27}.file-table tbody tr.selected{background:#1f3a35}.file-icon{background:#303832;color:#d6ded9}.dropzone{background:#1a1e1b}.dropzone.drag{background:#17312d}}
</style>
</head>
<body>
<header><h1>macftpd</h1><div class="muted">Signed in as {{.Username}}</div></header>
<main>
<section class="panel"><h2>Create / update user</h2>
<label>Username</label><input id="username">
<label>Password</label><input id="password" type="password">
<label>Home</label><input id="home" value="/public">
<div class="row"><label><input id="list" type="checkbox" checked> list</label><label><input id="download" type="checkbox" checked> download</label></div>
<div class="row"><label><input id="upload" type="checkbox"> upload</label><label><input id="delete" type="checkbox"> delete</label></div>
<div class="row"><label><input id="mkdir" type="checkbox"> mkdir</label><label><input id="rename" type="checkbox"> rename</label></div>
<div class="row"><label><input id="admin" type="checkbox"> admin</label><label><input id="public" type="checkbox" checked> public</label></div>
<div class="row"><label><input id="dropbox" type="checkbox"> dropbox</label></div>
<p><button onclick="saveUser()">Save user</button></p><pre id="status"></pre></section>
<section class="panel"><h2>Users</h2><table><thead><tr><th>User</th><th>Home</th><th>Groups</th><th>Disabled</th><th></th></tr></thead><tbody id="users"></tbody></table></section>
<section class="panel wide"><div class="toolbar"><h2>Files</h2><div class="muted" id="fileHeaderStatus">Ready</div></div><div class="file-top"><button class="icon" id="upBtn" title="Up one folder">Up</button><button class="icon" id="homeBtn" title="Storage root">/</button><div class="file-path-wrap"><span>/</span><input id="path" value="/" spellcheck="false"></div><button class="primary" id="goBtn">Go</button></div><div class="crumbs" id="crumbs"></div><div class="file-shell"><div><div class="file-tools"><input id="fileSearch" placeholder="Filter files"><button id="refreshBtn">Refresh</button><button id="mkdirBtn">New folder</button><button id="copySelectedBtn">Copy selected</button><button id="moveSelectedBtn">Move selected</button><button id="bulkDeleteBtn">Delete selected</button><button id="clearSelectionBtn">Clear</button></div><div class="file-summary" id="fileSummary"></div><div class="file-list-wrap"><table class="file-table"><thead><tr><th class="file-check"><input id="selectAllFiles" type="checkbox" title="Select all"></th><th><button data-sort="name">Name <span id="sort-name" class="sort-mark"></span></button></th><th class="right"><button data-sort="size">Size <span id="sort-size" class="sort-mark"></span></button></th><th><button data-sort="mod_time">Modified <span id="sort-mod_time" class="sort-mark"></span></button></th><th>Actions</th></tr></thead><tbody id="files"><tr><td colspan="5" class="empty-state">Loading...</td></tr></tbody></table></div><div id="dropzone" class="dropzone"><form id="uploadForm" enctype="multipart/form-data"><label>Upload to current folder</label><div class="row"><input id="uploadFile" type="file" multiple><button>Upload</button></div></form></div><div id="fileStatus" class="toast"></div></div><aside id="fileInfo" class="file-card"></aside></div></section>
<section class="panel"><h2>Cloudflare / Doctor</h2><div class="row"><button onclick="purge()">Purge public cache</button><button id="doctorBtn">Run doctor</button></div><pre id="cf"></pre></section>
<section class="panel"><h2>Links</h2><div class="row"><select id="linkKind"><option value="download">Share</option><option value="upload">Drop</option></select><input id="linkPath" value="/public"></div><div class="row"><input id="linkExpires" placeholder="Expiry e.g. 24h"><input id="linkPassword" type="password" placeholder="Password optional"></div><p><button id="createLinkBtn">Create link</button></p><pre id="linksOut"></pre></section>
<section class="panel"><h2>Trash / versions</h2><div class="row"><button id="loadTrashBtn">Trash</button><button id="loadVersionsBtn">Versions</button></div><div id="retentionList" class="activity-feed"></div></section>
<section class="panel wide"><div class="toolbar"><h2>Live status</h2><button id="refreshStatusBtn">Refresh</button></div><div id="liveStatus" class="activity-feed"></div></section>
<section class="panel wide"><div class="toolbar"><h2>Activity</h2><button id="refreshActivityBtn">Refresh</button></div><div id="activityFeed" class="activity-feed"><div class="muted">Loading activity...</div></div></section>
</main>
<script>
let fileRows=[];let fileSort='name';let fileSortDir=1;let fileDir={};let currentPath='/';let selectedPath='';let selectedFiles=new Set();let loadingFiles=false;let activityLastID=0;let activityRows=[];
function apiURL(path){return new URL(path, location.origin).toString()}
async function api(path, options={}){const r=await fetch(apiURL(path),{headers:{'content-type':'application/json'},...options});const j=await r.json();if(!r.ok)throw new Error(j.error||r.statusText);return j}
async function loginFromURLCredentials(){if(!location.username||location.protocol!=='https:')return;const username=decodeURIComponent(location.username);const password=decodeURIComponent(location.password);history.replaceState(null,'',location.pathname+location.search+location.hash);const r=await fetch(apiURL('/api/login'),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username,password})});if(!r.ok){let msg='login failed';try{msg=(await r.json()).error||msg}catch{}throw new Error(msg)}}
function perms(){return {list:byId('list').checked,download:byId('download').checked,upload:byId('upload').checked,delete:byId('delete').checked,mkdir:byId('mkdir').checked,rename:byId('rename').checked,admin:byId('admin').checked,public:byId('public').checked,dropbox:byId('dropbox').checked}}
function byId(id){return document.getElementById(id)}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function loadUsers(message){try{const data=await api('/api/users');byId('users').innerHTML=data.users.map(u=>'<tr><td class="mono">'+esc(u.username)+'</td><td>'+esc(u.home||'')+'</td><td>'+esc((u.groups||[]).join(', '))+'</td><td>'+(u.disabled?'yes':'no')+'</td><td class="actions"><button data-edit-user="'+esc(u.username)+'">Edit</button><button data-delete-user="'+esc(u.username)+'">Delete</button></td></tr>').join('');byId('users').querySelectorAll('[data-delete-user]').forEach(b=>b.addEventListener('click',()=>delUser(b.dataset.deleteUser)));byId('users').querySelectorAll('[data-edit-user]').forEach(b=>b.addEventListener('click',()=>editUser(data.users.find(u=>u.username===b.dataset.editUser))));byId('status').textContent=message||('Loaded '+data.users.length+' user'+(data.users.length===1?'':'s'))}catch(e){byId('status').textContent='Could not load users: '+e.message}}
function editUser(u){if(!u)return;byId('username').value=u.username;byId('password').value='';byId('home').value=u.home||'/'+u.username;for(const k of ['list','download','upload','delete','mkdir','rename','admin','public','dropbox'])byId(k).checked=!!(u.permissions&&u.permissions[k]);byId('status').textContent='Editing '+u.username+'; leave password blank to keep it'}
async function saveUser(){try{byId('status').textContent='Saving...';const body={username:byId('username').value.trim(),password:byId('password').value,home:byId('home').value.trim(),permissions:perms()};const data=await api('/api/users',{method:'POST',body:JSON.stringify(body)});byId('password').value='';await loadUsers('Saved '+data.user.username)}catch(e){byId('status').textContent='Save failed: '+e.message}}
async function delUser(u){try{if(!confirm('Delete user '+u+'?'))return;await api('/api/users/'+encodeURIComponent(u),{method:'DELETE'});await loadUsers('Deleted '+u)}catch(e){byId('status').textContent='Delete failed: '+e.message}}
function sizeText(n,isDir){if(isDir)return 'folder';let u=['B','KB','MB','GB','TB'],i=0,v=n;while(v>=1024&&i<u.length-1){v/=1024;i++}return (i?v.toFixed(1):v)+' '+u[i]}
function attr(s){return esc(String(s))}
function parentPath(p){const i=p.lastIndexOf('/');return i<=0?'/':p.slice(0,i)}
function downloadURL(p){return apiURL('/api/download?path='+encodeURIComponent(p))}
function cleanPath(p){p=String(p||'/').trim().replace(/\\/g,'/');if(!p.startsWith('/'))p='/'+p;const parts=[];for(const part of p.split('/')){if(!part||part==='.'){continue}else if(part==='..'){parts.pop()}else{parts.push(part)}}return '/'+parts.join('/')}
function basename(p){const parts=cleanPath(p).split('/').filter(Boolean);return parts.length?parts[parts.length-1]:'/'}
function joinPath(base,name){return cleanPath((base==='/'?'':base)+'/'+name)}
function stateURL(path,selected){const u=new URL(location.pathname+location.search+location.hash,location.origin);u.searchParams.set('path',cleanPath(path));if(selected)u.searchParams.set('selected',cleanPath(selected));else u.searchParams.delete('selected');return u.pathname+u.search+u.hash}
function setFileStatus(msg,kind){byId('fileStatus').textContent=msg||'';byId('fileStatus').className='toast '+(kind||'')}
async function parseJSONResponse(r){let j={};try{j=await r.json()}catch{const text=await r.text().catch(()=>'');j={error:text||r.statusText||'request failed'}}if(!r.ok)throw new Error(j.error||r.statusText);return j}
function setHeaderStatus(msg){byId('fileHeaderStatus').textContent=msg}
function initialPath(){return cleanPath(new URLSearchParams(location.search).get('path')||'/')}
function initialSelected(){const p=new URLSearchParams(location.search).get('selected');return p?cleanPath(p):''}
async function loadFiles(path=currentPath,opts={}){path=cleanPath(path);currentPath=path;byId('path').value=path;loadingFiles=true;setHeaderStatus('Loading '+path);if(opts.push)history.pushState({path,selected:opts.selected||''},'',stateURL(path,opts.selected||''));else if(opts.replace)history.replaceState({path,selected:opts.selected||''},'',stateURL(path,opts.selected||''));try{const data=await api('/api/files?path='+encodeURIComponent(path));fileDir=data;selectedFiles.clear();byId('selectAllFiles').checked=false;if(data.entry&&!data.entry.is_dir){selectedPath=data.entry.path;currentPath=parentPath(data.entry.path);byId('path').value=currentPath;fileRows=[];renderCrumbs(currentPath);renderFiles();renderFileInfo(data.entry);setHeaderStatus('Selected '+data.entry.name);if(opts.push)history.replaceState({path:currentPath,selected:selectedPath},'',stateURL(currentPath,selectedPath));}else{fileRows=(data.entries||[]);selectedPath=opts.selected||selectedPath;renderCrumbs(data.path||path);renderFiles();const selected=fileRows.find(e=>e.path===selectedPath);if(selected)renderFileInfo(selected);else hideFileInfo();setHeaderStatus('Browsing '+currentPath);if(opts.replace)history.replaceState({path:currentPath,selected:selectedPath||''},'',stateURL(currentPath,selectedPath||''));}setFileStatus('', '')}catch(e){setHeaderStatus('Error');setFileStatus(e.message,'danger-text')}finally{loadingFiles=false}}
function hideFileInfo(){byId('fileInfo').innerHTML='<h2>No file selected</h2><p class="muted">Select a file or folder to inspect it. Double-click folders to open them.</p><dl><dt>Folder</dt><dd class="mono">'+esc(currentPath)+'</dd><dt>Items</dt><dd>'+fileRows.length+'</dd></dl>'}
function renderFileInfo(e){selectedPath=e.path;byId('fileInfo').innerHTML='<h2>'+esc(e.name)+'</h2><dl><dt>Path</dt><dd class="mono">'+esc(e.path)+'</dd><dt>Type</dt><dd>'+(e.is_dir?'Folder':'File')+'</dd><dt>Size</dt><dd>'+esc(e.size_text||sizeText(e.size,e.is_dir))+'</dd><dt>Mode</dt><dd class="mono">'+esc(e.mode||'')+'</dd><dt>Modified</dt><dd class="mono">'+esc(new Date(e.mod_time).toLocaleString())+'</dd></dl><label>Rename or move to</label><input id="renamePath" class="mono" value="'+attr(e.path)+'"><div class="inspector-actions"><button type="button" id="renameFile">Rename</button><button type="button" id="copyFileTo">Copy to...</button><button type="button" id="moveFileTo">Move to...</button><button type="button" id="copyPath">Copy path</button>'+(e.is_dir?'<button type="button" id="openFolder" class="wide-action primary">Open folder</button>':'<a class="wide-action" href="'+attr(downloadURL(e.path))+'"><button type="button" class="wide-action">Download</button></a>')+'<button type="button" id="deleteFile" class="wide-action danger">Delete</button></div>';byId('renameFile').addEventListener('click',()=>renameFile(e.path));byId('copyFileTo').addEventListener('click',()=>fileAction('copy',[e.path]));byId('moveFileTo').addEventListener('click',()=>fileAction('move',[e.path]));byId('copyPath').addEventListener('click',()=>copyText(e.path));byId('deleteFile').addEventListener('click',()=>delFile(e.path));const open=byId('openFolder');if(open)open.addEventListener('click',()=>goPath(e.path))}
function renderCrumbs(p){const parts=cleanPath(p).split('/').filter(Boolean);let cur='';let html='<button data-path="/">root</button>';for(const part of parts){cur+='/'+part;html+='<button data-path="'+attr(cur)+'">'+esc(part)+'</button>'}byId('crumbs').innerHTML=html;byId('crumbs').querySelectorAll('[data-path]').forEach(b=>b.addEventListener('click',()=>goPath(b.dataset.path)))}
function visibleRows(){const q=byId('fileSearch').value.trim().toLowerCase();return fileRows.filter(e=>!q||e.name.toLowerCase().includes(q)||e.path.toLowerCase().includes(q)).sort((a,b)=>{if(a.is_dir!==b.is_dir)return a.is_dir?-1:1;let av=a[fileSort],bv=b[fileSort];if(fileSort==='name'){av=String(av).toLowerCase();bv=String(bv).toLowerCase()}else{av=Number(av)||0;bv=Number(bv)||0}return (av>bv?1:av<bv?-1:0)*fileSortDir})}
function renderFiles(){for(const k of ['name','size','mod_time'])byId('sort-'+k).textContent=fileSort===k?(fileSortDir>0?'up':'down'):'';const rows=visibleRows();byId('fileSummary').textContent=fileRows.length+' item'+(fileRows.length===1?'':'s')+(selectedFiles.size?' - '+selectedFiles.size+' selected':'');if(!rows.length){byId('files').innerHTML='<tr><td colspan="5" class="empty-state">'+(fileRows.length?'No matching files.':'This folder is empty.')+'</td></tr>';hideFileInfo();return}byId('files').innerHTML=rows.map(e=>'<tr data-path="'+attr(e.path)+'" class="'+(selectedPath===e.path?'selected':'')+'"><td class="file-check"><input type="checkbox" data-check-path="'+attr(e.path)+'" '+(selectedFiles.has(e.path)?'checked':'')+'></td><td><div class="file-name"><span class="file-icon">'+(e.is_dir?'DIR':'FILE')+'</span><strong>'+esc(e.name)+'</strong></div></td><td class="right mono">'+sizeText(e.size,e.is_dir)+'</td><td class="mono">'+esc(new Date(e.mod_time).toLocaleString())+'</td><td class="actions">'+(e.is_dir?'<button data-open-path="'+attr(e.path)+'">Open</button>':'<a href="'+attr(downloadURL(e.path))+'"><button type="button">Download</button></a>')+'<button data-delete-path="'+attr(e.path)+'" class="danger">Delete</button></td></tr>').join('');byId('files').querySelectorAll('tr[data-path]').forEach(row=>{row.addEventListener('click',ev=>{if(ev.target.closest('button,a,input'))return;selectEntry(row.dataset.path,true)});row.addEventListener('dblclick',()=>{const e=fileRows.find(x=>x.path===row.dataset.path);if(e&&e.is_dir)goPath(e.path)})});byId('files').querySelectorAll('[data-open-path]').forEach(b=>b.addEventListener('click',()=>goPath(b.dataset.openPath)));byId('files').querySelectorAll('[data-delete-path]').forEach(b=>b.addEventListener('click',()=>delFile(b.dataset.deletePath)));byId('files').querySelectorAll('[data-check-path]').forEach(c=>c.addEventListener('change',()=>{if(c.checked)selectedFiles.add(c.dataset.checkPath);else selectedFiles.delete(c.dataset.checkPath);renderFiles()}));const selected=fileRows.find(e=>e.path===selectedPath);if(selected)renderFileInfo(selected);else hideFileInfo()}
function sortFiles(k){if(fileSort===k)fileSortDir*=-1;else{fileSort=k;fileSortDir=1}renderFiles()}
function goPath(p){selectedPath='';loadFiles(p,{push:true})}
function selectEntry(p,push){selectedPath=cleanPath(p);const e=fileRows.find(x=>x.path===selectedPath);if(e)renderFileInfo(e);renderFiles();if(push)history.pushState({path:currentPath,selected:selectedPath},'',stateURL(currentPath,selectedPath))}
async function delFile(p){p=cleanPath(p);if(!confirm('Delete '+p+'?'))return;try{await api('/api/files?path='+encodeURIComponent(p),{method:'DELETE'});selectedFiles.delete(p);if(selectedPath===p)selectedPath='';setFileStatus('Deleted '+p,'ok');await loadFiles(currentPath,{replace:true})}catch(e){setFileStatus(e.message,'danger-text')}}
async function bulkDelete(){const paths=[...selectedFiles];if(!paths.length){setFileStatus('No files selected','');return}if(!confirm('Delete '+paths.length+' selected item'+(paths.length===1?'':'s')+'?'))return;try{for(const p of paths)await api('/api/files?path='+encodeURIComponent(p),{method:'DELETE'});selectedFiles.clear();selectedPath='';setFileStatus('Deleted '+paths.length+' item'+(paths.length===1?'':'s'),'ok');await loadFiles(currentPath,{replace:true})}catch(e){setFileStatus(e.message,'danger-text')}}
async function fileAction(operation,paths){paths=paths&&paths.length?paths:[...selectedFiles];if(!paths.length){setFileStatus('No files selected','');return}const dest=prompt((operation==='copy'?'Copy':'Move')+' '+paths.length+' item'+(paths.length===1?'':'s')+' to folder or full path',operation==='copy'?'/public':currentPath);if(!dest)return;const overwrite=confirm('Overwrite destination if it already exists?');try{const data=await api('/api/files/action',{method:'POST',body:JSON.stringify({operation,paths,dest_path:dest,deduplicate:true,overwrite})});selectedFiles.clear();selectedPath=data.items&&data.items[0]?data.items[0].dest_path:'';setFileStatus((operation==='copy'?'Copied ':'Moved ')+paths.length+' item'+(paths.length===1?'':'s')+(data.bytes?' ('+sizeText(data.bytes,false)+')':''),'ok');await loadFiles(operation==='move'?parentPath(selectedPath||currentPath):currentPath,{replace:true,selected:selectedPath});loadActivity()}catch(e){setFileStatus(e.message,'danger-text')}}
async function renameFile(p){try{const dest=byId('renamePath').value.trim();if(!dest)return;const data=await api('/api/files?path='+encodeURIComponent(p),{method:'PATCH',body:JSON.stringify({dest_path:dest})});selectedPath=data.entry.path;currentPath=parentPath(data.entry.path);setFileStatus('Renamed to '+data.entry.path,'ok');await loadFiles(currentPath,{push:true,selected:selectedPath})}catch(e){setFileStatus(e.message,'danger-text')}}
async function mkdir(){const name=prompt('Folder name');if(!name)return;const p=joinPath(currentPath,name);try{await api('/api/files?path='+encodeURIComponent(p),{method:'POST',body:'{}'});setFileStatus('Created '+p,'ok');await loadFiles(currentPath,{replace:true,selected:p})}catch(e){setFileStatus(e.message,'danger-text')}}
function uploadID(){const a=new Uint8Array(12);crypto.getRandomValues(a);return [...a].map(x=>x.toString(16).padStart(2,'0')).join('')}
async function uploadOneFile(f,index,totalFiles){const chunkSize=16*1024*1024;const id=uploadID();let offset=0;let chunkIndex=0;if(f.size===0){const fd=new FormData();fd.append('path',currentPath);fd.append('filename',f.name);fd.append('upload_id',id);fd.append('offset','0');fd.append('total_size','0');fd.append('chunk',new Blob([]),f.name);const r=await fetch(apiURL('/api/upload/chunk'),{method:'POST',body:fd});await parseJSONResponse(r);return}while(offset<f.size){const end=Math.min(offset+chunkSize,f.size);const fd=new FormData();fd.append('path',currentPath);fd.append('filename',f.name);fd.append('upload_id',id);fd.append('offset',String(offset));fd.append('total_size',String(f.size));fd.append('chunk',f.slice(offset,end),f.name);setFileStatus('Uploading '+index+'/'+totalFiles+' '+f.name+' '+Math.floor((end/f.size)*100)+'%','');const r=await fetch(apiURL('/api/upload/chunk'),{method:'POST',body:fd});await parseJSONResponse(r);offset=end;chunkIndex++}}
async function uploadFiles(files){files=[...files];if(!files.length)return;try{let i=0;for(const f of files){i++;await uploadOneFile(f,i,files.length)}setFileStatus('Uploaded '+files.length+' file'+(files.length===1?'':'s'),'ok');byId('uploadFile').value='';await loadFiles(currentPath,{replace:true})}catch(e){const msg=e&&e.message==='Load failed'?'Upload failed before reaching macftpd. Retrying as chunked upload should avoid Cloudflare request-size limits; if this persists, check your network and login session.':(e.message||String(e));setFileStatus(msg,'danger-text')}}
async function copyText(text){try{await navigator.clipboard.writeText(text);setFileStatus('Copied '+text,'ok')}catch(e){setFileStatus(text,'')}}
function renderActivity(){byId('activityFeed').innerHTML=activityRows.map(e=>'<div class="activity-item"><div class="activity-time">'+esc(new Date(e.time).toLocaleTimeString())+'</div><div><div class="activity-msg">'+esc(e.message||'Activity')+'</div><div class="activity-meta">'+esc([e.actor,e.protocol,e.remote].filter(Boolean).join(' - '))+'</div></div><div class="activity-pill '+attr(e.outcome||'ok')+'">'+esc(e.outcome||'ok')+'</div></div>').join('')||'<div class="muted">No activity yet.</div>'}
async function loadActivity(){try{const data=await api('/api/activity?limit=80');activityRows=data.events||[];activityLastID=activityRows.reduce((m,e)=>Math.max(m,e.id||0),activityLastID);renderActivity()}catch(e){byId('activityFeed').innerHTML='<div class="danger-text">'+esc(e.message)+'</div>'}}
async function pollActivity(){try{const data=await api('/api/activity?limit=80&after='+activityLastID);const fresh=data.events||[];if(fresh.length){activityRows=[...fresh,...activityRows].sort((a,b)=>b.id-a.id).slice(0,80);activityLastID=activityRows.reduce((m,e)=>Math.max(m,e.id||0),activityLastID);renderActivity()}}catch(e){}}
async function loadLiveStatus(){try{const data=await api('/api/status');const rows=data.sessions||[];byId('liveStatus').innerHTML=rows.map(s=>'<div class="activity-item"><div class="activity-time">'+esc(s.protocol)+' #'+esc(s.id)+'</div><div><div class="activity-msg">'+esc([s.user||'anonymous',s.action||'connected',s.path||''].filter(Boolean).join(' - '))+'</div><div class="activity-meta">'+esc([s.remote,s.secure?'TLS':'clear',s.mode,s.bytes?sizeText(s.bytes,false):''].filter(Boolean).join(' - '))+'</div></div><div class="activity-pill ok">'+esc(new Date(s.updated_at).toLocaleTimeString())+'</div></div>').join('')||'<div class="muted">No active sessions.</div>'}catch(e){byId('liveStatus').innerHTML='<div class="danger-text">'+esc(e.message)+'</div>'}}
async function createLink(){try{const body={kind:byId('linkKind').value,path:byId('linkPath').value,expires_in:byId('linkExpires').value,password:byId('linkPassword').value,allow_overwrite:true};const data=await api('/api/shares',{method:'POST',body:JSON.stringify(body)});byId('linksOut').textContent=data.url;loadLinks()}catch(e){byId('linksOut').textContent=e.message}}
async function loadLinks(){try{const data=await api('/api/shares');if(!byId('linksOut').textContent)byId('linksOut').textContent=(data.links||[]).map(l=>l.kind+' '+l.path+' '+l.id+(l.expires_at?' expires '+new Date(l.expires_at).toLocaleString():'')).join('\n')}catch(e){}}
async function loadRetention(kind){try{const data=await api('/api/retention?kind='+encodeURIComponent(kind));byId('retentionList').innerHTML=(data.items||[]).map(i=>'<div class="activity-item"><div class="activity-time">'+esc(kind)+'</div><div><div class="activity-msg">'+esc(i.original_path)+'</div><div class="activity-meta">'+esc([i.id,i.is_dir?'folder':sizeText(i.size,false)].join(' - '))+'</div></div><button data-restore="'+attr(i.id)+'" data-kind="'+attr(kind)+'">Restore</button></div>').join('')||'<div class="muted">Nothing retained.</div>';byId('retentionList').querySelectorAll('[data-restore]').forEach(b=>b.addEventListener('click',()=>restoreRetained(b.dataset.kind,b.dataset.restore)))}catch(e){byId('retentionList').innerHTML='<div class="danger-text">'+esc(e.message)+'</div>'}}
async function restoreRetained(kind,id){try{const dest=prompt('Restore to path (blank for original)','');await api('/api/retention/restore',{method:'POST',body:JSON.stringify({kind,id,dest_path:dest,overwrite:false})});loadRetention(kind);loadFiles(currentPath,{replace:true})}catch(e){alert(e.message)}}
function bindFileBrowser(){byId('goBtn').addEventListener('click',()=>goPath(byId('path').value));byId('path').addEventListener('keydown',e=>{if(e.key==='Enter')goPath(byId('path').value)});byId('upBtn').addEventListener('click',()=>goPath(parentPath(currentPath)));byId('homeBtn').addEventListener('click',()=>goPath('/'));byId('refreshBtn').addEventListener('click',()=>loadFiles(currentPath,{replace:true,selected:selectedPath}));byId('mkdirBtn').addEventListener('click',mkdir);byId('copySelectedBtn').addEventListener('click',()=>fileAction('copy'));byId('moveSelectedBtn').addEventListener('click',()=>fileAction('move'));byId('bulkDeleteBtn').addEventListener('click',bulkDelete);byId('clearSelectionBtn').addEventListener('click',()=>{selectedFiles.clear();selectedPath='';renderFiles();history.replaceState({path:currentPath,selected:''},'',stateURL(currentPath,''))});byId('fileSearch').addEventListener('input',renderFiles);byId('selectAllFiles').addEventListener('change',e=>{if(e.target.checked)visibleRows().forEach(r=>selectedFiles.add(r.path));else selectedFiles.clear();renderFiles()});document.querySelectorAll('.file-table th button[data-sort]').forEach(b=>b.addEventListener('click',()=>sortFiles(b.dataset.sort)));byId('uploadForm').addEventListener('submit',e=>{e.preventDefault();uploadFiles(byId('uploadFile').files)});byId('refreshActivityBtn').addEventListener('click',loadActivity);byId('refreshStatusBtn').addEventListener('click',loadLiveStatus);byId('createLinkBtn').addEventListener('click',createLink);byId('doctorBtn').addEventListener('click',doctor);byId('loadTrashBtn').addEventListener('click',()=>loadRetention('trash'));byId('loadVersionsBtn').addEventListener('click',()=>loadRetention('versions'));const dz=byId('dropzone');for(const ev of ['dragenter','dragover'])dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.add('drag')});for(const ev of ['dragleave','drop'])dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.remove('drag')});dz.addEventListener('drop',e=>uploadFiles(e.dataTransfer.files));window.addEventListener('popstate',()=>{selectedPath=initialSelected();loadFiles(initialPath(),{replace:false,selected:selectedPath})})}
async function purge(){try{byId('cf').textContent=JSON.stringify(await api('/api/cloudflare/purge',{method:'POST',body:'{}'}),null,2)}catch(e){byId('cf').textContent=e.message}}
async function doctor(){try{byId('cf').textContent=JSON.stringify(await api('/api/doctor'),null,2)}catch(e){byId('cf').textContent=e.message}}
async function init(){try{await loginFromURLCredentials()}catch(e){byId('status').textContent='Login setup failed: '+e.message;return}bindFileBrowser();selectedPath=initialSelected();history.replaceState({path:initialPath(),selected:selectedPath},'',stateURL(initialPath(),selectedPath));loadUsers();loadFiles(initialPath(),{selected:selectedPath});loadActivity();loadLiveStatus();loadLinks();setInterval(pollActivity,3000);setInterval(loadLiveStatus,3000)}
init();
</script>
</body></html>`))

var publicListingTemplate = template.Must(template.New("public-listing").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Public files {{.Path}}</title>
<style>
:root{color-scheme:light dark;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f7f8;color:#141719}
body{margin:0}header{padding:28px 24px 18px;border-bottom:1px solid #d7dee2;background:#fff}main{max-width:1120px;margin:0 auto;padding:22px 18px 44px}
h1{font-size:28px;line-height:1.1;margin:0 0 8px;letter-spacing:0}.meta{color:#5d6870;font-size:13px}.path{font-family:"SFMono-Regular",Consolas,monospace}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d9e0e4;border-radius:8px;overflow:hidden}th,td{padding:12px 14px;border-bottom:1px solid #edf1f3;text-align:left;font-size:14px}th{background:#f9faf9;color:#536069;font-size:12px;text-transform:uppercase;letter-spacing:.04em}th button{border:0;background:transparent;color:inherit;font:inherit;text-transform:inherit;letter-spacing:inherit;padding:0;cursor:pointer}.right{text-align:right}.mono{font-family:"SFMono-Regular",Consolas,monospace}.name a{color:#17645b;text-decoration:none}.name a:hover{text-decoration:underline}.icon{display:inline-block;width:24px}.parent{margin:0 0 14px}.parent a{color:#17645b}.empty{padding:26px;color:#66727a}
@media (max-width:720px){header{padding:20px 16px 14px}h1{font-size:22px}th:nth-child(3),td:nth-child(3){display:none}td,th{padding:10px 8px}}
@media (prefers-color-scheme:dark){:root{background:#151819;color:#eef2f3}header,table{background:#202527;border-color:#3b454b}th{background:#191d1f;color:#aab5bb}th,td{border-color:#343d42}.meta{color:#a8b2b8}.name a,.parent a{color:#7bd8ca}}
</style>
</head>
<body>
<header><h1>Public Files</h1><div class="meta"><span class="path">{{.Path}}</span> · updated {{.Updated}}</div></header>
<main>
{{if .Parent}}<p class="parent"><a href="{{.Parent}}">Up one folder</a></p>{{end}}
<table id="listing"><thead><tr><th><button data-sort="name">Name</button></th><th class="right"><button data-sort="size">Size</button></th><th><button data-sort="modified">Modified</button></th></tr></thead><tbody>
{{range .Rows}}<tr data-name="{{.Name}}" data-size="{{.Size}}" data-modified="{{.ModTime.Unix}}"><td class="name"><span class="icon">{{if .IsDir}}[+]{{else}}--{{end}}</span><a href="{{.Href}}">{{.Name}}</a> {{if not .IsDir}}<a class="meta" href="{{.InfoHref}}">info</a>{{end}}</td><td class="right mono">{{.SizeText}}</td><td class="mono">{{.ModText}}</td></tr>{{else}}<tr><td colspan="3" class="empty">This folder is empty.</td></tr>{{end}}
</tbody></table>
</main>
<script>
const tbody=document.querySelector('#listing tbody');let active='name',dir=1;
document.querySelectorAll('th button').forEach(b=>b.addEventListener('click',()=>{const k=b.dataset.sort;dir=active===k?-dir:1;active=k;sortRows(k)}));
function sortRows(k){const rows=[...tbody.querySelectorAll('tr[data-name]')];rows.sort((a,b)=>{let av=a.dataset[k],bv=b.dataset[k];if(k!=='name'){av=Number(av);bv=Number(bv)}else{av=av.toLowerCase();bv=bv.toLowerCase()}return av>bv?dir:av<bv?-dir:0});rows.forEach(r=>tbody.appendChild(r))}
</script>
</body></html>`))
