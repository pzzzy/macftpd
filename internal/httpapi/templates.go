package httpapi

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"macftpd/internal/share"
)

//go:embed templates/*.html static/*
var uiFS embed.FS

var (
	fileInfoTemplate         = mustTemplate("file_info.html")
	passwordTemplate         = mustTemplate("password.html")
	dropTemplate             = mustTemplate("drop.html")
	adminTemplate            = mustTemplate("admin.html")
	filesPartialTemplate     = mustTemplate("partial_files.html")
	usersPartialTemplate     = mustTemplate("partial_users.html")
	linksPartialTemplate     = mustTemplate("partial_links.html")
	activityPartialTemplate  = mustTemplate("partial_activity.html")
	statusPartialTemplate    = mustTemplate("partial_status.html")
	retentionPartialTemplate = mustTemplate("partial_retention.html")
	publicListingTemplate    = mustTemplate("public_listing.html")
)

const uiAssetVersion = "20260528-retention-scroll"

func mustTemplate(name string) *template.Template {
	return template.Must(template.New(name).Funcs(templateFuncs()).ParseFS(uiFS, "templates/"+name))
}

func (s *Server) staticAssets() http.Handler {
	sub, err := fs.Sub(uiFS, "static")
	if err != nil {
		return http.NotFoundHandler()
	}
	fileServer := http.StripPrefix("/assets/", http.FileServer(http.FS(sub)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		fileServer.ServeHTTP(w, r)
	})
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"base": filepathBase,
		"checked": func(ok bool) template.HTMLAttr {
			if ok {
				return `checked`
			}
			return ``
		},
		"downloadURL": func(p string) string {
			return "/api/download?path=" + url.QueryEscape(p)
		},
		"expiryText": expiryText,
		"formatDate": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.Local().Format("Jan 2, 2006 3:04 PM")
		},
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.Local().Format("3:04:05 PM")
		},
		"hasPrefix": strings.HasPrefix,
		"humanSize": humanSize,
		"ifDirPath": func(entryPath string, isDir bool, currentPath string) string {
			if isDir {
				return entryPath
			}
			return currentPath
		},
		"ifFilePath": func(entryPath string, isDir bool) string {
			if isDir {
				return ""
			}
			return entryPath
		},
		"join": strings.Join,
		"linkURL": func(link share.PublicLink) string {
			if link.URLPath == "" {
				return ""
			}
			return link.URLPath
		},
		"notZero": func(t time.Time) bool {
			return !t.IsZero()
		},
		"adminFilesURL": func(p, selected string) template.URL {
			return template.URL(filesURL("/admin/", p, selected))
		},
		"partialFilesURL": func(p, selected string) string {
			return filesURL("/admin/partials/files", p, selected)
		},
		"pathEscape":  url.PathEscape,
		"queryEscape": url.QueryEscape,
		"shortID": func(s string) string {
			if len(s) <= 10 {
				return s
			}
			return s[:10]
		},
		"statusClass": func(outcome string) string {
			switch strings.ToLower(outcome) {
			case "", "ok":
				return "badge-success"
			case "failed", "denied", "limited":
				return "badge-error"
			default:
				return "badge-warning"
			}
		},
		"uiAsset": func(name string) string {
			return "/assets/" + strings.TrimPrefix(name, "/") + "?v=" + uiAssetVersion
		},
	}
}

func filesURL(urlPath, p, selected string) string {
	values := url.Values{}
	values.Set("path", p)
	if selected != "" {
		values.Set("selected", selected)
	}
	return (&url.URL{Path: urlPath, RawQuery: values.Encode()}).String()
}

func filepathBase(p string) string {
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "/"
	}
	return path.Base(p)
}

func expiryText(link share.PublicLink) string {
	if link.MaxDownloads == 1 {
		return "1 download"
	}
	if link.ExpiresAt == nil || link.ExpiresAt.IsZero() {
		return "never"
	}
	return fmt.Sprintf("expires %s", link.ExpiresAt.Local().Format("Jan 2, 2006 3:04 PM"))
}
