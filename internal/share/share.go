package share

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"macftpd/internal/auth"
)

type Kind string

const (
	KindDownload Kind = "download"
	KindUpload   Kind = "upload"
)

type Link struct {
	ID             string    `json:"id"`
	Kind           Kind      `json:"kind"`
	Path           string    `json:"path"`
	Label          string    `json:"label,omitempty"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	MaxDownloads   int       `json:"max_downloads,omitempty"`
	DownloadCount  int       `json:"download_count,omitempty"`
	TokenHash      string    `json:"token_hash"`
	PasswordHash   string    `json:"password_hash,omitempty"`
	AllowOverwrite bool      `json:"allow_overwrite,omitempty"`
	Disabled       bool      `json:"disabled,omitempty"`
}

type PublicLink struct {
	ID             string    `json:"id"`
	Kind           Kind      `json:"kind"`
	Path           string    `json:"path"`
	Label          string    `json:"label,omitempty"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	MaxDownloads   int       `json:"max_downloads,omitempty"`
	DownloadCount  int       `json:"download_count,omitempty"`
	HasPassword    bool      `json:"has_password"`
	AllowOverwrite bool      `json:"allow_overwrite,omitempty"`
	Disabled       bool      `json:"disabled,omitempty"`
}

type CreateRequest struct {
	Kind           Kind
	Path           string
	Label          string
	CreatedBy      string
	ExpiresAt      time.Time
	MaxDownloads   int
	Password       string
	AllowOverwrite bool
}

type Created struct {
	Link  PublicLink
	Token string
}

type Store struct {
	mu    sync.RWMutex
	path  string
	links map[string]Link
}

var (
	ErrNotFound = errors.New("link not found")
	ErrDenied   = errors.New("link token denied")
	ErrExpired  = errors.New("link expired")
	ErrDisabled = errors.New("link disabled")
)

func Open(path string) (*Store, error) {
	s := &Store{path: path, links: map[string]Link{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Create(req CreateRequest) (Created, error) {
	if req.Kind != KindDownload && req.Kind != KindUpload {
		return Created{}, errors.New("bad link kind")
	}
	id, err := randomToken(10)
	if err != nil {
		return Created{}, err
	}
	token, err := randomToken(24)
	if err != nil {
		return Created{}, err
	}
	link := Link{
		ID:             id,
		Kind:           req.Kind,
		Path:           cleanVirtual(req.Path),
		Label:          strings.TrimSpace(req.Label),
		CreatedBy:      req.CreatedBy,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      req.ExpiresAt.UTC(),
		MaxDownloads:   req.MaxDownloads,
		TokenHash:      hashToken(token),
		AllowOverwrite: req.AllowOverwrite,
	}
	if req.Password != "" {
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			return Created{}, err
		}
		link.PasswordHash = hash
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if _, exists := s.links[id]; !exists {
			break
		}
		id, err = randomToken(10)
		if err != nil {
			return Created{}, err
		}
		link.ID = id
	}
	s.links[link.ID] = link
	if err := s.saveLocked(); err != nil {
		return Created{}, err
	}
	return Created{Link: public(link), Token: token}, nil
}

func (s *Store) List() []PublicLink {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PublicLink, 0, len(s.links))
	for _, link := range s.links {
		out = append(out, public(link))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *Store) Public(id string) (PublicLink, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	link, ok := s.links[id]
	if !ok {
		return PublicLink{}, ErrNotFound
	}
	return public(link), nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.links[id]; !ok {
		return ErrNotFound
	}
	delete(s.links, id)
	return s.saveLocked()
}

func (s *Store) Verify(id, token, password string) (PublicLink, error) {
	s.mu.RLock()
	link, ok := s.links[id]
	s.mu.RUnlock()
	if !ok {
		return PublicLink{}, ErrNotFound
	}
	if err := validate(link, token, password); err != nil {
		return PublicLink{}, err
	}
	return public(link), nil
}

func (s *Store) RecordDownload(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	link, ok := s.links[id]
	if !ok {
		return ErrNotFound
	}
	link.DownloadCount++
	s.links[id] = link
	return s.saveLocked()
}

func validate(link Link, token, password string) error {
	if link.Disabled {
		return ErrDisabled
	}
	if !link.ExpiresAt.IsZero() && time.Now().After(link.ExpiresAt) {
		return ErrExpired
	}
	if link.MaxDownloads > 0 && link.DownloadCount >= link.MaxDownloads {
		return ErrExpired
	}
	if subtle.ConstantTimeCompare([]byte(hashToken(token)), []byte(link.TokenHash)) != 1 {
		return ErrDenied
	}
	if link.PasswordHash != "" && !auth.VerifyPassword(link.PasswordHash, password) {
		return ErrDenied
	}
	return nil
}

func public(link Link) PublicLink {
	return PublicLink{
		ID:             link.ID,
		Kind:           link.Kind,
		Path:           link.Path,
		Label:          link.Label,
		CreatedBy:      link.CreatedBy,
		CreatedAt:      link.CreatedAt,
		ExpiresAt:      link.ExpiresAt,
		MaxDownloads:   link.MaxDownloads,
		DownloadCount:  link.DownloadCount,
		HasPassword:    link.PasswordHash != "",
		AllowOverwrite: link.AllowOverwrite,
		Disabled:       link.Disabled,
	}
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s.saveLocked()
	}
	if err != nil {
		return err
	}
	var links []Link
	if err := json.Unmarshal(raw, &links); err != nil {
		return err
	}
	s.links = map[string]Link{}
	for _, link := range links {
		if link.ID != "" {
			s.links[link.ID] = link
		}
	}
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	links := make([]Link, 0, len(s.links))
	for _, link := range s.links {
		links = append(links, link)
	}
	sort.Slice(links, func(i, j int) bool { return links[i].CreatedAt.Before(links[j].CreatedAt) })
	raw, err := json.MarshalIndent(links, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, fs.FileMode(0o600)); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomToken(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func cleanVirtual(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	if p == "" {
		return "/"
	}
	clean := filepath.Clean("/" + strings.TrimPrefix(p, "/"))
	return filepath.ToSlash(clean)
}
