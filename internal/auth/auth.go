package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

const (
	hashIterations = 210000
	hashSaltBytes  = 18
	hashKeyBytes   = 32
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

var (
	ErrInvalidUsername = errors.New("username must start with a lowercase letter or digit and contain only lowercase letters, digits, underscore, dash, or dot")
	ErrLastAdmin       = errors.New("refusing to remove or disable the last admin")
)

type PermissionSet struct {
	List     bool `json:"list"`
	Download bool `json:"download"`
	Upload   bool `json:"upload"`
	Delete   bool `json:"delete"`
	Mkdir    bool `json:"mkdir"`
	Rename   bool `json:"rename"`
	Admin    bool `json:"admin"`
	Public   bool `json:"public"`
	Dropbox  bool `json:"dropbox"`
}

func AdminPermissions() PermissionSet {
	return PermissionSet{List: true, Download: true, Upload: true, Delete: true, Mkdir: true, Rename: true, Admin: true, Public: true, Dropbox: true}
}

func ReadOnlyPermissions() PermissionSet {
	return PermissionSet{List: true, Download: true, Public: true}
}

func (p PermissionSet) Merge(other PermissionSet) PermissionSet {
	return PermissionSet{
		List:     p.List || other.List,
		Download: p.Download || other.Download,
		Upload:   p.Upload || other.Upload,
		Delete:   p.Delete || other.Delete,
		Mkdir:    p.Mkdir || other.Mkdir,
		Rename:   p.Rename || other.Rename,
		Admin:    p.Admin || other.Admin,
		Public:   p.Public || other.Public,
		Dropbox:  p.Dropbox || other.Dropbox,
	}
}

type User struct {
	Username     string        `json:"username"`
	PasswordHash string        `json:"password_hash,omitempty"`
	Groups       []string      `json:"groups,omitempty"`
	Home         string        `json:"home"`
	Disabled     bool          `json:"disabled,omitempty"`
	Permissions  PermissionSet `json:"permissions"`
}

type Group struct {
	Name        string        `json:"name"`
	Home        string        `json:"home,omitempty"`
	Permissions PermissionSet `json:"permissions"`
}

type Database struct {
	Users  map[string]User  `json:"users"`
	Groups map[string]Group `json:"groups"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	db   Database
}

func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) BootstrapAdmin(username, password string) error {
	username = NormalizeName(username)
	if username == "" {
		username = "admin"
	}
	if err := ValidateName(username); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.db.Users[username]; ok {
		return nil
	}
	if password == "" {
		password = randomBootstrapPassword()
		fmt.Fprintf(os.Stderr, "macftpd generated bootstrap password for %s: %s\n", username, password)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	s.db.Users[username] = User{
		Username:     username,
		PasswordHash: hash,
		Groups:       []string{"admins"},
		Home:         "/",
		Permissions:  AdminPermissions(),
	}
	s.db.Groups["admins"] = Group{Name: "admins", Home: "/", Permissions: AdminPermissions()}
	return s.saveLocked()
}

func (s *Store) Authenticate(username, password string) (User, PermissionSet, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.db.Users[NormalizeName(username)]
	if !ok || user.Disabled || user.PasswordHash == "" {
		return User{}, PermissionSet{}, false
	}
	if !VerifyPassword(user.PasswordHash, password) {
		return User{}, PermissionSet{}, false
	}
	return user, s.permissionsLocked(user), true
}

func (s *Store) Permissions(username string) (User, PermissionSet, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.db.Users[NormalizeName(username)]
	if !ok || user.Disabled {
		return User{}, PermissionSet{}, false
	}
	return user, s.permissionsLocked(user), true
}

func (s *Store) ListUsers() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]User, 0, len(s.db.Users))
	for _, user := range s.db.Users {
		user.PasswordHash = ""
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return users
}

func (s *Store) UpsertUser(user User, password string) error {
	user.Username = NormalizeName(user.Username)
	if err := ValidateName(user.Username); err != nil {
		return err
	}
	if user.Home == "" {
		user.Home = "/" + user.Username
	}
	user.PasswordHash = ""
	s.mu.Lock()
	defer s.mu.Unlock()
	old, existed := s.db.Users[user.Username]
	if existed && password == "" {
		user.PasswordHash = old.PasswordHash
	}
	if password != "" {
		hash, err := HashPassword(password)
		if err != nil {
			return err
		}
		user.PasswordHash = hash
	}
	if user.PasswordHash == "" {
		return errors.New("password is required for new user")
	}
	if existed && s.isLastAdminLocked(old.Username) && !s.userWouldBeAdminLocked(user) {
		return ErrLastAdmin
	}
	s.db.Users[user.Username] = user
	return s.saveLocked()
}

func (s *Store) DeleteUser(username string) error {
	username = NormalizeName(username)
	if err := ValidateName(username); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isLastAdminLocked(username) {
		return ErrLastAdmin
	}
	delete(s.db.Users, username)
	return s.saveLocked()
}

func (s *Store) ListGroups() []Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	groups := make([]Group, 0, len(s.db.Groups))
	for _, group := range s.db.Groups {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	return groups
}

func (s *Store) UpsertGroup(group Group) error {
	group.Name = NormalizeName(group.Name)
	if err := ValidateName(group.Name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Groups[group.Name] = group
	return s.saveLocked()
}

func (s *Store) permissionsLocked(user User) PermissionSet {
	merged := user.Permissions
	for _, groupName := range user.Groups {
		group, ok := s.db.Groups[NormalizeName(groupName)]
		if !ok {
			continue
		}
		merged = merged.Merge(group.Permissions)
	}
	return merged
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db = Database{Users: map[string]User{}, Groups: map[string]Group{}}
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s.saveLocked()
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &s.db); err != nil {
		return err
	}
	if s.db.Users == nil {
		s.db.Users = map[string]User{}
	}
	if s.db.Groups == nil {
		s.db.Groups = map[string]Group{}
	}
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	raw, err := json.MarshalIndent(s.db, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, fs.FileMode(0o600)); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func HashPassword(password string) (string, error) {
	salt := make([]byte, hashSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2.Key([]byte(password), salt, hashIterations, hashKeyBytes, sha256.New)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", hashIterations, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	var iterations int
	if _, err := fmt.Sscanf(parts[1], "%d", &iterations); err != nil || iterations <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual := pbkdf2.Key([]byte(password), salt, iterations, len(expected), sha256.New)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func (s *Store) isLastAdminLocked(username string) bool {
	user, ok := s.db.Users[username]
	if !ok || !s.userWouldBeAdminLocked(user) {
		return false
	}
	admins := 0
	for _, candidate := range s.db.Users {
		if s.userWouldBeAdminLocked(candidate) {
			admins++
		}
	}
	return admins <= 1
}

func (s *Store) userWouldBeAdminLocked(user User) bool {
	if user.Disabled {
		return false
	}
	return s.permissionsLocked(user).Admin
}

func ValidateName(name string) error {
	if !usernamePattern.MatchString(name) {
		return ErrInvalidUsername
	}
	return nil
}

func NormalizeName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' {
			return r
		}
		return -1
	}, name)
	return name
}

func randomBootstrapPassword() string {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "change-me-now"
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
