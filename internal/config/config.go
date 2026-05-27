package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	FTP        FTPConfig        `json:"ftp"`
	HTTP       HTTPConfig       `json:"http"`
	Storage    StorageConfig    `json:"storage"`
	Auth       AuthConfig       `json:"auth"`
	Cloudflare CloudflareConfig `json:"cloudflare"`
}

type FTPConfig struct {
	Listen          string   `json:"listen"`
	PassivePorts    string   `json:"passive_ports"`
	ExternalIP      string   `json:"external_ip"`
	AutoMap         bool     `json:"auto_map"`
	NATGateway      string   `json:"nat_gateway"`
	MappingLifetime Duration `json:"mapping_lifetime"`
	TLSCertFile     string   `json:"tls_cert_file"`
	TLSKeyFile      string   `json:"tls_key_file"`
	RequireTLS      bool     `json:"require_tls"`
	AllowActive     bool     `json:"allow_active"`
	AllowFXP        bool     `json:"allow_fxp"`
	IdleTimeout     Duration `json:"idle_timeout"`
	Welcome         string   `json:"welcome"`
	AllowedCommands []string `json:"allowed_commands"`
}

type HTTPConfig struct {
	Listen             string   `json:"listen"`
	PublicBaseURL      string   `json:"public_base_url"`
	SessionKey         string   `json:"session_key"`
	PublicCacheControl string   `json:"public_cache_control"`
	TurnstileSiteKey   string   `json:"turnstile_site_key"`
	TurnstileSecret    string   `json:"turnstile_secret"`
	ReadTimeout        Duration `json:"read_timeout"`
	WriteTimeout       Duration `json:"write_timeout"`
}

type StorageConfig struct {
	Root       string   `json:"root"`
	PublicDir  string   `json:"public_dir"`
	DropboxDir string   `json:"dropbox_dir"`
	Ignore     []string `json:"ignore"`
}

type AuthConfig struct {
	UsersPath          string `json:"users_path"`
	BootstrapAdminUser string `json:"bootstrap_admin_user"`
	BootstrapAdminPass string `json:"bootstrap_admin_pass"`
}

type CloudflareConfig struct {
	Enabled   bool   `json:"enabled"`
	ZoneID    string `json:"zone_id"`
	APIToken  string `json:"api_token"`
	CacheTag  string `json:"cache_tag"`
	HTTPProxy bool   `json:"http_proxy"`
}

type Duration time.Duration

func (d *Duration) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return err
	}
	*d = Duration(time.Duration(n) * time.Second)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d Duration) Std(defaultValue time.Duration) time.Duration {
	if d == 0 {
		return defaultValue
	}
	return time.Duration(d)
}

func Default() Config {
	return Config{
		FTP: FTPConfig{
			Listen:          "127.0.0.1:2121",
			PassivePorts:    "50000-50100",
			AllowActive:     true,
			AllowFXP:        false,
			AutoMap:         true,
			MappingLifetime: Duration(1 * time.Hour),
			IdleTimeout:     Duration(10 * time.Minute),
			Welcome:         "macftpd ready",
		},
		HTTP: HTTPConfig{
			Listen:             "127.0.0.1:8080",
			PublicCacheControl: "public, max-age=300, stale-while-revalidate=60",
			ReadTimeout:        Duration(10 * time.Second),
			WriteTimeout:       Duration(60 * time.Second),
		},
		Storage: StorageConfig{
			Root:       "./var/ftpd",
			PublicDir:  "public",
			DropboxDir: "dropboxes",
			Ignore:     []string{".DS_Store", "._*", ".AppleDouble", ".Spotlight-V100", ".Trashes", ".fseventsd", ".TemporaryItems", ".apdisk", ".git", ".svn", ".hg", ".env", ".ssh", "._macftpd_trash", "._macftpd_versions"},
		},
		Auth: AuthConfig{
			UsersPath:          "./var/users.json",
			BootstrapAdminUser: "admin",
		},
		Cloudflare: CloudflareConfig{
			CacheTag: "macftpd-public",
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		raw, err := os.ReadFile(path) // #nosec G304 -- config path is explicit operator-supplied startup input.
		if err != nil {
			return cfg, err
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, err
		}
	}

	applyEnv(&cfg)
	if err := cfg.Normalize(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) Normalize() error {
	if c.FTP.Listen == "" {
		c.FTP.Listen = Default().FTP.Listen
	}
	if c.FTP.MappingLifetime == 0 {
		c.FTP.MappingLifetime = Duration(1 * time.Hour)
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = Default().HTTP.Listen
	}
	if c.Storage.Root == "" {
		return errors.New("storage.root is required")
	}
	root, err := filepath.Abs(c.Storage.Root)
	if err != nil {
		return err
	}
	c.Storage.Root = filepath.Clean(root)
	if c.Storage.PublicDir == "" {
		c.Storage.PublicDir = "public"
	}
	if c.Storage.DropboxDir == "" {
		c.Storage.DropboxDir = "dropboxes"
	}
	c.Storage.PublicDir = strings.Trim(strings.ReplaceAll(c.Storage.PublicDir, "\\", "/"), "/")
	c.Storage.DropboxDir = strings.Trim(strings.ReplaceAll(c.Storage.DropboxDir, "\\", "/"), "/")
	if c.Storage.PublicDir == "" || strings.Contains(c.Storage.PublicDir, "/") {
		return errors.New("storage.public_dir must be a single directory name")
	}
	if c.Storage.DropboxDir == "" || strings.Contains(c.Storage.DropboxDir, "/") {
		return errors.New("storage.dropbox_dir must be a single directory name")
	}
	if c.Auth.UsersPath == "" {
		c.Auth.UsersPath = filepath.Join(filepath.Dir(c.Storage.Root), "users.json")
	}
	usersPath, err := filepath.Abs(c.Auth.UsersPath)
	if err != nil {
		return err
	}
	c.Auth.UsersPath = filepath.Clean(usersPath)
	if c.HTTP.SessionKey == "" {
		c.HTTP.SessionKey = os.Getenv("MACFTPD_SESSION_KEY")
	}
	if c.HTTP.SessionKey == "" {
		key, err := randomSessionKey()
		if err != nil {
			return err
		}
		c.HTTP.SessionKey = key
		fmt.Fprintln(os.Stderr, "macftpd generated ephemeral HTTP session key; set http.session_key or MACFTPD_HTTP_SESSION_KEY to preserve admin sessions across restarts")
	}
	c.Cloudflare.ZoneID = strings.TrimSpace(c.Cloudflare.ZoneID)
	c.Cloudflare.APIToken = strings.TrimSpace(c.Cloudflare.APIToken)
	c.FTP.TLSCertFile = strings.TrimSpace(c.FTP.TLSCertFile)
	c.FTP.TLSKeyFile = strings.TrimSpace(c.FTP.TLSKeyFile)
	c.HTTP.TurnstileSiteKey = strings.TrimSpace(c.HTTP.TurnstileSiteKey)
	c.HTTP.TurnstileSecret = strings.TrimSpace(c.HTTP.TurnstileSecret)
	return nil
}

func EnsureDirs(c Config) error {
	dirs := []string{
		c.Storage.Root,
		filepath.Join(c.Storage.Root, c.Storage.PublicDir),
		filepath.Join(c.Storage.Root, c.Storage.DropboxDir),
		filepath.Dir(c.Auth.UsersPath),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	return nil
}

func applyEnv(c *Config) {
	env := map[string]*string{
		"MACFTPD_FTP_LISTEN":       &c.FTP.Listen,
		"MACFTPD_FTP_PASSIVE":      &c.FTP.PassivePorts,
		"MACFTPD_FTP_EXTERNAL_IP":  &c.FTP.ExternalIP,
		"MACFTPD_FTP_NAT_GATEWAY":  &c.FTP.NATGateway,
		"MACFTPD_FTP_TLS_CERT":     &c.FTP.TLSCertFile,
		"MACFTPD_FTP_TLS_KEY":      &c.FTP.TLSKeyFile,
		"MACFTPD_HTTP_LISTEN":      &c.HTTP.Listen,
		"MACFTPD_STORAGE_ROOT":     &c.Storage.Root,
		"MACFTPD_USERS_PATH":       &c.Auth.UsersPath,
		"MACFTPD_ADMIN_USER":       &c.Auth.BootstrapAdminUser,
		"MACFTPD_ADMIN_PASS":       &c.Auth.BootstrapAdminPass,
		"MACFTPD_CF_ZONE_ID":       &c.Cloudflare.ZoneID,
		"MACFTPD_CF_API_TOKEN":     &c.Cloudflare.APIToken,
		"MACFTPD_PUBLIC_BASE_URL":  &c.HTTP.PublicBaseURL,
		"MACFTPD_CACHE_CONTROL":    &c.HTTP.PublicCacheControl,
		"MACFTPD_CLOUDFLARE_TAG":   &c.Cloudflare.CacheTag,
		"MACFTPD_HTTP_SESSION_KEY": &c.HTTP.SessionKey,
		"MACFTPD_TURNSTILE_SITE":   &c.HTTP.TurnstileSiteKey,
		"MACFTPD_TURNSTILE_SECRET": &c.HTTP.TurnstileSecret,
	}
	for name, dest := range env {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			*dest = v
		}
	}
	if os.Getenv("MACFTPD_CF_ENABLED") == "1" {
		c.Cloudflare.Enabled = true
	}
	if os.Getenv("MACFTPD_FTP_REQUIRE_TLS") == "1" {
		c.FTP.RequireTLS = true
	}
}

func randomSessionKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
