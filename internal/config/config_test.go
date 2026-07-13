package config

import (
	"path/filepath"
	"testing"
)

func TestNormalizePublicBaseURL(t *testing.T) {
	cfg := Default()
	cfg.Storage.Root = filepath.Join(t.TempDir(), "storage")
	cfg.Auth.UsersPath = filepath.Join(t.TempDir(), "users.json")
	cfg.HTTP.SessionKey = "test-session-key"
	cfg.HTTP.PublicBaseURL = " https://ftp.example.com/ "
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.PublicBaseURL != "https://ftp.example.com" {
		t.Fatalf("public base URL = %q", cfg.HTTP.PublicBaseURL)
	}

	cfg.HTTP.PublicBaseURL = "ftp.example.com"
	if err := cfg.Normalize(); err == nil {
		t.Fatal("expected relative public base URL to be rejected")
	}
}
