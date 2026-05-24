package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"macftpd/internal/config"
)

var ErrNotConfigured = errors.New("cloudflare is not configured")

type Client struct {
	cfg  config.CloudflareConfig
	http *http.Client
}

func New(cfg config.CloudflareConfig) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second}}
}

func (c *Client) Enabled() bool {
	return c != nil && c.cfg.Enabled && c.cfg.ZoneID != "" && c.cfg.APIToken != ""
}

func (c *Client) AddCacheHeaders(w http.ResponseWriter) {
	if c == nil || c.cfg.CacheTag == "" {
		return
	}
	w.Header().Set("Cache-Tag", c.cfg.CacheTag)
}

func (c *Client) PurgeEverything(ctx context.Context) error {
	if !c.Enabled() {
		return ErrNotConfigured
	}
	body := map[string]bool{"purge_everything": true}
	return c.post(ctx, body)
}

func (c *Client) PurgeFiles(ctx context.Context, files []string) error {
	if len(files) == 0 {
		return nil
	}
	if !c.Enabled() {
		return ErrNotConfigured
	}
	body := map[string][]string{"files": files}
	return c.post(ctx, body)
}

func (c *Client) post(ctx context.Context, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/purge_cache", c.cfg.ZoneID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare purge failed: %s", resp.Status)
	}
	return nil
}
