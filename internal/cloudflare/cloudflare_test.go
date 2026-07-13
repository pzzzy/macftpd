package cloudflare

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"macftpd/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestPurgeTagUsesConfiguredPublicCacheTag(t *testing.T) {
	client := New(config.CloudflareConfig{Enabled: true, ZoneID: "zone", APIToken: "token", CacheTag: "macftpd-public"})
	client.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("authorization = %q", got)
		}
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(raw)); got != `{"tags":["macftpd-public"]}` {
			t.Fatalf("purge body = %s", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(`{"success":true}`)),
			Header:     make(http.Header),
		}, nil
	})
	if err := client.PurgeTag(context.Background()); err != nil {
		t.Fatal(err)
	}
}
