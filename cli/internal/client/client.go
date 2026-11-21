// Package client talks to a Warpvault server's HTTP API (protocol/PROTOCOL.md section 5).
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BioHazard786/warpvault/cli/internal/version"
)

var (
	ErrNotFound = errors.New("secret not found (wrong link, or it expired)")
	ErrBurned   = errors.New("secret was already read or destroyed")
	ErrBadLink  = errors.New("invalid warpvault link")
)

// Client provides programmatic access to a Warpvault server.
type Client struct {
	BaseURL   string
	AuthToken string
	HTTP      *http.Client
}

// New creates a Client for the server at baseURL.
func New(baseURL, authToken string) *Client {
	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		AuthToken: authToken,
		HTTP:      &http.Client{Timeout: 2 * time.Minute},
	}
}

// CreateResult is the server's answer to an upload.
type CreateResult struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	DeleteURL   string    `json:"delete_url"`
	DeleteToken string    `json:"delete_token"`
	SizeBytes   int64     `json:"size_bytes"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Burn        bool      `json:"burn"`
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "warpvault-cli/"+version.Version)
	req.Header.Set("Accept", "application/json")
	if c.AuthToken != "" {
		req.Header.Set("X-Auth-Token", c.AuthToken)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", c.BaseURL, err)
	}
	return resp, nil
}

// serverError turns a non-success response into an error carrying the server's {"error"} text.
func serverError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(b))
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	return fmt.Errorf("server error (%d): %s", resp.StatusCode, msg)
}

// Info is the server's public description (GET /api/info).
type Info struct {
	Service      string `json:"service"`
	Version      string `json:"version"`
	AuthRequired bool   `json:"auth_required"`
}

// Info fetches the server's description and checks that it really is a Warpvault server.
func (c *Client) Info(ctx context.Context) (*Info, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/info", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d for /api/info: is it a Warpvault server?", c.BaseURL, resp.StatusCode)
	}
	var info Info
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil || info.Service != "Warpvault" {
		return nil, fmt.Errorf("%s is not a Warpvault server", c.BaseURL)
	}
	return &info, nil
}

// Create uploads an encrypted blob. expiry is "burn" or one of the server's allowed durations.
func (c *Client) Create(ctx context.Context, blob []byte, expiry string) (*CreateResult, error) {
	path := "/api/vault"
	if expiry != "" {
		path += "?expiry=" + url.QueryEscape(expiry)
	}
	resp, err := c.do(ctx, http.MethodPost, path, blob)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, errors.New("the server requires an upload token (use --auth or WARPVAULT_AUTH_TOKEN)")
		}
		return nil, serverError(resp)
	}
	var res CreateResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("unexpected server response: %w", err)
	}
	return &res, nil
}

// Open downloads the blob. For burn-after-reading secrets this destroys the server copy, so callers
// must keep the returned bytes until they are done decrypting.
func (c *Client) Open(ctx context.Context, id string) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodPost, "/api/vault/"+url.PathEscape(id)+"/open", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return io.ReadAll(resp.Body)
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusGone:
		return nil, ErrBurned
	}
	return nil, serverError(resp)
}

// ParseLink splits a share link into server base URL, secret id and key.
// "https://vault.example.com/v/a8X2mP9z#KEY" -> ("https://vault.example.com", "a8X2mP9z", "KEY").
func ParseLink(raw string) (server, id, key string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %v", ErrBadLink, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", "", "", fmt.Errorf("%w: expected https://host/v/<id>#<key>", ErrBadLink)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "v" || parts[1] == "" {
		return "", "", "", fmt.Errorf("%w: path must be /v/<id>", ErrBadLink)
	}
	return u.Scheme + "://" + u.Host, parts[1], u.Fragment, nil
}
