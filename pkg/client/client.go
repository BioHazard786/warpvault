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

	"warpvault/internal/crypto"
)

var (
	ErrSecretBurned   = errors.New("secret has already been burned or destroyed")
	ErrSecretNotFound = errors.New("secret not found")
	ErrInvalidURL     = errors.New("invalid warpvault URL format")
	ErrMissingKey     = errors.New("missing decryption key")
)

// SendOptions configures the creation of a vault secret.
type SendOptions struct {
	Burn     bool
	Expiry   string
	Password string // if empty, a secure random key is auto-generated
}

// SendResult holds the created secret metadata and reconstructed shareable link with #key.
type SendResult struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	ShareURL    string    `json:"share_url"`
	Key         string    `json:"key"`
	DeleteURL   string    `json:"delete_url"`
	DeleteToken string    `json:"delete_token"`
	SizeBytes   int64     `json:"size_bytes"`
	ExpiresAt   time.Time `json:"expires_at"`
	IsBurn      bool      `json:"is_burn"`
}

// Client provides programmatic interactions with a Warpvault server.
type Client struct {
	BaseURL    string
	AuthToken  string
	HTTPClient *http.Client
}

// NewClient creates a new Warpvault Client.
func NewClient(baseURL, authToken string) *Client {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	return &Client{
		BaseURL:   baseURL,
		AuthToken: authToken,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendSecret encrypts plaintext locally and uploads ciphertext to the Warpvault server.
func (c *Client) SendSecret(ctx context.Context, plaintext []byte, opts SendOptions) (*SendResult, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("cannot send an empty secret")
	}

	key := opts.Password
	if key == "" {
		var err error
		key, err = crypto.GenerateRandomKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate encryption key: %w", err)
		}
	}

	// Encrypt locally using OpenSSL PBKDF2-AES-256-CBC format
	ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		return nil, fmt.Errorf("client-side encryption failed: %w", err)
	}

	// Prepare request query parameters
	vals := url.Values{}
	if opts.Burn {
		vals.Set("burn", "true")
	} else if opts.Expiry != "" {
		vals.Set("time", opts.Expiry)
	}

	uploadURL := fmt.Sprintf("%s/api/vault", c.BaseURL)
	if q := vals.Encode(); q != "" {
		uploadURL += "?" + q
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, bytes.NewReader(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("failed to create upload request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "warpvault-cli/1.0.0")
	if c.AuthToken != "" {
		req.Header.Set("X-Auth-Token", c.AuthToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to server failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rawResp struct {
		ID           string    `json:"id"`
		URL          string    `json:"url"`
		DeleteURL    string    `json:"delete_url"`
		DeleteToken  string    `json:"delete_token"`
		SizeBytes    int64     `json:"size_bytes"`
		ExpiresAt    time.Time `json:"expires_at"`
		IsBurnOnRead bool      `json:"is_burn_on_read"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawResp); err != nil {
		return nil, fmt.Errorf("failed to parse server response: %w", err)
	}

	shareURL := fmt.Sprintf("%s#%s", rawResp.URL, key)

	return &SendResult{
		ID:          rawResp.ID,
		URL:         rawResp.URL,
		ShareURL:    shareURL,
		Key:         key,
		DeleteURL:   rawResp.DeleteURL,
		DeleteToken: rawResp.DeleteToken,
		SizeBytes:   rawResp.SizeBytes,
		ExpiresAt:   rawResp.ExpiresAt,
		IsBurn:      rawResp.IsBurnOnRead,
	}, nil
}

// GetSecret fetches ciphertext from the server and decrypts it locally in memory.
func (c *Client) GetSecret(ctx context.Context, id, key string) ([]byte, error) {
	if id == "" {
		return nil, errors.New("secret ID cannot be empty")
	}
	if key == "" {
		return nil, ErrMissingKey
	}

	getURL := fmt.Sprintf("%s/api/vault/%s?burn=1", c.BaseURL, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create get request: %w", err)
	}

	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "warpvault-cli/1.0.0")
	req.Header.Set("X-Burn", "1")
	if c.AuthToken != "" {
		req.Header.Set("X-Auth-Token", c.AuthToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusGone {
		return nil, ErrSecretBurned
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrSecretNotFound
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	ciphertext, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response stream: %w", err)
	}

	// Decrypt locally in RAM
	plaintext, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong key or corrupted data): %w", err)
	}

	return plaintext, nil
}

// ParseVaultURL extracts the server base URL, secret ID, and encryption key from a shareable URL.
// Example: "https://vault.example.com/v/a8X2mP9z#f8c3e210a4b7..." -> ("https://vault.example.com", "a8X2mP9z", "f8c3e210a4b7...", nil)
func ParseVaultURL(rawURL string) (serverBase, id, key string, err error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	key = u.Fragment

	// Extract ID from path: "/v/a8X2mP9z" or "/api/vault/a8X2mP9z" or "a8X2mP9z"
	path := strings.Trim(u.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		id = parts[len(parts)-1]
	}

	if id == "" {
		return "", "", "", fmt.Errorf("%w: path does not contain secret ID", ErrInvalidURL)
	}

	if u.Scheme != "" && u.Host != "" {
		serverBase = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	}

	return serverBase, id, key, nil
}
