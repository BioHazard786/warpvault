// Package config decides which Warpvault server the CLI talks to, and with which upload token.
//
// Precedence, highest first: command-line flag, environment variable, the saved config file, then the
// built-in default. `warpvault config set server <url>` writes the config file, so a self-hoster sets it once.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const DefaultServer = "https://vault.warplabs.info"

// Source says where a setting came from, for `warpvault config get`.
type Source string

const (
	FromFlag    Source = "flag"
	FromEnv     Source = "environment"
	FromFile    Source = "config file"
	FromDefault Source = "default"
	NotSet      Source = ""
)

// File is what is saved on disk.
type File struct {
	Server    string `json:"server,omitempty"`
	AuthToken string `json:"auth_token,omitempty"` // only ever sent to Server
}

// Path is the config file location: $WARPVAULT_CONFIG, else <user config dir>/warpvault/config.json
// (~/.config on Linux, ~/Library/Application Support on macOS, %AppData% on Windows).
func Path() (string, error) {
	if p := os.Getenv("WARPVAULT_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot find your config directory (set WARPVAULT_CONFIG to choose a file): %w", err)
	}
	return filepath.Join(dir, "warpvault", "config.json"), nil
}

// Load reads the config file. A missing file is not an error: it returns an empty File.
func Load() (File, error) {
	path, err := Path()
	if err != nil {
		return File{}, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return File{}, nil
	}
	if err != nil {
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, fmt.Errorf("%s is not valid JSON (fix or delete it): %w", path, err)
	}
	return f, nil
}

// Save writes the config file atomically, readable by the owner only (it may hold a token).
func (f File) Save() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// NormalizeServer validates a server address. A bare domain means https.
func NormalizeServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("invalid server %q (want https://host or host)", s)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// Resolve picks the server: flag > $WARPVAULT_SERVER > saved config > default.
func Resolve(flag string) (string, Source, error) {
	candidates := []struct {
		value string
		src   Source
	}{{flag, FromFlag}, {os.Getenv("WARPVAULT_SERVER"), FromEnv}}
	for _, c := range candidates {
		if c.value != "" {
			s, err := NormalizeServer(c.value)
			return s, c.src, err
		}
	}
	f, err := Load()
	if err != nil {
		return "", NotSet, err
	}
	if f.Server != "" {
		s, err := NormalizeServer(f.Server)
		return s, FromFile, err
	}
	return DefaultServer, FromDefault, nil
}

// ResolveAuth picks the upload token for `server`: flag > $WARPVAULT_AUTH_TOKEN > saved token. The saved
// token is only used for the server it was saved with, so it can never leak to a different one.
func ResolveAuth(flag, server string) (string, Source) {
	if flag != "" {
		return flag, FromFlag
	}
	if env := os.Getenv("WARPVAULT_AUTH_TOKEN"); env != "" {
		return env, FromEnv
	}
	f, err := Load()
	if err != nil || f.AuthToken == "" {
		return "", NotSet
	}
	owner := f.Server
	if owner == "" {
		owner = DefaultServer
	}
	if n, err := NormalizeServer(owner); err != nil || n != server {
		return "", NotSet
	}
	return f.AuthToken, FromFile
}
