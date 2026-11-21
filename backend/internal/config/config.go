package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Version is injected at build time:
// -ldflags "-X github.com/BioHazard786/warpvault/backend/internal/config.Version=v1.0.0".
// "dev" for local builds, or the module version when installed with `go install`.
var Version = "dev"

func init() {
	if Version == "" || Version == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			Version = bi.Main.Version
		} else {
			Version = "dev"
		}
	}
}

// Config represents all application configuration parameters.
type Config struct {
	Version            string        `json:"version"`
	HealthCheck        bool          `json:"-"` // -healthcheck: probe /healthz and exit (distroless has no curl)
	Port               string        `env:"WARPVAULT_PORT" envDefault:"8080"`
	BaseURL            string        `env:"WARPVAULT_BASE_URL" envDefault:"http://localhost:8080"`
	StoragePath        string        `env:"WARPVAULT_STORAGE_PATH" envDefault:"./data/storage"`
	DBPath             string        `env:"WARPVAULT_DB_PATH" envDefault:"./data/warpvault.db"`
	MaxSecretSizeMB    int64         `env:"WARPVAULT_MAX_SECRET_SIZE_MB" envDefault:"25"`
	AuthToken          string        `env:"WARPVAULT_AUTH_TOKEN"`
	DefaultExpiry      string        `env:"WARPVAULT_DEFAULT_EXPIRY" envDefault:"burn"`
	AllowedExpiries    []string      `env:"WARPVAULT_ALLOWED_EXPIRIES" envDefault:"burn,1h,12h,24h,72h" envSeparator:","`
	GCInterval         time.Duration `env:"WARPVAULT_GC_INTERVAL" envDefault:"60s"`
	RateLimitReqPerSec float64       `env:"WARPVAULT_RATE_LIMIT_RPS" envDefault:"10.0"`
	RateLimitBurst     int           `env:"WARPVAULT_RATE_LIMIT_BURST" envDefault:"30"`
	TrustProxy         bool          `env:"WARPVAULT_TRUST_PROXY" envDefault:"false"`
	LogLevel           string        `env:"WARPVAULT_LOG_LEVEL" envDefault:"info"`
	LogFormat          string        `env:"WARPVAULT_LOG_FORMAT" envDefault:"text"`
}

// LoadConfig parses flags and environment variables with sensible defaults.
// Environment variables override defaults, and CLI flags override environment variables.
func LoadConfig() *Config {
	// Attempt to load .env from current directory or parents (ignored if file does not exist)
	_ = godotenv.Load(".env", "../.env", "../../.env")

	cfg := &Config{Version: Version}
	if err := env.Parse(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: error parsing environment variables: %v\n", err)
	}

	// CLI flags override environment variables
	if !flag.Parsed() && flag.CommandLine.Lookup("port") == nil {
		flag.StringVar(&cfg.Port, "port", cfg.Port, "HTTP server listening port")
		flag.StringVar(&cfg.BaseURL, "base-url", cfg.BaseURL, "Canonical public base URL (e.g. https://vault.example.com)")
		flag.StringVar(&cfg.StoragePath, "storage-path", cfg.StoragePath, "Path to store encrypted secret payloads")
		flag.StringVar(&cfg.DBPath, "db-path", cfg.DBPath, "Path to SQLite database file")
		flag.Int64Var(&cfg.MaxSecretSizeMB, "max-secret-size-mb", cfg.MaxSecretSizeMB, "Max single secret payload size in MB")
		flag.StringVar(&cfg.AuthToken, "auth-token", cfg.AuthToken, "Optional secret token required for creating vaults")
		flag.StringVar(&cfg.DefaultExpiry, "default-expiry", cfg.DefaultExpiry, "Default expiration duration if omitted")
		flag.BoolVar(&cfg.HealthCheck, "healthcheck", false, "Probe /healthz on the local server and exit")
		flag.BoolVar(&cfg.TrustProxy, "trust-proxy", cfg.TrustProxy, "Trust X-Real-IP and X-Forwarded-For headers from reverse proxy")
	}

	if !flag.Parsed() {
		flag.Parse()
	}

	// Clean trailing slash from BaseURL
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	return cfg
}

// MaxSecretSizeBytes returns the configured maximum secret size in bytes.
func (c *Config) MaxSecretSizeBytes() int64 {
	return c.MaxSecretSizeMB * 1024 * 1024
}

// IsAllowedExpiry checks if the requested expiry string is in AllowedExpiries.
func (c *Config) IsAllowedExpiry(expiry string) bool {
	norm := strings.ToLower(strings.TrimSpace(expiry))
	for _, allowed := range c.AllowedExpiries {
		if strings.ToLower(strings.TrimSpace(allowed)) == norm {
			return true
		}
	}
	return false
}

// ParseExpiry parses and validates an expiration duration.
// Returns duration, whether it is burn-on-read, or an error.
func (c *Config) ParseExpiry(expiry string) (time.Duration, bool, error) {
	norm := strings.ToLower(strings.TrimSpace(expiry))
	if norm == "" {
		norm = strings.ToLower(strings.TrimSpace(c.DefaultExpiry))
	}

	if !c.IsAllowedExpiry(norm) {
		return 0, false, fmt.Errorf("invalid expiry %q (allowed: %s)", expiry, strings.Join(c.AllowedExpiries, ", "))
	}

	if norm == "burn" {
		// Burn-after-reading secrets also expire after 72 hours max by default if never read
		return 72 * time.Hour, true, nil
	}

	d, err := time.ParseDuration(norm)
	if err != nil {
		return 0, false, errors.New("invalid expiry duration format")
	}

	return d, false, nil
}
