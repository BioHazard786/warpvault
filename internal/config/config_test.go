package config

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := &Config{
		Port:            "8080",
		BaseURL:         "http://localhost:8080",
		MaxSecretSizeMB: 25,
		DefaultExpiry:   "burn",
		AllowedExpiries: []string{"burn", "1h", "12h", "24h", "72h"},
	}

	if cfg.MaxSecretSizeBytes() != 25*1024*1024 {
		t.Errorf("expected 26214400 bytes, got %d", cfg.MaxSecretSizeBytes())
	}

	dur, isBurn, err := cfg.ParseExpiry("burn")
	if err != nil {
		t.Fatalf("unexpected error parsing burn: %v", err)
	}
	if !isBurn {
		t.Error("expected isBurn to be true")
	}
	if dur != 72*time.Hour {
		t.Errorf("expected 72h max lifetime for burn, got %v", dur)
	}

	dur, isBurn, err = cfg.ParseExpiry("12h")
	if err != nil {
		t.Fatalf("unexpected error parsing 12h: %v", err)
	}
	if isBurn {
		t.Error("expected isBurn to be false for 12h")
	}
	if dur != 12*time.Hour {
		t.Errorf("expected 12h, got %v", dur)
	}

	_, _, err = cfg.ParseExpiry("999h")
	if err == nil {
		t.Error("expected error for unallowed expiry 999h")
	}
}
