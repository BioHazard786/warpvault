package client

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"warpvault/internal/api"
	"warpvault/internal/config"
	"warpvault/internal/database"
	"warpvault/internal/gc"
	"warpvault/internal/logger"
	"warpvault/internal/storage"
)

func setupTestServer(t *testing.T) (*httptest.Server, func()) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	storeDir := tmpDir + "/storage"
	store, err := storage.NewDiskStorage(storeDir)
	if err != nil {
		t.Fatalf("failed to open test storage: %v", err)
	}

	cleaner := gc.NewCleaner(db, store, 1*time.Hour, 2)

	cfg := &config.Config{
		Port:               "8080",
		BaseURL:            "http://localhost:8080",
		StoragePath:        storeDir,
		DBPath:             dbPath,
		MaxSecretSizeMB:    10,
		DefaultExpiry:      "burn",
		AllowedExpiries:    []string{"burn", "1h", "12h", "24h", "72h"},
		GCInterval:         1 * time.Hour,
		RateLimitReqPerSec: 100,
		RateLimitBurst:     100,
	}

	l := logger.Init("error", "json")
	router := api.NewRouter(&api.RouterConfig{
		Config:   cfg,
		DB:       db,
		Storage:  store,
		Cleaner:  cleaner,
		Logger:   l,
		StaticFS: nil,
	})

	server := httptest.NewServer(router)
	cfg.BaseURL = server.URL

	cleanup := func() {
		server.Close()
		cleaner.Stop()
		_ = db.Close()
	}

	return server, cleanup
}

func TestClientSendAndGetBurnSecret(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	c := NewClient(server.URL, "")
	ctx := context.Background()

	original := []byte("top_secret_api_key_sk_999888777")

	// 1. Send secret (Burn-on-read by default)
	res, err := c.SendSecret(ctx, original, SendOptions{Burn: true})
	if err != nil {
		t.Fatalf("SendSecret failed: %v", err)
	}

	if res.ID == "" || res.Key == "" || res.ShareURL == "" {
		t.Fatalf("invalid SendResult: %+v", res)
	}

	// 2. Parse the returned share URL
	serverBase, id, key, err := ParseVaultURL(res.ShareURL)
	if err != nil {
		t.Fatalf("ParseVaultURL failed: %v", err)
	}
	if id != res.ID || key != res.Key {
		t.Fatalf("parsed id/key mismatch: got (%s, %s), expected (%s, %s)", id, key, res.ID, res.Key)
	}
	if serverBase != server.URL {
		t.Fatalf("parsed serverBase mismatch: got %s, expected %s", serverBase, server.URL)
	}

	// 3. Get and Decrypt secret
	decrypted, err := c.GetSecret(ctx, id, key)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}

	if string(decrypted) != string(original) {
		t.Fatalf("decrypted payload mismatch:\nExpected: %s\nGot: %s", string(original), string(decrypted))
	}

	// 4. Second read must fail with ErrSecretBurned
	_, err = c.GetSecret(ctx, id, key)
	if err != ErrSecretBurned {
		t.Fatalf("expected ErrSecretBurned on second read, got: %v", err)
	}
}

func TestClientCustomPassword(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	c := NewClient(server.URL, "")
	ctx := context.Background()

	original := []byte("secret-with-password")
	password := "my-team-passphrase"

	res, err := c.SendSecret(ctx, original, SendOptions{
		Burn:     false,
		Expiry:   "12h",
		Password: password,
	})
	if err != nil {
		t.Fatalf("SendSecret failed: %v", err)
	}

	if res.Key != password {
		t.Errorf("expected key %s, got %s", password, res.Key)
	}

	decrypted, err := c.GetSecret(ctx, res.ID, password)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	if string(decrypted) != string(original) {
		t.Errorf("decrypted payload mismatch: %s != %s", decrypted, original)
	}

	// Wrong password should fail
	_, err = c.GetSecret(ctx, res.ID, "wrong-password")
	if err == nil {
		t.Error("expected error with wrong password, got nil")
	}
}

func TestParseVaultURL(t *testing.T) {
	tests := []struct {
		url        string
		wantServer string
		wantID     string
		wantKey    string
		wantErr    bool
	}{
		{
			url:        "https://vault.example.com/v/a8X2mP9z#f8c3e210a4b7",
			wantServer: "https://vault.example.com",
			wantID:     "a8X2mP9z",
			wantKey:    "f8c3e210a4b7",
			wantErr:    false,
		},
		{
			url:        "http://localhost:8080/v/k8X2mP9z#mykey",
			wantServer: "http://localhost:8080",
			wantID:     "k8X2mP9z",
			wantKey:    "mykey",
			wantErr:    false,
		},
		{
			url:        "simpleID#key",
			wantServer: "",
			wantID:     "simpleID",
			wantKey:    "key",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		serverBase, id, key, err := ParseVaultURL(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseVaultURL(%q) err = %v, wantErr %v", tt.url, err, tt.wantErr)
			continue
		}
		if serverBase != tt.wantServer || id != tt.wantID || key != tt.wantKey {
			t.Errorf("ParseVaultURL(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.url, serverBase, id, key, tt.wantServer, tt.wantID, tt.wantKey)
		}
	}
}
