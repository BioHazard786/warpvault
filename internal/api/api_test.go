package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"warpvault/internal/config"
	"warpvault/internal/database"
	"warpvault/internal/gc"
	"warpvault/internal/logger"
	"warpvault/internal/storage"
)

func setupTestRouter(t *testing.T, authToken string) (http.Handler, *database.DB, *gc.Cleaner, func()) {
	tmpDir, err := os.MkdirTemp("", "warpvault_api_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := database.Open(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to open database: %v", err)
	}

	storeDir := filepath.Join(tmpDir, "storage")
	store, err := storage.NewDiskStorage(storeDir)
	if err != nil {
		_ = db.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to open storage: %v", err)
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
		AuthToken:          authToken,
	}

	l := logger.Init("error", "json")
	router := NewRouter(&RouterConfig{
		Config:   cfg,
		DB:       db,
		Storage:  store,
		Cleaner:  cleaner,
		Logger:   l,
		StaticFS: nil,
	})

	cleanup := func() {
		cleaner.Stop()
		_ = db.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return router, db, cleaner, cleanup
}

func TestCreateAndGetBurnSecret(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	payload := []byte("encrypted-ciphertext-bytes-12345")

	// 1. POST /api/vault
	req := httptest.NewRequest("POST", "/api/vault?burn=true", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp VaultResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	if resp.ID == "" || resp.DeleteToken == "" {
		t.Fatalf("invalid response fields: %+v", resp)
	}
	if !resp.IsBurnOnRead {
		t.Error("expected IsBurnOnRead to be true")
	}

	// 2. GET /api/vault/{id} with burn=1 (First read -> success & burn)
	getReq := httptest.NewRequest("GET", "/api/vault/"+resp.ID+"?burn=1", nil)
	getRec := httptest.NewRecorder()

	router.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on first read, got %d: %s", getRec.Code, getRec.Body.String())
	}

	if !bytes.Equal(getRec.Body.Bytes(), payload) {
		t.Fatalf("payload mismatch:\nExpected: %s\nGot: %s", string(payload), getRec.Body.String())
	}
	if getRec.Header().Get("X-Burn-Destroyed") != "true" {
		t.Error("expected X-Burn-Destroyed header")
	}

	// 3. Second GET /api/vault/{id} -> must be 410 Gone!
	secondReq := httptest.NewRequest("GET", "/api/vault/"+resp.ID+"?burn=1", nil)
	secondRec := httptest.NewRecorder()

	router.ServeHTTP(secondRec, secondReq)
	if secondRec.Code != http.StatusGone {
		t.Fatalf("expected 410 Gone on second read, got %d: %s", secondRec.Code, secondRec.Body.String())
	}
}

func TestCreateAndGetTimedSecret(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	payload := []byte("confidential-timed-payload")

	// POST /api/vault with time=12h
	req := httptest.NewRequest("POST", "/api/vault?time=12h", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", rec.Code)
	}

	var resp VaultResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	// Multiple GETs should succeed because it's not burn-on-read
	for i := 0; i < 3; i++ {
		getReq := httptest.NewRequest("GET", "/api/vault/"+resp.ID, nil)
		getRec := httptest.NewRecorder()
		router.ServeHTTP(getRec, getReq)

		if getRec.Code != http.StatusOK {
			t.Fatalf("iteration %d: expected 200 OK, got %d", i, getRec.Code)
		}
		if !bytes.Equal(getRec.Body.Bytes(), payload) {
			t.Fatalf("iteration %d: payload mismatch", i)
		}
	}
}

func TestDeleteSecretWithToken(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/vault?time=24h", bytes.NewReader([]byte("secret")))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	var resp VaultResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	// DELETE with correct token
	delReq := httptest.NewRequest("DELETE", "/api/vault/"+resp.ID, nil)
	delReq.Header.Set("X-Delete-Token", resp.DeleteToken)
	delRec := httptest.NewRecorder()

	router.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on delete, got %d", delRec.Code)
	}

	// Retrieval after delete must fail
	getReq := httptest.NewRequest("GET", "/api/vault/"+resp.ID, nil)
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after deletion, got %d", getRec.Code)
	}
}

func TestBrowserOneClickDelete(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/vault?time=24h", bytes.NewReader([]byte("secret")))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	var resp VaultResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	// GET /d/{delete_token}
	delReq := httptest.NewRequest("GET", "/d/"+resp.DeleteToken, nil)
	delRec := httptest.NewRecorder()

	router.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on browser delete, got %d", delRec.Code)
	}

	// Second click should be 404
	delReq2 := httptest.NewRequest("GET", "/d/"+resp.DeleteToken, nil)
	delRec2 := httptest.NewRecorder()
	router.ServeHTTP(delRec2, delReq2)
	if delRec2.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on second browser delete, got %d", delRec2.Code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var health map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("failed to parse /api/health: %v", err)
	}
	if health["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", health["status"])
	}
}

func TestTelemetryEndpoint(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/info", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var info map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("failed to parse /api/info: %v", err)
	}

	if info["service"] != "Warpvault" {
		t.Errorf("expected service 'Warpvault', got %v", info["service"])
	}
}

func TestAuthTokenProtection(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "secret-club-key")
	defer cleanup()

	// 1. Unauthorized request
	req1 := httptest.NewRequest("POST", "/api/vault", bytes.NewReader([]byte("secret")))
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rec1.Code)
	}

	// 2. Authorized request
	req2 := httptest.NewRequest("POST", "/api/vault", bytes.NewReader([]byte("secret")))
	req2.Header.Set("X-Auth-Token", "secret-club-key")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created with valid token, got %d", rec2.Code)
	}
}

func TestMultipartUpload(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	part, err := w.CreateFormFile("secret", "keys.enc")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	_, _ = io.WriteString(part, "multipart-encrypted-contents")
	_ = w.Close()

	req := httptest.NewRequest("POST", "/api/vault?burn=true", &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on multipart upload, got %d: %s", rec.Code, rec.Body.String())
	}
}
