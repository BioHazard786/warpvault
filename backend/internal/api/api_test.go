package api

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/BioHazard786/warpvault/backend/internal/config"
	"github.com/BioHazard786/warpvault/backend/internal/database"
	"github.com/BioHazard786/warpvault/backend/internal/gc"
	"github.com/BioHazard786/warpvault/backend/internal/logger"
	"github.com/BioHazard786/warpvault/backend/internal/storage"
)

func setupTestRouter(t *testing.T, authToken string) (http.Handler, *database.DB, *gc.Cleaner, func()) {
	return setupTestRouterWith(t, authToken, nil, "http://localhost:8080")
}

func setupTestRouterWith(t *testing.T, authToken string, staticFS fs.FS, baseURL string) (http.Handler, *database.DB, *gc.Cleaner, func()) {
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
		BaseURL:            baseURL,
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
		StaticFS: staticFS,
	})

	cleanup := func() {
		cleaner.Stop()
		_ = db.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return router, db, cleaner, cleanup
}

// blob returns a syntactically valid warpvault blob (version 1, no passphrase) of n payload bytes.
func blob(n int) []byte {
	b := make([]byte, blobHeaderLen+n+16)
	b[0] = blobVersion
	for i := 2; i < len(b); i++ {
		b[i] = byte(i)
	}
	return b
}

func create(t *testing.T, router http.Handler, query string, body []byte) (VaultResponse, int) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/vault"+query, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var resp VaultResponse
	if rec.Code == http.StatusCreated {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("bad response JSON: %v", err)
		}
	}
	return resp, rec.Code
}

func do(router http.Handler, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestBurnSecretOpensOnce(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	payload := blob(20)
	resp, code := create(t, router, "?expiry=burn", payload)
	if code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", code)
	}
	if !resp.Burn || resp.ID == "" || resp.DeleteToken == "" {
		t.Fatalf("invalid response: %+v", resp)
	}

	// Metadata never burns, however often it is read.
	for i := 0; i < 3; i++ {
		if rec := do(router, "GET", "/api/vault/"+resp.ID, nil); rec.Code != http.StatusOK {
			t.Fatalf("meta read %d: expected 200, got %d", i, rec.Code)
		}
	}
	// A GET on /open must not burn either (previews and crawlers use GET).
	if rec := do(router, "GET", "/api/vault/"+resp.ID+"/open", nil); rec.Code == http.StatusOK {
		t.Fatal("GET /open must not be served")
	}

	open := do(router, "POST", "/api/vault/"+resp.ID+"/open", nil)
	if open.Code != http.StatusOK || !bytes.Equal(open.Body.Bytes(), payload) {
		t.Fatalf("first open: code %d, payload match %v", open.Code, bytes.Equal(open.Body.Bytes(), payload))
	}
	if open.Header().Get("X-Burn-Destroyed") != "true" {
		t.Error("expected X-Burn-Destroyed header")
	}
	if rec := do(router, "POST", "/api/vault/"+resp.ID+"/open", nil); rec.Code != http.StatusGone {
		t.Fatalf("second open: expected 410, got %d", rec.Code)
	}
	if rec := do(router, "GET", "/api/vault/"+resp.ID, nil); rec.Code != http.StatusGone {
		t.Fatalf("meta after burn: expected 410, got %d", rec.Code)
	}
}

func TestMetaReportsPassphraseFlag(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	for _, flag := range []byte{0, 1} {
		b := blob(10)
		b[1] = flag
		resp, _ := create(t, router, "?expiry=1h", b)
		var meta struct {
			Passphrase bool `json:"passphrase"`
		}
		rec := do(router, "GET", "/api/vault/"+resp.ID, nil)
		if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil || meta.Passphrase != (flag == 1) {
			t.Fatalf("flag %d: passphrase=%v err=%v body=%s", flag, meta.Passphrase, err, rec.Body.String())
		}
	}
}

func TestTimedSecretOpensRepeatedly(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	payload := blob(30)
	resp, code := create(t, router, "?expiry=1h", payload)
	if code != http.StatusCreated || resp.Burn {
		t.Fatalf("create: code %d burn %v", code, resp.Burn)
	}
	for i := 0; i < 2; i++ {
		rec := do(router, "POST", "/api/vault/"+resp.ID+"/open", nil)
		if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), payload) {
			t.Fatalf("open %d: code %d", i, rec.Code)
		}
		if rec.Header().Get("X-Burn-Destroyed") != "" {
			t.Error("timed secret must not be marked burned")
		}
	}
}

func TestExpiredSecretIsGoneBeforeGC(t *testing.T) {
	router, db, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	resp, _ := create(t, router, "?expiry=1h", blob(10))
	// Age the secret past its expiry without running the GC.
	if _, err := db.ExecForTest("UPDATE secrets SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Minute).UTC(), resp.ID); err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ method, path string }{
		{"GET", "/api/vault/" + resp.ID},
		{"POST", "/api/vault/" + resp.ID + "/open"},
	} {
		if rec := do(router, p.method, p.path, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s: expected 404 for expired secret, got %d", p.method, p.path, rec.Code)
		}
	}
}

func TestRejectsNonBlobPayloads(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	cases := map[string][]byte{
		"empty":         {},
		"too short":     []byte("hello"),
		"plaintext":     bytes.Repeat([]byte("secret password "), 8),
		"no tag":        blob(0)[:blobHeaderLen+5],
		"unknown flags": append([]byte{blobVersion, 0x80}, blob(10)[2:]...),
	}
	for name, body := range cases {
		if _, code := create(t, router, "?expiry=burn", body); code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", name, code)
		}
	}
	if _, code := create(t, router, "?expiry=7y", blob(10)); code != http.StatusBadRequest {
		t.Errorf("bad expiry: expected 400, got %d", code)
	}
}

func TestOversizedSecretRejected(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()
	if _, code := create(t, router, "?expiry=burn", blob(11*1024*1024)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", code)
	}
}

func TestDeleteWithToken(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	resp, _ := create(t, router, "?expiry=24h", blob(10))
	if rec := do(router, "DELETE", "/api/vault/"+resp.ID, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing token: expected 400, got %d", rec.Code)
	}
	if rec := do(router, "DELETE", "/api/vault/"+resp.ID, map[string]string{"X-Delete-Token": "nope"}); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong token: expected 403, got %d", rec.Code)
	}
	if rec := do(router, "DELETE", "/api/vault/"+resp.ID, map[string]string{"X-Delete-Token": resp.DeleteToken}); rec.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := do(router, "GET", "/api/vault/"+resp.ID, nil); rec.Code != http.StatusNotFound && rec.Code != http.StatusGone {
		t.Fatalf("after delete: expected 404/410, got %d", rec.Code)
	}
}

func TestDestroyByTokenIsPostOnly(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	resp, _ := create(t, router, "?expiry=24h", blob(10))
	// A scanner GETting the delete link (/d/{token}) must not destroy anything.
	do(router, "GET", "/d/"+resp.DeleteToken, nil)
	if rec := do(router, "GET", "/api/vault/"+resp.ID, nil); rec.Code != http.StatusOK {
		t.Fatalf("secret must survive GET /d/{token}, got %d", rec.Code)
	}
	if rec := do(router, "POST", "/api/destroy/"+resp.DeleteToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("destroy: expected 200, got %d", rec.Code)
	}
	if rec := do(router, "POST", "/api/destroy/"+resp.DeleteToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("second destroy: expected 404, got %d", rec.Code)
	}
}

func TestHealthAndInfo(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "")
	defer cleanup()

	if rec := do(router, "GET", "/healthz", nil); rec.Code != http.StatusOK {
		t.Fatalf("healthz: %d", rec.Code)
	}
	rec := do(router, "GET", "/api/info", nil)
	var info map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("info: %d %v", rec.Code, err)
	}
	for _, k := range []string{"version", "max_secret_size_mb", "allowed_expiries", "default_expiry", "auth_required"} {
		if _, ok := info[k]; !ok {
			t.Errorf("/api/info missing %q", k)
		}
	}
}

func TestAuthTokenProtection(t *testing.T) {
	router, _, _, cleanup := setupTestRouter(t, "s3cret")
	defer cleanup()

	if _, code := create(t, router, "?expiry=burn", blob(10)); code != http.StatusUnauthorized {
		t.Fatalf("no token: expected 401, got %d", code)
	}
	req := httptest.NewRequest("POST", "/api/vault?expiry=burn", bytes.NewReader(blob(10)))
	req.Header.Set("X-Auth-Token", "s3cret")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid token: expected 201, got %d", rec.Code)
	}
}

const testInstaller = "#!/bin/bash\nSERVER_URL=\"__WARPVAULT_SERVER__\"\nDEFAULT_SERVER=\"https://vault.warplabs.info\"\n"

func TestInstallScriptGetsServerURL(t *testing.T) {
	static := fstest.MapFS{"install.sh": {Data: []byte(testInstaller)}, "index.html": {Data: []byte("<html>")}}
	router, _, _, cleanup := setupTestRouterWith(t, "", static, "https://vault.example.com")
	defer cleanup()

	rec := do(router, "GET", "/install.sh", nil)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `SERVER_URL="https://vault.example.com"`) {
		t.Fatalf("expected the server URL in the script, got %d: %s", rec.Code, body)
	}
	if strings.Contains(body, "__WARPVAULT_SERVER__") {
		t.Fatal("placeholder was not replaced")
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "shellscript") || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("unexpected headers: %v", rec.Header())
	}
}

// The script is piped into bash, so a BaseURL that isn't a plain http(s) URL must never reach it.
func TestInstallScriptRefusesUnsafeServerURL(t *testing.T) {
	static := fstest.MapFS{"install.sh": {Data: []byte(testInstaller)}}
	for _, evil := range []string{`https://x.com"; rm -rf ~; "`, "https://x.com$(id)", "https://x.com`id`", "javascript:alert(1)", ""} {
		router, _, _, cleanup := setupTestRouterWith(t, "", static, evil)
		body := do(router, "GET", "/install.sh", nil).Body.String()
		cleanup()
		if !strings.Contains(body, `SERVER_URL="__WARPVAULT_SERVER__"`) || strings.Contains(body, "rm -rf") || strings.Contains(body, "$(id)") {
			t.Errorf("BaseURL %q leaked into the script: %s", evil, body)
		}
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	static := fstest.MapFS{"index.html": {Data: []byte("<html>")}}
	router, _, _, cleanup := setupTestRouterWith(t, "", static, "http://localhost:8080")
	defer cleanup()

	for _, path := range []string{"/", "/v/abc", "/healthz", "/api/info", "/nope"} {
		h := do(router, "GET", path, nil).Header()
		if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") ||
			h.Get("Referrer-Policy") != "no-referrer" ||
			h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: missing security headers: %v", path, h)
		}
	}
}

func TestWebManifestContentType(t *testing.T) {
	static := fstest.MapFS{"site.webmanifest": {Data: []byte("{}")}, "index.html": {Data: []byte("<html>")}}
	router, _, _, cleanup := setupTestRouterWith(t, "", static, "http://localhost:8080")
	defer cleanup()

	rec := do(router, "GET", "/site.webmanifest", nil)
	if got := rec.Header().Get("Content-Type"); rec.Code != http.StatusOK || !strings.HasPrefix(got, "application/manifest+json") {
		t.Fatalf("expected application/manifest+json, got %d %q", rec.Code, got)
	}
}
