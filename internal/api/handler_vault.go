package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"warpvault/internal/config"
	"warpvault/internal/database"
	"warpvault/internal/gc"
	"warpvault/internal/storage"
	"warpvault/internal/util"
)

// VaultResponse is returned when a secret is stored.
type VaultResponse struct {
	ID           string    `json:"id"`
	URL          string    `json:"url"`
	DeleteURL    string    `json:"delete_url"`
	DeleteToken  string    `json:"delete_token"`
	SizeBytes    int64     `json:"size_bytes"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	IsBurnOnRead bool      `json:"is_burn_on_read"`
}

// VaultHandler handles encrypted secret storage, single-use burn claims, and streaming.
type VaultHandler struct {
	cfg     *config.Config
	db      *database.DB
	storage storage.StorageEngine
	cleaner *gc.Cleaner
	logger  *slog.Logger
}

// NewVaultHandler creates a VaultHandler instance.
func NewVaultHandler(cfg *config.Config, db *database.DB, store storage.StorageEngine, cleaner *gc.Cleaner, l *slog.Logger) *VaultHandler {
	return &VaultHandler{
		cfg:     cfg,
		db:      db,
		storage: store,
		cleaner: cleaner,
		logger:  l,
	}
}

// HandleCreateSecret handles POST /api/vault uploads from Web UI, CLI, and terminal piping.
func (h *VaultHandler) HandleCreateSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Content-Length check
	if r.ContentLength > h.cfg.MaxSecretSizeBytes() {
		http.Error(w, fmt.Sprintf("secret exceeds maximum allowed size of %d MB", h.cfg.MaxSecretSizeMB), http.StatusRequestEntityTooLarge)
		return
	}

	// 2. Parse Expiry and Burn parameters
	expiryParam := r.URL.Query().Get("time")
	if expiryParam == "" {
		expiryParam = r.URL.Query().Get("expiry")
	}
	if expiryParam == "" {
		expiryParam = r.Header.Get("X-Expiry")
	}

	burnParam := r.URL.Query().Get("burn")
	if burnParam == "" {
		burnParam = r.Header.Get("X-Burn")
	}

	if strings.EqualFold(burnParam, "true") || burnParam == "1" {
		expiryParam = "burn"
	}

	dur, isBurn, err := h.cfg.ParseExpiry(expiryParam)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 3. Extract payload stream (multipart form or raw stream)
	var streamReader io.Reader
	contentType := r.Header.Get("Content-Type")

	if strings.HasPrefix(contentType, "multipart/form-data") {
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}

		var filePart *multipart.Part
		for {
			part, err := mr.NextPart()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				http.Error(w, "error reading multipart form: "+err.Error(), http.StatusBadRequest)
				return
			}

			name := part.FormName()
			if name == "secret" || name == "file" || part.FileName() != "" {
				filePart = part
				break
			}
		}

		if filePart == nil {
			http.Error(w, "missing 'secret' or 'file' form field", http.StatusBadRequest)
			return
		}
		defer filePart.Close()
		streamReader = filePart
	} else {
		// Raw binary stream (curl -T - or CLI)
		streamReader = r.Body
		defer r.Body.Close()
	}

	// 4. Verify stream has content (peek first byte)
	buf := make([]byte, 1)
	n, readErr := streamReader.Read(buf)
	if n == 0 || (readErr != nil && errors.Is(readErr, io.EOF)) {
		http.Error(w, "secret payload cannot be empty", http.StatusBadRequest)
		return
	}
	// Recombine peeked byte with the rest of the stream
	fullReader := io.MultiReader(bytes.NewReader(buf[:n]), streamReader)

	// 5. Check physical disk capacity
	hasSpace, err := h.storage.HasAvailableDiskSpace(r.ContentLength)
	if err != nil || !hasSpace {
		h.logger.Error("storage quota exceeded", "error", err)
		http.Error(w, "insufficient server storage capacity", http.StatusServiceUnavailable)
		return
	}

	// 6. Generate NanoID and Delete Token
	id, err := util.GenerateID(10)
	if err != nil {
		h.logger.Error("failed to generate NanoID", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	deleteToken, err := util.GenerateDeleteToken()
	if err != nil {
		h.logger.Error("failed to generate delete token", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// 7. Stream payload directly to sharded disk storage
	relPath, writtenSize, _, err := h.storage.SaveStream(ctx, id, fullReader, h.cfg.MaxSecretSizeBytes())
	if err != nil {
		if errors.Is(err, storage.ErrFileTooLarge) {
			http.Error(w, fmt.Sprintf("secret exceeds maximum allowed size of %d MB", h.cfg.MaxSecretSizeMB), http.StatusRequestEntityTooLarge)
			return
		}
		h.logger.Error("failed to save secret stream to disk", "error", err)
		http.Error(w, "failed to persist secret", http.StatusInternalServerError)
		return
	}

	// 8. Record in SQLite Database
	now := time.Now().UTC()
	expiresAt := now.Add(dur).UTC()
	uploaderIP := ClientIP(r, h.cfg.TrustProxy)

	record := &database.SecretRecord{
		ID:           id,
		SizeBytes:    writtenSize,
		StoragePath:  relPath,
		DeleteToken:  deleteToken,
		UploaderIP:   uploaderIP,
		IsBurnOnRead: isBurn,
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
	}

	if err := h.db.InsertSecret(ctx, record); err != nil {
		_ = h.storage.Delete(relPath)
		h.logger.Error("failed to insert secret in database", "error", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	// 9. Format response
	shareURL := fmt.Sprintf("%s/v/%s", h.cfg.BaseURL, id)
	deleteURL := fmt.Sprintf("%s/d/%s", h.cfg.BaseURL, deleteToken)

	w.Header().Set("X-Vault-ID", id)

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "id" || format == "raw" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintln(w, id)
		return
	}
	if format == "url" || format == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintln(w, shareURL)
		return
	}

	// JSON response (default for API / Web)
	resp := VaultResponse{
		ID:           id,
		URL:          shareURL,
		DeleteURL:    deleteURL,
		DeleteToken:  deleteToken,
		SizeBytes:    writtenSize,
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
		IsBurnOnRead: isBurn,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleGetSecret handles GET /api/vault/{id}.
func (h *VaultHandler) HandleGetSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rawID := chi.URLParam(r, "id")
	if rawID == "" {
		http.NotFound(w, r)
		return
	}

	// Clean ID (strip any .enc or .dat extension if accidentally provided)
	id := strings.TrimSuffix(rawID, filepath.Ext(rawID))

	// Fetch metadata from DB
	secret, err := h.db.GetSecret(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Check if this was a burn-after-reading secret already consumed
			isBurned, checkErr := h.db.IsBurnedSecret(ctx, id)
			if checkErr == nil && isBurned {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusGone)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":  "secret has already been burned or destroyed",
					"burned": true,
				})
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "secret not found",
			})
			return
		}
		h.logger.Error("error querying secret metadata", "id", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Handle Burn-After-Reading secret
	if secret.IsBurnOnRead {
		isCLI := isCLICaller(r)
		hasBurnFlag := strings.EqualFold(r.Header.Get("X-Burn"), "true") ||
			r.Header.Get("X-Burn") == "1" ||
			r.URL.Query().Get("burn") == "1" ||
			r.URL.Query().Get("claim") == "1"
		wantsStream := strings.Contains(r.Header.Get("Accept"), "application/octet-stream")

		// If caller is NOT claiming or burning (e.g. browser status query before revealing),
		// return safe metadata without destroying the secret!
		if !isCLI && !hasBurnFlag && !wantsStream {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":              secret.ID,
				"size_bytes":      secret.SizeBytes,
				"is_burn_on_read": true,
				"status":          "pending_reveal",
				"expires_at":      secret.ExpiresAt,
			})
			return
		}

		// Perform atomic claim
		claimed, err := h.db.AtomicClaimBurnSecret(ctx, id)
		if err != nil {
			// Race condition: another concurrent request already claimed it
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusGone)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":  "secret has already been burned",
				"burned": true,
			})
			return
		}

		// Stream single-use payload
		h.streamCiphertext(w, claimed.StoragePath, claimed.SizeBytes, true)

		// Asynchronously unlink from disk storage
		h.cleaner.EnqueueImmediate(claimed.ID, claimed.StoragePath, claimed.SizeBytes)
		return
	}

	// Handle standard (time-based) secret
	_ = h.db.IncrementDownloadCount(ctx, id)
	h.streamCiphertext(w, secret.StoragePath, secret.SizeBytes, false)
}

func (h *VaultHandler) streamCiphertext(w http.ResponseWriter, storagePath string, sizeBytes int64, wasBurned bool) {
	reader, _, err := h.storage.Open(storagePath)
	if err != nil {
		h.logger.Error("failed to open storage file", "path", storagePath, "error", err)
		http.Error(w, "secret file could not be opened", http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", sizeBytes))
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	if wasBurned {
		w.Header().Set("X-Burn-Destroyed", "true")
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, reader)
}

func isCLICaller(r *http.Request) bool {
	ua := strings.ToLower(r.UserAgent())
	return strings.HasPrefix(ua, "curl/") ||
		strings.HasPrefix(ua, "wget/") ||
		strings.HasPrefix(ua, "warpvault/") ||
		strings.Contains(ua, "httpie")
}
