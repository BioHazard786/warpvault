package api

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/BioHazard786/warpvault/backend/internal/config"
	"github.com/BioHazard786/warpvault/backend/internal/database"
	"github.com/BioHazard786/warpvault/backend/internal/gc"
	"github.com/BioHazard786/warpvault/backend/internal/storage"
	"github.com/BioHazard786/warpvault/backend/internal/util"
)

// The server only ever stores opaque blobs (protocol/PROTOCOL.md): version(1) flags(1) salt(16)
// nonce(12) then AES-256-GCM ciphertext+tag(16). It checks the framing so a client that forgot to
// encrypt can't upload plaintext by accident; it can never verify the encryption itself.
const (
	blobVersion   = 0x01
	blobHeaderLen = 1 + 1 + 16 + 12
	blobMinLen    = blobHeaderLen + 16
)

// VaultResponse is returned when a secret is stored.
type VaultResponse struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	DeleteURL   string    `json:"delete_url"`
	DeleteToken string    `json:"delete_token"`
	SizeBytes   int64     `json:"size_bytes"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Burn        bool      `json:"burn"`
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
	return &VaultHandler{cfg: cfg, db: db, storage: store, cleaner: cleaner, logger: l}
}

// HandleCreateSecret handles POST /api/vault: the request body is the encrypted blob.
func (h *VaultHandler) HandleCreateSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit := h.cfg.MaxSecretSizeBytes()
	tooLarge := fmt.Sprintf("secret exceeds maximum allowed size of %d MB", h.cfg.MaxSecretSizeMB)

	if r.ContentLength > limit {
		writeError(w, http.StatusRequestEntityTooLarge, tooLarge)
		return
	}

	dur, isBurn, err := h.cfg.ParseExpiry(r.URL.Query().Get("expiry"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	defer r.Body.Close()

	// Validate the blob header before anything touches the disk.
	header := make([]byte, blobHeaderLen)
	if _, err := io.ReadFull(r.Body, header); err != nil {
		writeError(w, http.StatusBadRequest, "payload is not a warpvault blob (too short)")
		return
	}
	if header[0] != blobVersion || header[1]&^0x01 != 0 {
		writeError(w, http.StatusBadRequest, "payload is not a warpvault blob (bad header); encrypt it client-side first")
		return
	}

	hasSpace, err := h.storage.HasAvailableDiskSpace(r.ContentLength)
	if err != nil {
		h.logger.Error("storage unavailable", "error", err)
		writeError(w, http.StatusServiceUnavailable, "server storage is unavailable")
		return
	}
	if !hasSpace {
		h.logger.Error("storage full", "required_bytes", r.ContentLength)
		writeError(w, http.StatusServiceUnavailable, "insufficient server storage capacity")
		return
	}

	id, err := util.GenerateID(10)
	if err != nil {
		h.logger.Error("failed to generate NanoID", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	deleteToken, err := util.GenerateDeleteToken()
	if err != nil {
		h.logger.Error("failed to generate delete token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Stream the header + rest of the body to sharded disk storage.
	body := io.MultiReader(bytes.NewReader(header), r.Body)
	relPath, written, _, err := h.storage.SaveStream(ctx, id, body, limit)
	if err != nil {
		if errors.Is(err, storage.ErrFileTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, tooLarge)
			return
		}
		h.logger.Error("failed to save secret stream to disk", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to persist secret")
		return
	}
	if written < blobMinLen {
		_ = h.storage.Delete(relPath)
		writeError(w, http.StatusBadRequest, "payload is not a warpvault blob (too short)")
		return
	}

	now := time.Now().UTC()
	record := &database.SecretRecord{
		ID:           id,
		SizeBytes:    written,
		StoragePath:  relPath,
		DeleteToken:  deleteToken,
		UploaderIP:   ClientIP(r, h.cfg.TrustProxy),
		IsBurnOnRead: isBurn,
		CreatedAt:    now,
		ExpiresAt:    now.Add(dur),
	}
	if err := h.db.InsertSecret(ctx, record); err != nil {
		_ = h.storage.Delete(relPath)
		h.logger.Error("failed to insert secret in database", "error", err)
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	writeJSON(w, http.StatusCreated, VaultResponse{
		ID:          id,
		URL:         fmt.Sprintf("%s/v/%s", h.cfg.BaseURL, id),
		DeleteURL:   fmt.Sprintf("%s/d/%s", h.cfg.BaseURL, deleteToken),
		DeleteToken: deleteToken,
		SizeBytes:   written,
		CreatedAt:   now,
		ExpiresAt:   record.ExpiresAt,
		Burn:        isBurn,
	})
}

// lookup finds a live secret. It writes the 404/410/500 response itself and returns nil when the
// secret can't be served. Expired secrets count as gone even before the GC sweep removes them.
func (h *VaultHandler) lookup(w http.ResponseWriter, r *http.Request) *database.SecretRecord {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	secret, err := h.db.GetSecret(ctx, id)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			h.logger.Error("error querying secret metadata", "id", id, "error", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return nil
		}
		if burned, checkErr := h.db.IsBurnedSecret(ctx, id); checkErr == nil && burned {
			writeJSON(w, http.StatusGone, map[string]any{"error": "secret has already been burned or destroyed", "burned": true})
			return nil
		}
		writeError(w, http.StatusNotFound, "secret not found")
		return nil
	}
	if !secret.ExpiresAt.After(time.Now()) {
		writeError(w, http.StatusNotFound, "secret not found")
		return nil
	}
	return secret
}

// HandleGetMeta handles GET /api/vault/{id}. It never returns the ciphertext and never burns.
func (h *VaultHandler) HandleGetMeta(w http.ResponseWriter, r *http.Request) {
	secret := h.lookup(w, r)
	if secret == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         secret.ID,
		"size_bytes": secret.SizeBytes,
		"burn":       secret.IsBurnOnRead,
		"passphrase": h.hasPassphrase(secret.StoragePath),
		"expires_at": secret.ExpiresAt,
	})
}

// hasPassphrase reads the blob's flags byte (a public header field) so the viewer can ask for the
// passphrase before it opens, and thereby burns, a single-use secret.
func (h *VaultHandler) hasPassphrase(storagePath string) bool {
	f, _, err := h.storage.Open(storagePath)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [2]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return hdr[1]&0x01 != 0
}

// HandleOpenSecret handles POST /api/vault/{id}/open: streams the ciphertext and, for
// burn-after-reading secrets, atomically claims it. POST (never GET) so link previews, crawlers and
// prefetchers can't burn a secret.
func (h *VaultHandler) HandleOpenSecret(w http.ResponseWriter, r *http.Request) {
	secret := h.lookup(w, r)
	if secret == nil {
		return
	}

	if secret.IsBurnOnRead {
		claimed, err := h.db.AtomicClaimBurnSecret(r.Context(), secret.ID)
		if err != nil {
			// Lost the race: another request claimed it first.
			writeJSON(w, http.StatusGone, map[string]any{"error": "secret has already been burned or destroyed", "burned": true})
			return
		}
		h.streamCiphertext(w, claimed.StoragePath, claimed.SizeBytes, true)
		h.cleaner.EnqueueImmediate(claimed.ID, claimed.StoragePath, claimed.SizeBytes)
		return
	}

	_ = h.db.IncrementDownloadCount(r.Context(), secret.ID)
	h.streamCiphertext(w, secret.StoragePath, secret.SizeBytes, false)
}

func (h *VaultHandler) streamCiphertext(w http.ResponseWriter, storagePath string, sizeBytes int64, wasBurned bool) {
	reader, _, err := h.storage.Open(storagePath)
	if err != nil {
		h.logger.Error("failed to open storage file", "path", storagePath, "error", err)
		writeError(w, http.StatusInternalServerError, "secret file could not be opened")
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", sizeBytes))
	w.Header().Set("Cache-Control", "no-store")
	if wasBurned {
		w.Header().Set("X-Burn-Destroyed", "true")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, reader)
}
