package api

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/BioHazard786/warpvault/backend/internal/database"
	"github.com/BioHazard786/warpvault/backend/internal/gc"
)

// DeleteHandler handles early secret deletion by the creator.
type DeleteHandler struct {
	db      *database.DB
	cleaner *gc.Cleaner
	logger  *slog.Logger
}

// NewDeleteHandler creates a DeleteHandler instance.
func NewDeleteHandler(db *database.DB, cleaner *gc.Cleaner, l *slog.Logger) *DeleteHandler {
	return &DeleteHandler{db: db, cleaner: cleaner, logger: l}
}

// HandleAPIDelete handles DELETE /api/vault/{id} with the delete token in X-Delete-Token
// (or Authorization: Bearer).
func (h *DeleteHandler) HandleAPIDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	token := r.Header.Get("X-Delete-Token")
	if token == "" {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if token == "" {
		writeError(w, http.StatusBadRequest, "missing delete token (send it in the X-Delete-Token header)")
		return
	}

	secret, err := h.db.GetSecret(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "secret not found or already deleted")
			return
		}
		h.logger.Error("error checking secret for deletion", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}

	if subtle.ConstantTimeCompare([]byte(token), []byte(secret.DeleteToken)) != 1 {
		writeError(w, http.StatusForbidden, "invalid delete token")
		return
	}

	if err := h.db.SoftDeleteByID(ctx, id); err != nil {
		h.logger.Error("error deleting secret record", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete secret")
		return
	}
	h.cleaner.EnqueueImmediate(secret.ID, secret.StoragePath, secret.SizeBytes)

	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": id})
}

// HandleDestroyByToken handles POST /api/destroy/{token}, called by the SPA's /d/{token}
// confirmation page. It is a POST so link scanners opening the delete link can't destroy anything.
func (h *DeleteHandler) HandleDestroyByToken(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	secret, err := h.db.SoftDeleteByToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "secret not found or already deleted")
			return
		}
		h.logger.Error("error deleting secret by token", "error", err) // never log the token
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	h.cleaner.EnqueueImmediate(secret.ID, secret.StoragePath, secret.SizeBytes)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": secret.ID})
}
