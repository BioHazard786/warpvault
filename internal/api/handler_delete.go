package api

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"warpvault/internal/database"
	"warpvault/internal/gc"
)

// DeleteHandler handles secret deletions via API and browser one-click links.
type DeleteHandler struct {
	db      *database.DB
	cleaner *gc.Cleaner
	logger  *slog.Logger
}

// NewDeleteHandler creates a DeleteHandler instance.
func NewDeleteHandler(db *database.DB, cleaner *gc.Cleaner, l *slog.Logger) *DeleteHandler {
	return &DeleteHandler{
		db:      db,
		cleaner: cleaner,
		logger:  l,
	}
}

// HandleAPIDelete handles DELETE /api/vault/{id}.
func (h *DeleteHandler) HandleAPIDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	token := r.Header.Get("X-Delete-Token")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if token == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "missing delete token (provide via X-Delete-Token header or ?token= query parameter)",
		})
		return
	}

	secret, err := h.db.GetSecret(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "secret not found or already deleted",
			})
			return
		}
		h.logger.Error("error checking secret for deletion", "id", id, "error", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	if subtle.ConstantTimeCompare([]byte(token), []byte(secret.DeleteToken)) != 1 {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "invalid delete token",
		})
		return
	}

	if err := h.db.SoftDeleteByID(ctx, id); err != nil {
		h.logger.Error("error deleting secret record", "id", id, "error", err)
		http.Error(w, "failed to delete secret", http.StatusInternalServerError)
		return
	}

	h.cleaner.EnqueueImmediate(secret.ID, secret.StoragePath, secret.SizeBytes)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "deleted",
		"id":      id,
		"message": "secret permanently destroyed",
	})
}

// HandleBrowserDelete handles GET /d/{token} for 1-click deletion links.
func (h *DeleteHandler) HandleBrowserDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := chi.URLParam(r, "token")
	if token == "" {
		http.NotFound(w, r)
		return
	}

	secret, err := h.db.SoftDeleteByToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.renderDeletionPage(w, r, "Secret Not Found", "This secret has already been deleted, burned, or never existed.", false)
			return
		}
		h.logger.Error("error deleting secret by token", "token", token, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.cleaner.EnqueueImmediate(secret.ID, secret.StoragePath, secret.SizeBytes)
	h.renderDeletionPage(w, r, "Secret Destroyed", "The encrypted secret was permanently deleted from the vault.", true)
}

func (h *DeleteHandler) renderDeletionPage(w http.ResponseWriter, r *http.Request, title, message string, success bool) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if !success {
			w.WriteHeader(http.StatusNotFound)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  title,
			"message": message,
			"success": success,
		})
		return
	}

	statusColor := "#ef4444" // red
	if success {
		statusColor = "#10b981" // emerald
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !success {
		w.WriteHeader(http.StatusNotFound)
	}

	html := `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>` + title + ` — Warpvault</title>
  <style>
    body {
      margin: 0;
      background-color: #09090b;
      color: #fafafa;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #18181b;
      border: 1px solid #27272a;
      border-radius: 12px;
      padding: 32px;
      max-width: 440px;
      width: 90%;
      text-align: center;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    }
    .title {
      font-size: 20px;
      font-weight: 700;
      margin-bottom: 8px;
      color: ` + statusColor + `;
    }
    .message {
      color: #a1a1aa;
      font-size: 14px;
      line-height: 1.5;
      margin-bottom: 24px;
    }
    .btn {
      display: inline-block;
      background: #27272a;
      color: #fafafa;
      text-decoration: none;
      padding: 8px 18px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 500;
      border: 1px solid #3f3f46;
      transition: background 0.15s;
    }
    .btn:hover { background: #3f3f46; }
  </style>
</head>
<body>
  <div class="card">
    <div class="title">` + title + `</div>
    <div class="message">` + message + `</div>
    <a href="/" class="btn">Return to Vault</a>
  </div>
</body>
</html>`

	_, _ = w.Write([]byte(html))
}
