package api

import (
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"golang.org/x/time/rate"

	"warpvault/internal/config"
	"warpvault/internal/database"
	"warpvault/internal/gc"
	"warpvault/internal/logger"
	"warpvault/internal/storage"
)

// RouterConfig bundles all dependencies needed to configure the HTTP routing engine.
type RouterConfig struct {
	Config   *config.Config
	DB       *database.DB
	Storage  storage.StorageEngine
	Cleaner  *gc.Cleaner
	Logger   *slog.Logger
	StaticFS fs.FS // Optional embedded filesystem for compiled Astro frontend
}

// isRegularFile returns true if the named file exists in fsys and is not a directory.
func isRegularFile(fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// serveErrorPage serves an error page (HTML if browser request and file exists, JSON if API request).
func serveErrorPage(w http.ResponseWriter, r *http.Request, staticFS fs.FS, statusCode int, pageName string) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": http.StatusText(statusCode),
		})
		return
	}

	if staticFS != nil {
		if f, err := staticFS.Open(pageName); err == nil {
			defer f.Close()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(statusCode)
			_, _ = io.Copy(w, f)
			return
		}
	}

	http.Error(w, http.StatusText(statusCode), statusCode)
}

// NewRouter builds and binds the Chi HTTP handler tree.
func NewRouter(rc *RouterConfig) http.Handler {
	r := chi.NewRouter()

	// 1. Core Middleware
	r.Use(chimw.RequestID)
	r.Use(chimw.GetHead)
	r.Use(logger.HTTPMiddleware(rc.Logger))
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rvr := recover(); rvr != nil {
					if rvr == http.ErrAbortHandler {
						panic(rvr)
					}
					rc.Logger.Error("panic recovered", "error", rvr, "path", r.URL.Path)
					serveErrorPage(w, r, rc.StaticFS, http.StatusInternalServerError, "500.html")
				}
			}()
			next.ServeHTTP(w, r)
		})
	})

	// 2. CORS Policy
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Auth-Token", "X-Expiry", "X-Burn", "X-Delete-Token"},
		ExposedHeaders:   []string{"Link", "Content-Disposition", "X-Vault-ID", "X-Burn-Destroyed"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// 3. In-memory Rate Limiting per IP
	rateLimiter := NewIPRateLimiter(rate.Limit(rc.Config.RateLimitReqPerSec), rc.Config.RateLimitBurst)
	r.Use(RateLimitMiddleware(rateLimiter, rc.Config))

	// 4. Initialize Handlers
	vaultHandler := NewVaultHandler(rc.Config, rc.DB, rc.Storage, rc.Cleaner, rc.Logger)
	deleteHandler := NewDeleteHandler(rc.DB, rc.Cleaner, rc.Logger)

	// Auth middleware for vault creation endpoints
	authMw := RequireAuthTokenMiddleware(rc.Config)

	// 5. Vault Endpoints
	r.With(authMw).Post("/api/vault", vaultHandler.HandleCreateSecret)
	r.With(authMw).Put("/api/vault", vaultHandler.HandleCreateSecret)
	r.Get("/api/vault/{id}", vaultHandler.HandleGetSecret)
	r.Delete("/api/vault/{id}", deleteHandler.HandleAPIDelete)

	// 6. Creator 1-Click Deletion
	r.Get("/d/{token}", deleteHandler.HandleBrowserDelete)

	// 7. Telemetry & Health Info
	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})
	})

	r.Get("/api/info", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		dbUsage, _ := rc.DB.GetTotalStorageUsage(ctx)
		diskSpace, _ := rc.Storage.DiskSpace()

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service":            "Warpvault",
			"version":            "1.0.0",
			"max_secret_size_mb": rc.Config.MaxSecretSizeMB,
			"allowed_expiries":   rc.Config.AllowedExpiries,
			"default_expiry":     rc.Config.DefaultExpiry,
			"auth_required":      rc.Config.AuthToken != "",
			"storage_used_bytes": dbUsage,
			"disk_space":         diskSpace,
			"purged_secrets":     rc.Cleaner.PurgedCount(),
		})
	})

	// 8. Fallback handlers
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		serveErrorPage(w, r, rc.StaticFS, http.StatusNotFound, "404.html")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "method not allowed",
		})
	})

	// 9. Static Frontend Serving (Embedded Astro)
	if rc.StaticFS != nil {
		fileServer := http.FileServer(http.FS(rc.StaticFS))
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			path := strings.TrimPrefix(r.URL.Path, "/")
			if path == "" {
				fileServer.ServeHTTP(w, r)
				return
			}

			// Direct static file match (e.g. "_astro/foo.css", "favicon.svg")
			if isRegularFile(rc.StaticFS, path) {
				if strings.HasPrefix(path, "_astro/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else if strings.HasSuffix(path, ".html") {
					w.Header().Set("Cache-Control", "no-cache")
				}
				fileServer.ServeHTTP(w, r)
				return
			}

			// Route extension match (e.g. "/404" -> "404.html")
			if isRegularFile(rc.StaticFS, path+".html") {
				if path == "404" {
					serveErrorPage(w, r, rc.StaticFS, http.StatusNotFound, "404.html")
					return
				}
				if path == "410" {
					serveErrorPage(w, r, rc.StaticFS, http.StatusGone, "410.html")
					return
				}
				if path == "500" {
					serveErrorPage(w, r, rc.StaticFS, http.StatusInternalServerError, "500.html")
					return
				}
				w.Header().Set("Cache-Control", "no-cache")
				r.URL.Path = "/" + path + ".html"
				fileServer.ServeHTTP(w, r)
				return
			}

			// Subdirectory index match
			if isRegularFile(rc.StaticFS, path+"/index.html") {
				r.URL.Path = "/" + path + "/index.html"
				fileServer.ServeHTTP(w, r)
				return
			}

			// Dynamic /v/{id} web viewer: if /v/ route requested, serve v/index.html or v.html
			if strings.HasPrefix(path, "v/") || path == "v" {
				if isRegularFile(rc.StaticFS, "v/index.html") {
					r.URL.Path = "/v/index.html"
					fileServer.ServeHTTP(w, r)
					return
				}
				if isRegularFile(rc.StaticFS, "v.html") {
					r.URL.Path = "/v.html"
					fileServer.ServeHTTP(w, r)
					return
				}
			}

			// Non-existent path -> 404
			serveErrorPage(w, r, rc.StaticFS, http.StatusNotFound, "404.html")
		})
	}

	return r
}
