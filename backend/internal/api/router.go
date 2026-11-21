package api

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"golang.org/x/time/rate"

	"github.com/BioHazard786/warpvault/backend/internal/config"
	"github.com/BioHazard786/warpvault/backend/internal/database"
	"github.com/BioHazard786/warpvault/backend/internal/gc"
	"github.com/BioHazard786/warpvault/backend/internal/logger"
	"github.com/BioHazard786/warpvault/backend/internal/storage"
)

// RouterConfig bundles all dependencies needed to configure the HTTP routing engine.
type RouterConfig struct {
	Config   *config.Config
	DB       *database.DB
	Storage  storage.StorageEngine
	Cleaner  *gc.Cleaner
	Logger   *slog.Logger
	StaticFS fs.FS // Embedded SPA build (web/dist); may be empty when the frontend isn't built
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

// writeJSON writes v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// serveErrorPage serves an error as JSON for API callers, else the SPA (which renders the error view).
func serveErrorPage(w http.ResponseWriter, r *http.Request, staticFS fs.FS, statusCode int) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeError(w, statusCode, http.StatusText(statusCode))
		return
	}
	if !serveIndex(w, staticFS, statusCode) {
		http.Error(w, http.StatusText(statusCode), statusCode)
	}
}

// serveIndex writes the SPA's index.html with the given status; the client router picks the view
// from the URL. Returns false when no frontend build is embedded.
func serveIndex(w http.ResponseWriter, staticFS fs.FS, status int) bool {
	if staticFS == nil {
		return false
	}
	page, err := fs.ReadFile(staticFS, "index.html")
	if err != nil {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(status)
	_, _ = w.Write(page)
	return true
}

const installPlaceholder = "__WARPVAULT_SERVER__"

// serverURLPattern is what may be written into the shell script. BaseURL is admin-controlled, but the
// script is piped into `bash`, so anything outside a plain http(s) URL is refused rather than escaped.
var serverURLPattern = regexp.MustCompile(`^https?://[A-Za-z0-9.\-\[\]:]+(/[A-Za-z0-9._~\-/]*)?$`)

// serveInstallScript serves the CLI installer with this server's public URL filled in, so the installed
// CLI already points at it (`curl https://vault.example.com/install.sh | bash`). With an unusable
// BaseURL the placeholder stays and the script simply doesn't save a server.
func serveInstallScript(w http.ResponseWriter, staticFS fs.FS, baseURL string) {
	script, err := fs.ReadFile(staticFS, "install.sh")
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	if serverURLPattern.MatchString(baseURL) {
		script = bytes.ReplaceAll(script, []byte(installPlaceholder), []byte(baseURL))
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(script)
}

// contentSecurityPolicy locks the app down to its own origin. Nothing here loads third-party code, so a
// compromised dependency or an injected tag can't send a secret (or the key in the URL) anywhere else.
// 'unsafe-inline' is for styles only (component libraries set style attributes); scripts stay 'self'.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; manifest-src 'self'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// securityHeaders sets defensive headers on every response. Referrer-Policy matters here: a link's
// path holds the secret's id, and the #key must never leave the page through a Referer.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// NewRouter builds and binds the Chi HTTP handler tree.
func NewRouter(rc *RouterConfig) http.Handler {
	r := chi.NewRouter()

	// 1. Core Middleware
	r.Use(chimw.RequestID)
	r.Use(chimw.GetHead)
	r.Use(securityHeaders)
	r.Use(logger.HTTPMiddleware(rc.Logger, rc.Config.TrustProxy))
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rvr := recover(); rvr != nil {
					if rvr == http.ErrAbortHandler {
						panic(rvr)
					}
					rc.Logger.Error("panic recovered", "error", rvr, "path", r.URL.Path)
					serveErrorPage(w, r, rc.StaticFS, http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	})

	// 2. CORS: no cookies are used, so credentials stay off and "*" is safe.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-Auth-Token", "X-Delete-Token"},
		MaxAge:         300,
	}))

	// 3. In-memory Rate Limiting per IP
	rateLimiter := NewIPRateLimiter(rate.Limit(rc.Config.RateLimitReqPerSec), rc.Config.RateLimitBurst)
	r.Use(RateLimitMiddleware(rateLimiter, rc.Config))

	// 4. Handlers
	vaultHandler := NewVaultHandler(rc.Config, rc.DB, rc.Storage, rc.Cleaner, rc.Logger)
	deleteHandler := NewDeleteHandler(rc.DB, rc.Cleaner, rc.Logger)
	authMw := RequireAuthTokenMiddleware(rc.Config)

	// 5. Vault API
	r.With(authMw).Post("/api/vault", vaultHandler.HandleCreateSecret)
	r.Get("/api/vault/{id}", vaultHandler.HandleGetMeta)
	r.Post("/api/vault/{id}/open", vaultHandler.HandleOpenSecret)
	r.Delete("/api/vault/{id}", deleteHandler.HandleAPIDelete)
	r.Post("/api/destroy/{token}", deleteHandler.HandleDestroyByToken)

	// 6. Health + server info
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := rc.DB.PingContext(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})

	r.Get("/api/info", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		dbUsage, _ := rc.DB.GetTotalStorageUsage(ctx)
		diskSpace, _ := rc.Storage.DiskSpace()
		writeJSON(w, http.StatusOK, map[string]any{
			"service":            "Warpvault",
			"version":            rc.Config.Version,
			"max_secret_size_mb": rc.Config.MaxSecretSizeMB,
			"allowed_expiries":   rc.Config.AllowedExpiries,
			"default_expiry":     rc.Config.DefaultExpiry,
			"auth_required":      rc.Config.AuthToken != "",
			"storage_used_bytes": dbUsage,
			"disk_space":         diskSpace,
			"purged_secrets":     rc.Cleaner.PurgedCount(),
		})
	})

	// 7. Fallbacks
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		serveErrorPage(w, r, rc.StaticFS, http.StatusNotFound)
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	})

	// 8. Embedded SPA: real files as-is; "/", "/about", "/v/*" and "/d/*" get index.html (the client
	// router renders them); anything else the SPA's 404 view.
	if rc.StaticFS != nil {
		r.Get("/install.sh", func(w http.ResponseWriter, r *http.Request) {
			serveInstallScript(w, rc.StaticFS, rc.Config.BaseURL)
		})
		fileServer := http.FileServer(http.FS(rc.StaticFS))
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			path := strings.TrimPrefix(r.URL.Path, "/")
			if path == "" || path == "about" || strings.HasPrefix(path, "v/") || strings.HasPrefix(path, "d/") {
				if !serveIndex(w, rc.StaticFS, http.StatusOK) {
					http.Error(w, "frontend not built", http.StatusNotFound)
				}
				return
			}
			if path != "index.html" && isRegularFile(rc.StaticFS, path) {
				if strings.HasPrefix(path, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				fileServer.ServeHTTP(w, r)
				return
			}
			serveErrorPage(w, r, rc.StaticFS, http.StatusNotFound)
		})
	}

	return r
}
