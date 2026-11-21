package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/BioHazard786/warpvault/backend/internal/api"
	"github.com/BioHazard786/warpvault/backend/internal/config"
	"github.com/BioHazard786/warpvault/backend/internal/database"
	"github.com/BioHazard786/warpvault/backend/internal/gc"
	"github.com/BioHazard786/warpvault/backend/internal/logger"
	"github.com/BioHazard786/warpvault/backend/internal/storage"
	"github.com/BioHazard786/warpvault/backend/web"
)

func main() {
	cfg := config.LoadConfig()
	if cfg.HealthCheck {
		os.Exit(healthcheck(cfg.Port))
	}
	l := logger.Init(cfg.LogLevel, cfg.LogFormat)

	l.Info("starting Warpvault server",
		"version", cfg.Version,
		"port", cfg.Port,
		"base_url", cfg.BaseURL,
		"storage_path", absPath(cfg.StoragePath),
		"db_path", absPath(cfg.DBPath),
		"max_secret_size_mb", cfg.MaxSecretSizeMB,
		"default_expiry", cfg.DefaultExpiry,
		"auth_enabled", cfg.AuthToken != "",
	)

	// 1. Initialize SQLite Database (WAL mode, pure Go)
	db, err := database.Open(cfg.DBPath)
	if err != nil {
		l.Error("failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// 2. Initialize Sharded Storage Engine
	store, err := storage.NewDiskStorage(cfg.StoragePath)
	if err != nil {
		l.Error("failed to initialize storage engine", "error", err)
		os.Exit(1)
	}

	// 3. Start Background Garbage Collection and Unlink Pipeline
	cleaner := gc.NewCleaner(db, store, cfg.GCInterval, 4)
	defer cleaner.Stop()

	// 4. Build HTTP Router with Embedded Static Frontend
	router := api.NewRouter(&api.RouterConfig{
		Config:   cfg,
		DB:       db,
		Storage:  store,
		Cleaner:  cleaner,
		Logger:   l,
		StaticFS: web.FS(),
	})

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		l.Info(fmt.Sprintf("Warpvault listening on http://localhost:%s", cfg.Port))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.Error("HTTP server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-stopChan
	l.Info("shutting down Warpvault server gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		l.Error("graceful shutdown failed", "error", err)
	}

	l.Info("server shutdown complete")
}

// healthcheck asks the server on this host for /healthz. The runtime image has no curl or shell,
// so Docker's HEALTHCHECK runs the binary itself. Returns the process exit code.
func healthcheck(port string) int {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy: HTTP", resp.StatusCode)
		return 1
	}
	return 0
}

// absPath resolves a configured path against the working directory, so the startup log shows where
// the data really lives.
func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}
