package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"warpvault"
	"warpvault/internal/api"
	"warpvault/internal/config"
	"warpvault/internal/database"
	"warpvault/internal/gc"
	"warpvault/internal/logger"
	"warpvault/internal/storage"
)

func main() {
	cfg := config.LoadConfig()
	l := logger.Init(cfg.LogLevel, cfg.LogFormat)

	l.Info("starting Warpvault server",
		"port", cfg.Port,
		"base_url", cfg.BaseURL,
		"storage_path", cfg.StoragePath,
		"db_path", cfg.DBPath,
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
	staticFS, err := warpvault.StaticFS()
	if err != nil {
		l.Warn("embedded static assets unavailable", "error", err)
	}

	router := api.NewRouter(&api.RouterConfig{
		Config:   cfg,
		DB:       db,
		Storage:  store,
		Cleaner:  cleaner,
		Logger:   l,
		StaticFS: staticFS,
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
