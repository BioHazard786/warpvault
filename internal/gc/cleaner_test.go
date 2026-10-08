package gc

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"warpvault/internal/database"
	"warpvault/internal/storage"
)

func TestCleanerEnqueueImmediate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "warpvault_gc_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	storeDir := filepath.Join(tmpDir, "storage")
	store, err := storage.NewDiskStorage(storeDir)
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}

	cleaner := NewCleaner(db, store, 1*time.Hour, 2)
	defer cleaner.Stop()

	// Create a dummy secret on disk and in DB
	id := "gcTestSec1"
	payload := []byte("some encrypted data")
	relPath, size, _, err := store.SaveStream(context.Background(), id, bytes.NewReader(payload), 1024)
	if err != nil {
		t.Fatalf("SaveStream failed: %v", err)
	}

	secret := &database.SecretRecord{
		ID:           id,
		SizeBytes:    size,
		StoragePath:  relPath,
		DeleteToken:  "gcdeltoken1",
		UploaderIP:   "127.0.0.1",
		IsBurnOnRead: true,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().Add(1 * time.Hour).UTC(),
	}
	if err := db.InsertSecret(context.Background(), secret); err != nil {
		t.Fatalf("InsertSecret failed: %v", err)
	}

	// Trigger immediate burn enqueue
	cleaner.EnqueueImmediate(id, relPath, size)

	// Wait up to 1 second for async worker to unlink
	var unlinked bool
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		if !store.Exists(relPath) {
			unlinked = true
			break
		}
	}

	if !unlinked {
		t.Errorf("file %s should have been unlinked by GC worker", relPath)
	}

	if cleaner.PurgedCount() == 0 {
		t.Error("expected PurgedCount > 0")
	}
}
