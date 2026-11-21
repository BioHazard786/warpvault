package database

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestDB(t *testing.T) (*DB, func()) {
	tmpDir, err := os.MkdirTemp("", "warpvault_db_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := Open(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to open database: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return db, cleanup
}

func TestDBInsertAndGet(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	secret := &SecretRecord{
		ID:           "testSec1",
		SizeBytes:    128,
		StoragePath:  "te/st/testSec1.enc",
		DeleteToken:  "deltoken123",
		UploaderIP:   "127.0.0.1",
		IsBurnOnRead: false,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC(),
	}

	if err := db.InsertSecret(ctx, secret); err != nil {
		t.Fatalf("InsertSecret failed: %v", err)
	}

	retrieved, err := db.GetSecret(ctx, "testSec1")
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}

	if retrieved.ID != secret.ID {
		t.Errorf("expected ID %s, got %s", secret.ID, retrieved.ID)
	}
	if retrieved.SizeBytes != 128 {
		t.Errorf("expected size 128, got %d", retrieved.SizeBytes)
	}
}

func TestAtomicClaimBurnSecret(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	secret := &SecretRecord{
		ID:           "burnSec1",
		SizeBytes:    256,
		StoragePath:  "bu/rn/burnSec1.enc",
		DeleteToken:  "burntoken456",
		UploaderIP:   "10.0.0.1",
		IsBurnOnRead: true,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().Add(1 * time.Hour).UTC(),
	}

	if err := db.InsertSecret(ctx, secret); err != nil {
		t.Fatalf("InsertSecret failed: %v", err)
	}

	// 1st Claim should succeed
	claimed, err := db.AtomicClaimBurnSecret(ctx, "burnSec1")
	if err != nil {
		t.Fatalf("1st AtomicClaimBurnSecret failed: %v", err)
	}
	if claimed.DownloadCount != 1 {
		t.Errorf("expected download count 1, got %d", claimed.DownloadCount)
	}
	if claimed.DeletedAt == nil {
		t.Error("expected DeletedAt to be set")
	}

	// 2nd Claim must fail with sql.ErrNoRows (already burned!)
	_, err = db.AtomicClaimBurnSecret(ctx, "burnSec1")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows on 2nd claim, got: %v", err)
	}

	// Check IsBurnedSecret
	isBurned, err := db.IsBurnedSecret(ctx, "burnSec1")
	if err != nil {
		t.Fatalf("IsBurnedSecret failed: %v", err)
	}
	if !isBurned {
		t.Error("expected IsBurnedSecret to return true")
	}
}

func TestSoftDeleteByToken(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	secret := &SecretRecord{
		ID:           "delSec1",
		SizeBytes:    512,
		StoragePath:  "de/ls/delSec1.enc",
		DeleteToken:  "tokenToDelete789",
		UploaderIP:   "192.168.1.1",
		IsBurnOnRead: false,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().Add(12 * time.Hour).UTC(),
	}

	if err := db.InsertSecret(ctx, secret); err != nil {
		t.Fatalf("InsertSecret failed: %v", err)
	}

	deleted, err := db.SoftDeleteByToken(ctx, "tokenToDelete789")
	if err != nil {
		t.Fatalf("SoftDeleteByToken failed: %v", err)
	}
	if deleted.DeletedAt == nil {
		t.Error("expected DeletedAt to be set after soft delete")
	}

	// Should not be retrievable anymore
	_, err = db.GetSecret(ctx, "delSec1")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows after soft delete, got: %v", err)
	}
}
