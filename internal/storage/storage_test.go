package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestStorageSaveAndRead(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "warpvault_storage_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := NewDiskStorage(tmpDir)
	if err != nil {
		t.Fatalf("failed to create DiskStorage: %v", err)
	}

	payload := []byte("encrypted_secret_data_stream_123456789")
	id := "testSecretID"

	relPath, size, shaHex, err := store.SaveStream(context.Background(), id, bytes.NewReader(payload), 1024*1024)
	if err != nil {
		t.Fatalf("SaveStream failed: %v", err)
	}

	if size != int64(len(payload)) {
		t.Errorf("expected size %d, got %d", len(payload), size)
	}
	if shaHex == "" {
		t.Error("expected non-empty shaHex")
	}

	if !store.Exists(relPath) {
		t.Errorf("file %s should exist", relPath)
	}

	r, info, err := store.Open(relPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer r.Close()

	if info.Size() != int64(len(payload)) {
		t.Errorf("expected file size %d, got %d", len(payload), info.Size())
	}

	readBack, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if !bytes.Equal(payload, readBack) {
		t.Errorf("data mismatch: expected %q, got %q", payload, readBack)
	}

	// Test Delete
	if err := store.Delete(relPath); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if store.Exists(relPath) {
		t.Errorf("file %s should not exist after delete", relPath)
	}
}

func TestStorageFileTooLarge(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "warpvault_storage_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := NewDiskStorage(tmpDir)
	if err != nil {
		t.Fatalf("failed to create DiskStorage: %v", err)
	}

	payload := make([]byte, 1024)
	id := "largeSecret"

	// maxBytes = 500 bytes (payload is 1024 bytes)
	_, _, _, err = store.SaveStream(context.Background(), id, bytes.NewReader(payload), 500)
	if err != ErrFileTooLarge {
		t.Fatalf("expected ErrFileTooLarge, got: %v", err)
	}

	// Verify temp file was cleaned up
	relDir, _ := store.shardPath(id)
	files, _ := os.ReadDir(filepath.Join(tmpDir, relDir))
	if len(files) != 0 {
		t.Errorf("expected temp file to be deleted on error, found %d files", len(files))
	}
}
