package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var (
	// ErrFileTooLarge is returned when the uploaded stream exceeds the configured byte limit.
	ErrFileTooLarge = errors.New("secret payload exceeds maximum allowed size")

	// 64KB buffer pool for high-throughput streaming with minimal heap allocations.
	bufferPool = sync.Pool{
		New: func() any {
			b := make([]byte, 64*1024)
			return &b
		},
	}
)

// StorageEngine defines the contract for persisting, reading, and deleting encrypted blobs.
type StorageEngine interface {
	SaveStream(ctx context.Context, id string, r io.Reader, maxBytes int64) (relPath string, size int64, sha256Hex string, err error)
	Open(relPath string) (io.ReadSeekCloser, os.FileInfo, error)
	Delete(relPath string) error
	Exists(relPath string) bool
	DiskUsage() (int64, error)
	DiskSpace() (DiskSpaceInfo, error)
	HasAvailableDiskSpace(bytesRequired int64) (bool, error)
}

// DiskStorage implements StorageEngine using a 2-level sharded directory structure.
type DiskStorage struct {
	baseDir string
}

// NewDiskStorage creates and initializes a DiskStorage instance.
func NewDiskStorage(baseDir string) (*DiskStorage, error) {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("invalid storage path: %w", err)
	}

	if err := os.MkdirAll(absBase, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory %s: %w", absBase, err)
	}

	return &DiskStorage{baseDir: absBase}, nil
}

// shardPath calculates the 2-level directory shard for an ID.
// For example: "k8X2mP9z" -> relDir: "k8/X2", relFile: "k8/X2/k8X2mP9z.enc"
func (s *DiskStorage) shardPath(id string) (relDir, relFile string) {
	if len(id) >= 4 {
		relDir = filepath.Join(id[0:2], id[2:4])
	} else if len(id) >= 2 {
		relDir = id[0:2]
	} else {
		relDir = "misc"
	}
	relFile = filepath.Join(relDir, id+".enc")
	return relDir, relFile
}

// SaveStream streams directly from an io.Reader to disk with zero heap memory buffering,
// computing SHA-256 hash on-the-fly and enforcing size limits.
func (s *DiskStorage) SaveStream(ctx context.Context, id string, r io.Reader, maxBytes int64) (string, int64, string, error) {
	relDir, relFile := s.shardPath(id)
	targetDir := filepath.Join(s.baseDir, relDir)

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return "", 0, "", fmt.Errorf("failed to create shard directory: %w", err)
	}

	// Create temporary file in the same directory for atomic rename
	tmpFile, err := os.CreateTemp(targetDir, fmt.Sprintf("tmp_%s_*", id))
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	var renameSuccess bool
	defer func() {
		if !renameSuccess {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	tee := io.TeeReader(r, hasher)

	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)

	var written int64
	for {
		select {
		case <-ctx.Done():
			return "", 0, "", ctx.Err()
		default:
		}

		nr, readErr := tee.Read(*bufPtr)
		if nr > 0 {
			written += int64(nr)
			if maxBytes > 0 && written > maxBytes {
				return "", 0, "", ErrFileTooLarge
			}

			nw, writeErr := tmpFile.Write((*bufPtr)[:nr])
			if writeErr != nil {
				return "", 0, "", fmt.Errorf("write error: %w", writeErr)
			}
			if nw != nr {
				return "", 0, "", io.ErrShortWrite
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return "", 0, "", fmt.Errorf("read error: %w", readErr)
		}
	}

	if err := tmpFile.Sync(); err != nil {
		return "", 0, "", fmt.Errorf("failed to sync temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", 0, "", fmt.Errorf("failed to close temp file: %w", err)
	}

	finalPath := filepath.Join(s.baseDir, relFile)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", 0, "", fmt.Errorf("failed to commit file: %w", err)
	}

	renameSuccess = true
	shaHex := hex.EncodeToString(hasher.Sum(nil))

	return relFile, written, shaHex, nil
}

// Open retrieves a readable and seekable stream for a stored ciphertext file.
func (s *DiskStorage) Open(relPath string) (io.ReadSeekCloser, os.FileInfo, error) {
	cleanRel := filepath.Clean(relPath)
	absPath := filepath.Join(s.baseDir, cleanRel)

	f, err := os.Open(absPath)
	if err != nil {
		return nil, nil, err
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}

	return f, info, nil
}

// Delete permanently removes the file and cleans up parent shard directories if empty.
func (s *DiskStorage) Delete(relPath string) error {
	cleanRel := filepath.Clean(relPath)
	absPath := filepath.Join(s.baseDir, cleanRel)

	if err := os.Remove(absPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Try removing empty parent directories up to baseDir
	parent := filepath.Dir(absPath)
	for parent != s.baseDir && len(parent) > len(s.baseDir) {
		if err := os.Remove(parent); err != nil {
			break
		}
		parent = filepath.Dir(parent)
	}

	return nil
}

// Exists checks if the file exists on disk.
func (s *DiskStorage) Exists(relPath string) bool {
	cleanRel := filepath.Clean(relPath)
	absPath := filepath.Join(s.baseDir, cleanRel)
	_, err := os.Stat(absPath)
	return err == nil
}

// DiskUsage calculates total size of files stored in the storage directory.
func (s *DiskStorage) DiskUsage() (int64, error) {
	var totalSize int64
	err := filepath.Walk(s.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	return totalSize, err
}

// HasAvailableDiskSpace verifies if the physical filesystem has sufficient capacity.
func (s *DiskStorage) HasAvailableDiskSpace(bytesRequired int64) (bool, error) {
	// The directory may have been removed while the server runs (a wiped volume, a stray rm -rf):
	// recreate it so uploads keep working instead of failing the capacity check forever.
	if err := os.MkdirAll(s.baseDir, 0755); err != nil {
		return false, fmt.Errorf("storage directory %s is unavailable: %w", s.baseDir, err)
	}
	space, err := s.DiskSpace()
	if err != nil {
		return false, err
	}
	if space.AvailableBytes <= DefaultSafetyReserveBytes {
		return false, nil
	}
	remaining := space.AvailableBytes - DefaultSafetyReserveBytes
	if bytesRequired <= 0 {
		return remaining > 0, nil
	}
	return remaining >= uint64(bytesRequired), nil
}
