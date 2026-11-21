package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// SecretRecord models a confidential vault secret stored in the database.
type SecretRecord struct {
	ID            string     `json:"id"`
	SizeBytes     int64      `json:"size_bytes"`
	StoragePath   string     `json:"storage_path"`
	DeleteToken   string     `json:"delete_token"`
	UploaderIP    string     `json:"uploader_ip"`
	IsBurnOnRead  bool       `json:"is_burn_on_read"`
	DownloadCount int        `json:"download_count"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
}

// DB encapsulates the SQLite database connection and operations.
type DB struct {
	db             *sql.DB
	usageMu        sync.RWMutex
	cachedUsage    int64
	usageCacheTime time.Time
}

// Open initializes SQLite in WAL mode with connection pooling and executes schema migrations.
func Open(dbPath string) (*DB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory %s: %w", dir, err)
	}

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", dbPath)
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// SQLite WAL mode supports multiple concurrent readers and 1 writer
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	db := &DB{db: sqlDB}
	if err := db.migrate(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("failed to run database migrations: %w", err)
	}

	return db, nil
}

// PingContext verifies the database connection is alive.
func (db *DB) PingContext(ctx context.Context) error {
	return db.db.PingContext(ctx)
}

// Close closes the underlying database connection.
func (db *DB) Close() error {
	return db.db.Close()
}

func (db *DB) migrate() error {
	query := `
	CREATE TABLE IF NOT EXISTS secrets (
		id TEXT PRIMARY KEY,
		size_bytes INTEGER NOT NULL,
		storage_path TEXT NOT NULL,
		delete_token TEXT NOT NULL UNIQUE,
		uploader_ip TEXT NOT NULL,
		is_burn_on_read INTEGER NOT NULL DEFAULT 1,
		download_count INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		deleted_at DATETIME
	);

	CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets(expires_at) WHERE deleted_at IS NULL;
	CREATE INDEX IF NOT EXISTS idx_secrets_gc ON secrets(deleted_at) WHERE storage_path != '';
	`
	_, err := db.db.Exec(query)
	return err
}

// InsertSecret stores secret metadata in the database.
func (db *DB) InsertSecret(ctx context.Context, s *SecretRecord) error {
	query := `
	INSERT INTO secrets (
		id, size_bytes, storage_path, delete_token, uploader_ip,
		is_burn_on_read, download_count, created_at, expires_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.db.ExecContext(ctx, query,
		s.ID,
		s.SizeBytes,
		s.StoragePath,
		s.DeleteToken,
		s.UploaderIP,
		s.IsBurnOnRead,
		s.DownloadCount,
		s.CreatedAt.UTC(),
		s.ExpiresAt.UTC(),
	)
	if err == nil {
		db.invalidateUsageCache()
	}
	return err
}

// GetSecret retrieves an active secret by its ID.
func (db *DB) GetSecret(ctx context.Context, id string) (*SecretRecord, error) {
	query := `
	SELECT id, size_bytes, storage_path, delete_token, uploader_ip,
	       is_burn_on_read, download_count, created_at, expires_at, deleted_at
	FROM secrets
	WHERE id = ? AND deleted_at IS NULL
	`
	row := db.db.QueryRowContext(ctx, query, id)
	return scanSecretRecord(row)
}

// GetSecretByDeleteToken finds a secret by its unique deletion secret token.
func (db *DB) GetSecretByDeleteToken(ctx context.Context, token string) (*SecretRecord, error) {
	query := `
	SELECT id, size_bytes, storage_path, delete_token, uploader_ip,
	       is_burn_on_read, download_count, created_at, expires_at, deleted_at
	FROM secrets
	WHERE delete_token = ? AND deleted_at IS NULL
	`
	row := db.db.QueryRowContext(ctx, query, token)
	return scanSecretRecord(row)
}

// AtomicClaimBurnSecret performs a race-condition-proof claim on a one-time burn-after-reading secret.
// If the secret is burn-on-read and has never been retrieved, it atomically marks it as downloaded
// and sets deleted_at to current timestamp, returning the secret record.
// If it was already downloaded, deleted, or does not exist, returns sql.ErrNoRows.
func (db *DB) AtomicClaimBurnSecret(ctx context.Context, id string) (*SecretRecord, error) {
	query := `
	UPDATE secrets
	SET download_count = download_count + 1,
	    deleted_at = CURRENT_TIMESTAMP
	WHERE id = ?
	  AND is_burn_on_read = 1
	  AND download_count = 0
	  AND deleted_at IS NULL
	RETURNING id, size_bytes, storage_path, delete_token, uploader_ip,
	          is_burn_on_read, download_count, created_at, expires_at, deleted_at
	`
	row := db.db.QueryRowContext(ctx, query, id)
	return scanSecretRecord(row)
}

// IsBurnedSecret checks if a secret with the given ID existed as a burn-on-read secret
// and has already been downloaded or deleted.
func (db *DB) IsBurnedSecret(ctx context.Context, id string) (bool, error) {
	query := `SELECT 1 FROM secrets WHERE id = ? AND is_burn_on_read = 1 AND (deleted_at IS NOT NULL OR download_count > 0)`
	var exists int
	err := db.db.QueryRowContext(ctx, query, id).Scan(&exists)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// IncrementDownloadCount increments the download counter for a non-burn secret.
func (db *DB) IncrementDownloadCount(ctx context.Context, id string) error {
	query := `UPDATE secrets SET download_count = download_count + 1 WHERE id = ? AND deleted_at IS NULL`
	_, err := db.db.ExecContext(ctx, query, id)
	return err
}

// SoftDeleteByToken marks a secret as deleted using its delete token and returns its storage path.
func (db *DB) SoftDeleteByToken(ctx context.Context, token string) (*SecretRecord, error) {
	query := `
	UPDATE secrets
	SET deleted_at = CURRENT_TIMESTAMP
	WHERE delete_token = ? AND deleted_at IS NULL
	RETURNING id, size_bytes, storage_path, delete_token, uploader_ip,
	          is_burn_on_read, download_count, created_at, expires_at, deleted_at
	`
	row := db.db.QueryRowContext(ctx, query, token)
	return scanSecretRecord(row)
}

// SoftDeleteByID marks a secret as deleted by ID.
func (db *DB) SoftDeleteByID(ctx context.Context, id string) error {
	query := `UPDATE secrets SET deleted_at = CURRENT_TIMESTAMP WHERE id = ? AND deleted_at IS NULL`
	res, err := db.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetExpiredSecrets returns a batch of secrets ready to be physically purged by the GC worker.
func (db *DB) GetExpiredSecrets(ctx context.Context, limit int) ([]*SecretRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `
	SELECT id, size_bytes, storage_path, delete_token, uploader_ip,
	       is_burn_on_read, download_count, created_at, expires_at, deleted_at
	FROM secrets
	WHERE expires_at <= CURRENT_TIMESTAMP
	   OR (deleted_at IS NOT NULL AND storage_path != '')
	LIMIT ?
	`
	rows, err := db.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*SecretRecord
	for rows.Next() {
		s := &SecretRecord{}
		var deletedAt sql.NullTime
		var createdAt, expiresAt time.Time

		err := rows.Scan(
			&s.ID,
			&s.SizeBytes,
			&s.StoragePath,
			&s.DeleteToken,
			&s.UploaderIP,
			&s.IsBurnOnRead,
			&s.DownloadCount,
			&createdAt,
			&expiresAt,
			&deletedAt,
		)
		if err != nil {
			return nil, err
		}
		s.CreatedAt = createdAt
		s.ExpiresAt = expiresAt
		if deletedAt.Valid {
			s.DeletedAt = &deletedAt.Time
		}
		records = append(records, s)
	}

	return records, rows.Err()
}

func (db *DB) invalidateUsageCache() {
	db.usageMu.Lock()
	db.usageCacheTime = time.Time{}
	db.usageMu.Unlock()
}

// HardDeleteSecret permanently deletes the secret record from the database.
func (db *DB) HardDeleteSecret(ctx context.Context, id string) error {
	query := `DELETE FROM secrets WHERE id = ?`
	_, err := db.db.ExecContext(ctx, query, id)
	if err == nil {
		db.invalidateUsageCache()
	}
	return err
}

// ClearStoragePath clears the on-disk storage path and preserves the tombstone.
func (db *DB) ClearStoragePath(ctx context.Context, id string) error {
	query := `UPDATE secrets SET storage_path = '', deleted_at = COALESCE(deleted_at, CURRENT_TIMESTAMP) WHERE id = ?`
	_, err := db.db.ExecContext(ctx, query, id)
	if err == nil {
		db.invalidateUsageCache()
	}
	return err
}

// GetTotalStorageUsage calculates the sum of all active secrets in bytes with a 10s TTL cache.
func (db *DB) GetTotalStorageUsage(ctx context.Context) (int64, error) {
	db.usageMu.RLock()
	if time.Since(db.usageCacheTime) < 10*time.Second {
		val := db.cachedUsage
		db.usageMu.RUnlock()
		return val, nil
	}
	db.usageMu.RUnlock()

	db.usageMu.Lock()
	defer db.usageMu.Unlock()

	if time.Since(db.usageCacheTime) < 10*time.Second {
		return db.cachedUsage, nil
	}

	query := `SELECT COALESCE(SUM(size_bytes), 0) FROM secrets WHERE deleted_at IS NULL`
	var total int64
	err := db.db.QueryRowContext(ctx, query).Scan(&total)
	if err == nil {
		db.cachedUsage = total
		db.usageCacheTime = time.Now()
	}
	return total, err
}

type scannable interface {
	Scan(dest ...any) error
}

func scanSecretRecord(s scannable) (*SecretRecord, error) {
	rec := &SecretRecord{}
	var deletedAt sql.NullTime
	var createdAt, expiresAt time.Time

	err := s.Scan(
		&rec.ID,
		&rec.SizeBytes,
		&rec.StoragePath,
		&rec.DeleteToken,
		&rec.UploaderIP,
		&rec.IsBurnOnRead,
		&rec.DownloadCount,
		&createdAt,
		&expiresAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}

	rec.CreatedAt = createdAt
	rec.ExpiresAt = expiresAt
	if deletedAt.Valid {
		rec.DeletedAt = &deletedAt.Time
	}

	return rec, nil
}

// ExecForTest runs a raw statement; tests use it to age rows without waiting.
func (db *DB) ExecForTest(query string, args ...any) (sql.Result, error) {
	return db.db.Exec(query, args...)
}
