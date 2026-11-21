package gc

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BioHazard786/warpvault/backend/internal/database"
	"github.com/BioHazard786/warpvault/backend/internal/storage"
)

// CleanupTask represents a secret scheduled for immediate or deferred unlinking.
type CleanupTask struct {
	ID          string
	StoragePath string
	SizeBytes   int64
	HardDelete  bool
}

// Cleaner coordinates the periodic GC of expired secrets and concurrent async deletion pipelines.
type Cleaner struct {
	db            *database.DB
	storage       storage.StorageEngine
	interval      time.Duration
	taskChan      chan CleanupTask
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	purgedSecrets atomic.Uint64
	purgedBytes   atomic.Uint64
}

// NewCleaner creates a Cleaner instance with a dedicated worker pool.
func NewCleaner(db *database.DB, store storage.StorageEngine, interval time.Duration, workerCount int) *Cleaner {
	if workerCount <= 0 {
		workerCount = 4
	}
	if interval <= 0 {
		interval = 60 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &Cleaner{
		db:       db,
		storage:  store,
		interval: interval,
		taskChan: make(chan CleanupTask, 1024),
		ctx:      ctx,
		cancel:   cancel,
	}

	for i := 0; i < workerCount; i++ {
		c.wg.Add(1)
		go c.workerLoop(i)
	}

	c.wg.Add(1)
	go c.tickerLoop()

	return c
}

// EnqueueImmediate unlinks a secret without making the HTTP request wait in the common case. If the
// queue is full or the cleaner is shutting down it does the work inline, so nothing is dropped and
// nothing sends on a closed channel.
func (c *Cleaner) EnqueueImmediate(id, storagePath string, sizeBytes int64) {
	task := CleanupTask{ID: id, StoragePath: storagePath, SizeBytes: sizeBytes}
	select {
	case <-c.ctx.Done():
		c.processDelete(task)
		return
	default:
	}
	select {
	case c.taskChan <- task:
	default:
		c.processDelete(task)
	}
}

func (c *Cleaner) workerLoop(_ int) {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			for {
				select {
				case task, ok := <-c.taskChan:
					if !ok {
						return
					}
					c.processDelete(task)
				default:
					return
				}
			}
		case task, ok := <-c.taskChan:
			if !ok {
				return
			}
			c.processDelete(task)
		}
	}
}

func (c *Cleaner) processDelete(task CleanupTask) {
	// 1. Unlink from disk
	if task.StoragePath != "" {
		if err := c.storage.Delete(task.StoragePath); err != nil {
			log.Printf("[GC] Warning: error deleting storage file %s: %v", task.StoragePath, err)
		}
	}

	// 2. Metadata handling:
	// If task.HardDelete is true (expired secret), wipe from DB completely.
	// If false (immediate burn unlink), clear storage path and preserve tombstone so IsBurnedSecret returns 410 Gone.
	if task.ID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if task.HardDelete {
			if err := c.db.HardDeleteSecret(ctx, task.ID); err != nil {
				log.Printf("[GC] Error hard deleting secret record %s: %v", task.ID, err)
			}
		} else {
			if err := c.db.ClearStoragePath(ctx, task.ID); err != nil {
				log.Printf("[GC] Error clearing storage path for %s: %v", task.ID, err)
			}
		}
		cancel()
	}

	c.purgedSecrets.Add(1)
	if task.SizeBytes > 0 {
		c.purgedBytes.Add(uint64(task.SizeBytes))
	}
}

func (c *Cleaner) tickerLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.SweepOnce()
		}
	}
}

// SweepOnce runs a single pass of checking and purging expired or soft-deleted secrets.
func (c *Cleaner) SweepOnce() {
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()

	for {
		records, err := c.db.GetExpiredSecrets(ctx, 100)
		if err != nil {
			log.Printf("[GC] Error querying expired secrets: %v", err)
			return
		}
		if len(records) == 0 {
			break
		}

		for _, rec := range records {
			isExpired := !rec.ExpiresAt.IsZero() && !rec.ExpiresAt.After(time.Now().UTC())
			c.processDelete(CleanupTask{
				ID:          rec.ID,
				StoragePath: rec.StoragePath,
				SizeBytes:   rec.SizeBytes,
				HardDelete:  isExpired,
			})
		}

		if len(records) < 100 {
			break
		}
	}
}

// PurgedCount returns the total number of secrets permanently purged.
func (c *Cleaner) PurgedCount() uint64 {
	return c.purgedSecrets.Load()
}

// PurgedBytes returns the total bytes reclaimed.
func (c *Cleaner) PurgedBytes() uint64 {
	return c.purgedBytes.Load()
}

// Stop gracefully terminates the GC workers and flushes remaining queue tasks.
func (c *Cleaner) Stop() {
	c.cancel() // workers drain what is queued, then exit
	c.wg.Wait()
}
