package buffer

import (
	"sync"

	"github.com/grd-platform/grd-siem-agent/internal/models"
)

// MemoryBuffer implements Buffer in memory. Used when buffer is disabled or
// SQLite is unavailable; its contents are lost when the process exits.
type MemoryBuffer struct {
	mu      sync.Mutex
	nextID  int64
	entries []BufferedBatch
}

// NewMemoryBuffer creates a new in-memory buffer.
func NewMemoryBuffer() *MemoryBuffer {
	return &MemoryBuffer{}
}

func (b *MemoryBuffer) Push(payload models.SyncPayload, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if key != "" {
		kept := b.entries[:0]
		for _, e := range b.entries {
			if e.Key != key {
				kept = append(kept, e)
			}
		}
		b.entries = kept
	}
	b.nextID++
	b.entries = append(b.entries, BufferedBatch{ID: b.nextID, Key: key, Payload: payload})
	return nil
}

func (b *MemoryBuffer) Peek(afterID int64, limit int) ([]BufferedBatch, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var result []BufferedBatch
	for _, e := range b.entries {
		if len(result) >= limit {
			break
		}
		if e.ID > afterID {
			result = append(result, e)
		}
	}
	return result, nil
}

func (b *MemoryBuffer) Ack(id int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, e := range b.entries {
		if e.ID == id {
			b.entries = append(b.entries[:i], b.entries[i+1:]...)
			break
		}
	}
	return nil
}

func (b *MemoryBuffer) Reject(id int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i := range b.entries {
		if b.entries[i].ID == id {
			b.entries[i].Rejections++
			break
		}
	}
	return nil
}

func (b *MemoryBuffer) Len() (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries), nil
}

func (b *MemoryBuffer) Close() error {
	return nil
}
