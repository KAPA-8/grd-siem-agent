package buffer

import (
	"sync"

	"github.com/grd-platform/grd-siem-agent/internal/models"
)

// MemoryBuffer implements Buffer using an in-memory slice.
// Used when buffer is disabled or for testing.
type MemoryBuffer struct {
	mu      sync.Mutex
	entries []BufferedBatch
}

// NewMemoryBuffer creates a new in-memory buffer.
func NewMemoryBuffer() *MemoryBuffer {
	return &MemoryBuffer{}
}

func (b *MemoryBuffer) Push(alerts []models.AlertImportTemplate, connectionID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries = append(b.entries, BufferedBatch{
		ConnectionID: connectionID,
		Alerts:       alerts,
	})
	return nil
}

func (b *MemoryBuffer) Pop(limit int) ([]BufferedBatch, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.entries) == 0 {
		return nil, nil
	}

	n := limit
	if n > len(b.entries) {
		n = len(b.entries)
	}

	result := make([]BufferedBatch, n)
	copy(result, b.entries[:n])
	b.entries = b.entries[n:]

	return result, nil
}

func (b *MemoryBuffer) Len() (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries), nil
}

func (b *MemoryBuffer) Close() error {
	return nil
}
