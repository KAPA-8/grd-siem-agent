package buffer

import "github.com/grd-platform/grd-siem-agent/internal/models"

// Buffer provides offline resilience by storing alerts locally
// when the cloud platform is unreachable.
type Buffer interface {
	// Push stores alerts that failed to send.
	Push(alerts []models.AlertImportTemplate, connectionID string) error

	// Pop retrieves and removes up to limit buffered entries (FIFO).
	Pop(limit int) ([]BufferedBatch, error)

	// Len returns the number of buffered entries.
	Len() (int, error)

	// Close cleanly shuts down the buffer.
	Close() error
}

// BufferedBatch is a stored batch of alerts waiting to be retried.
type BufferedBatch struct {
	ConnectionID string
	Alerts       []models.AlertImportTemplate
}
