package collector

import (
	"context"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/models"
)

// Collector defines the interface that all SIEM collectors must implement.
// Each SIEM type (QRadar, Stellar Cyber, ...) provides its own implementation.
//
// The agent calls Collect from its main loop and HealthCheck from the
// heartbeat goroutine, but never both at once: the SIEM sees one request at a
// time, and a health check is skipped while a collection is running.
type Collector interface {
	// Name returns the unique identifier for this collector type (e.g., "qradar").
	Name() string

	// Init performs one-time setup: connection validation, API version check, etc.
	// The agent retries it with backoff until it succeeds.
	Init(ctx context.Context) error

	// Collect performs a single poll cycle. It fetches alerts newer than the
	// given checkpoint and returns them already in the platform format,
	// together with the checkpoint to persist once all of them are delivered.
	Collect(ctx context.Context, checkpoint string) (Batch, error)

	// HealthCheck verifies the SIEM is reachable and credentials are valid.
	HealthCheck(ctx context.Context) error

	// Close performs cleanup (close connections, flush state).
	Close() error
}

// Batch is the result of one collection cycle.
type Batch struct {
	// Templates are the alerts to deliver, in the platform format.
	Templates []models.AlertImportTemplate

	// Checkpoint is the checkpoint to persist once every template has been
	// imported. It equals the input checkpoint when nothing new was found.
	Checkpoint string

	// WindowFrom and WindowTo are the bounds of the window that was queried
	// (lower bound = checkpoint or lookback start). They become the sync
	// metadata date_from/date_to, which define the import's period.
	WindowFrom time.Time
	WindowTo   time.Time

	// Fetched is the number of source records read in this cycle (including
	// duplicates and records dropped by filters or mapping errors).
	Fetched int

	// DuplicatesRemoved is the number of records dropped because they were
	// already part of this batch.
	DuplicatesRemoved int
}
