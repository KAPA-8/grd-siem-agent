package collector

import (
	"context"

	"github.com/grd-platform/grd-siem-agent/internal/models"
)

// Collector defines the interface that all SIEM collectors must implement.
// Each SIEM type (QRadar, Splunk, Sentinel) provides its own implementation.
type Collector interface {
	// Name returns the unique identifier for this collector type (e.g., "qradar").
	Name() string

	// Init performs one-time setup: connection validation, API version check, etc.
	// Called once during agent startup. Should fail fast if SIEM is unreachable.
	Init(ctx context.Context) error

	// Collect performs a single poll cycle. It fetches new/updated alerts since
	// the given checkpoint and returns them in normalized format.
	// Returns: alerts, new checkpoint string, error.
	Collect(ctx context.Context, checkpoint string) ([]models.Alert, string, error)

	// HealthCheck verifies the SIEM is reachable and credentials are valid.
	HealthCheck(ctx context.Context) error

	// Close performs cleanup (close connections, flush state).
	Close() error
}
