package buffer

import (
	"strings"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/models"
)

// Buffer provides offline resilience by storing sync payloads locally when
// the cloud platform is unreachable.
//
// Delivery is at-least-once: Peek does not remove anything, and a batch is
// removed with Ack only after the platform accepted it. A crash or restart
// between Peek and Ack sends the batch again; the platform deduplicates
// alerts on (connection, externalId).
type Buffer interface {
	// Push stores a payload, including its sync metadata. When key is not
	// empty, a batch already stored under the same key is replaced in the
	// same transaction (the agent keys batches by checkpoint and chunk, so a
	// re-collected window does not pile up copies during an outage).
	Push(payload models.SyncPayload, key string) error

	// Peek returns up to limit batches with ID greater than afterID, oldest
	// first, without removing them.
	Peek(afterID int64, limit int) ([]BufferedBatch, error)

	// Ack removes a delivered batch. Acknowledging an unknown ID is a no-op.
	Ack(id int64) error

	// Reject records that the platform refused a batch (a permanent 4xx or a
	// partial import) without removing it; Peek reports the count, so the
	// caller can drop a batch that keeps being refused. Rejecting an unknown
	// ID is a no-op.
	Reject(id int64) error

	// Len returns the number of buffered batches.
	Len() (int, error)

	// Close cleanly shuts down the buffer.
	Close() error
}

// BufferedBatch is a stored payload waiting to be delivered.
type BufferedBatch struct {
	ID      int64
	Key     string
	Payload models.SyncPayload
	// Rejections is how many times the platform refused this batch.
	Rejections int
}

// DeriveMetadata rebuilds sync metadata for batches stored without it (rows
// written by agents before metadata was persisted): the date range spans the
// alerts' dates, falling back to the time the batch was stored.
func DeriveMetadata(alerts []models.AlertImportTemplate, storedAt time.Time) models.SyncMetadata {
	var minDate, maxDate time.Time
	for _, a := range alerts {
		date, ok := parseAlertDate(a.AlertDate)
		if !ok {
			continue
		}
		if minDate.IsZero() || date.Before(minDate) {
			minDate = date
		}
		if maxDate.IsZero() || date.After(maxDate) {
			maxDate = date
		}
	}
	if minDate.IsZero() {
		if storedAt.IsZero() {
			storedAt = time.Now()
		}
		day := storedAt.UTC().Truncate(24 * time.Hour)
		minDate, maxDate = day, day
	}
	return models.SyncMetadata{
		DateFrom:         minDate.UTC().Format(time.RFC3339),
		DateTo:           maxDate.UTC().Add(24*time.Hour - time.Second).Format(time.RFC3339),
		TotalFetched:     len(alerts),
		TotalAfterFilter: len(alerts),
	}
}

// parseAlertDate accepts YYYY-MM-DD or a full RFC 3339 timestamp and returns
// the UTC calendar day.
func parseAlertDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC().Truncate(24 * time.Hour), true
	}
	return time.Time{}, false
}
