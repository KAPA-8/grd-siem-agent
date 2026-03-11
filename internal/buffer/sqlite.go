package buffer

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/models"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// SQLiteBuffer implements Buffer using a local SQLite database.
// Uses modernc.org/sqlite (pure Go, no CGO) for cross-compilation.
type SQLiteBuffer struct {
	db *sql.DB
}

// NewSQLiteBuffer creates a new SQLite buffer at the given path.
func NewSQLiteBuffer(path string) (*SQLiteBuffer, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening buffer database: %w", err)
	}

	// Enable WAL mode for better concurrent read/write performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	// Create table if not exists
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS buffered_alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			connection_id TEXT NOT NULL,
			alerts_json TEXT NOT NULL,
			alert_count INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating buffer table: %w", err)
	}

	if _, err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_buffered_created_at ON buffered_alerts(created_at)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating index: %w", err)
	}

	log.Info().Str("path", path).Msg("SQLite buffer initialized")
	return &SQLiteBuffer{db: db}, nil
}

// Push stores a batch of alerts that failed to send.
func (b *SQLiteBuffer) Push(alerts []models.AlertImportTemplate, connectionID string) error {
	data, err := json.Marshal(alerts)
	if err != nil {
		return fmt.Errorf("marshaling alerts for buffer: %w", err)
	}

	_, err = b.db.Exec(
		"INSERT INTO buffered_alerts (connection_id, alerts_json, alert_count) VALUES (?, ?, ?)",
		connectionID, string(data), len(alerts),
	)
	if err != nil {
		return fmt.Errorf("inserting into buffer: %w", err)
	}

	log.Debug().
		Int("alert_count", len(alerts)).
		Str("connection_id", connectionID).
		Msg("alerts buffered for retry")

	return nil
}

// Pop retrieves and removes up to limit buffered batches (FIFO order).
func (b *SQLiteBuffer) Pop(limit int) ([]BufferedBatch, error) {
	rows, err := b.db.Query(
		"SELECT id, connection_id, alerts_json FROM buffered_alerts ORDER BY created_at ASC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying buffer: %w", err)
	}
	defer rows.Close()

	var batches []BufferedBatch
	var ids []int64

	for rows.Next() {
		var id int64
		var connectionID, alertsJSON string

		if err := rows.Scan(&id, &connectionID, &alertsJSON); err != nil {
			return nil, fmt.Errorf("scanning buffer row: %w", err)
		}

		var alerts []models.AlertImportTemplate
		if err := json.Unmarshal([]byte(alertsJSON), &alerts); err != nil {
			log.Warn().Int64("id", id).Err(err).Msg("corrupted buffer entry, skipping")
			ids = append(ids, id) // Still delete corrupted entries
			continue
		}

		batches = append(batches, BufferedBatch{
			ConnectionID: connectionID,
			Alerts:       alerts,
		})
		ids = append(ids, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating buffer rows: %w", err)
	}

	// Delete popped entries
	for _, id := range ids {
		if _, err := b.db.Exec("DELETE FROM buffered_alerts WHERE id = ?", id); err != nil {
			log.Error().Int64("id", id).Err(err).Msg("failed to delete buffer entry")
		}
	}

	return batches, nil
}

// Len returns the number of buffered entries.
func (b *SQLiteBuffer) Len() (int, error) {
	var count int
	err := b.db.QueryRow("SELECT COUNT(*) FROM buffered_alerts").Scan(&count)
	return count, err
}

// Close closes the database connection.
func (b *SQLiteBuffer) Close() error {
	return b.db.Close()
}
