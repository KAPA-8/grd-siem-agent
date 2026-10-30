package buffer

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/models"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// schemaVersion is stored in PRAGMA user_version.
//
//	0/1: buffered_alerts(id, connection_id, alerts_json, alert_count, created_at)
//	2:   + metadata_json (the batch's SyncMetadata) and dedupe_key
const schemaVersion = 2

// SQLiteBuffer implements Buffer using a local SQLite database.
// Uses modernc.org/sqlite (pure Go, no CGO) for cross-compilation.
type SQLiteBuffer struct {
	db *sql.DB
}

// NewSQLiteBuffer opens (or creates) the buffer at path and migrates older
// schemas.
func NewSQLiteBuffer(path string) (*SQLiteBuffer, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening buffer database: %w", err)
	}
	// One connection: the agent uses the buffer sequentially, and a single
	// connection rules out SQLITE_BUSY between pooled connections.
	db.SetMaxOpenConns(1)

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	log.Info().Str("path", path).Msg("SQLite buffer initialized")
	return &SQLiteBuffer{db: db}, nil
}

func initSchema(db *sql.DB) error {
	// Enable WAL mode for better crash safety and concurrent reads.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return fmt.Errorf("setting WAL mode: %w", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS buffered_alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			connection_id TEXT NOT NULL,
			alerts_json TEXT NOT NULL,
			alert_count INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("creating buffer table: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_buffered_created_at ON buffered_alerts(created_at)`); err != nil {
		return fmt.Errorf("creating index: %w", err)
	}

	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("reading buffer schema version: %w", err)
	}
	if version >= schemaVersion {
		return nil
	}
	return migrate(db)
}

// migrate adds the metadata and dedupe key columns and backfills the
// metadata of existing rows from their alerts, in one transaction.
func migrate(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("starting buffer migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	columns, err := tableColumns(tx)
	if err != nil {
		return err
	}
	for _, col := range []string{"metadata_json", "dedupe_key"} {
		if !columns[col] {
			if _, err := tx.Exec("ALTER TABLE buffered_alerts ADD COLUMN " + col + " TEXT"); err != nil {
				return fmt.Errorf("adding column %s: %w", col, err)
			}
		}
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_buffered_dedupe_key ON buffered_alerts(dedupe_key)`); err != nil {
		return fmt.Errorf("creating dedupe key index: %w", err)
	}

	type legacyRow struct {
		id        int64
		alerts    string
		createdAt sql.NullString
	}
	rows, err := tx.Query("SELECT id, alerts_json, created_at FROM buffered_alerts WHERE metadata_json IS NULL ORDER BY id")
	if err != nil {
		return fmt.Errorf("reading rows to migrate: %w", err)
	}
	var legacy []legacyRow
	for rows.Next() {
		var r legacyRow
		if err := rows.Scan(&r.id, &r.alerts, &r.createdAt); err != nil {
			rows.Close()
			return fmt.Errorf("scanning row to migrate: %w", err)
		}
		legacy = append(legacy, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating rows to migrate: %w", err)
	}

	for _, r := range legacy {
		alerts, err := decodeAlerts(r.alerts)
		if err != nil {
			continue // left for Peek, which drops corrupt rows
		}
		meta := DeriveMetadata(alerts, parseSQLiteTime(r.createdAt.String))
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("encoding migrated metadata: %w", err)
		}
		if _, err := tx.Exec("UPDATE buffered_alerts SET metadata_json = ? WHERE id = ?", string(metaJSON), r.id); err != nil {
			return fmt.Errorf("migrating row %d: %w", r.id, err)
		}
	}

	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("setting buffer schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing buffer migration: %w", err)
	}
	if len(legacy) > 0 {
		log.Info().Int("rows", len(legacy)).Msg("buffer migrated: metadata derived for existing batches")
	}
	return nil
}

func tableColumns(tx *sql.Tx) (map[string]bool, error) {
	rows, err := tx.Query("PRAGMA table_info(buffered_alerts)")
	if err != nil {
		return nil, fmt.Errorf("reading buffer columns: %w", err)
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var (
			cid       int
			name, typ string
			notNull   int
			dflt      sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, fmt.Errorf("scanning buffer columns: %w", err)
		}
		columns[name] = true
	}
	return columns, rows.Err()
}

// parseSQLiteTime parses CURRENT_TIMESTAMP values (UTC).
func parseSQLiteTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// decodeAlerts decodes alerts keeping numbers in rawData exact.
func decodeAlerts(data string) ([]models.AlertImportTemplate, error) {
	dec := json.NewDecoder(bytes.NewReader([]byte(data)))
	dec.UseNumber()
	var alerts []models.AlertImportTemplate
	if err := dec.Decode(&alerts); err != nil {
		return nil, err
	}
	return alerts, nil
}

// Push stores a payload (alerts and metadata), replacing any batch stored
// under the same non-empty key, atomically.
func (b *SQLiteBuffer) Push(payload models.SyncPayload, key string) error {
	alertsJSON, err := json.Marshal(payload.Alerts)
	if err != nil {
		return fmt.Errorf("marshaling alerts for buffer: %w", err)
	}
	metaJSON, err := json.Marshal(payload.SyncMetadata)
	if err != nil {
		return fmt.Errorf("marshaling metadata for buffer: %w", err)
	}

	tx, err := b.db.Begin()
	if err != nil {
		return fmt.Errorf("starting buffer transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	var dedupeKey sql.NullString
	if key != "" {
		dedupeKey = sql.NullString{String: key, Valid: true}
		if _, err := tx.Exec("DELETE FROM buffered_alerts WHERE dedupe_key = ?", key); err != nil {
			return fmt.Errorf("replacing buffered batch: %w", err)
		}
	}
	if _, err := tx.Exec(
		"INSERT INTO buffered_alerts (connection_id, alerts_json, alert_count, metadata_json, dedupe_key) VALUES (?, ?, ?, ?, ?)",
		payload.ConnectionID, string(alertsJSON), len(payload.Alerts), string(metaJSON), dedupeKey,
	); err != nil {
		return fmt.Errorf("inserting into buffer: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing buffer insert: %w", err)
	}

	log.Debug().
		Int("alert_count", len(payload.Alerts)).
		Str("connection_id", payload.ConnectionID).
		Msg("alerts buffered for retry")
	return nil
}

// Peek returns up to limit batches with id > afterID in insertion order.
// Rows whose alerts cannot be decoded can never be delivered and are removed.
func (b *SQLiteBuffer) Peek(afterID int64, limit int) ([]BufferedBatch, error) {
	rows, err := b.db.Query(
		`SELECT id, connection_id, alerts_json, metadata_json, dedupe_key, created_at
		   FROM buffered_alerts WHERE id > ? ORDER BY id ASC LIMIT ?`,
		afterID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("querying buffer: %w", err)
	}

	var batches []BufferedBatch
	var corrupt []int64
	for rows.Next() {
		var (
			id                   int64
			connectionID, alerts string
			metaJSON, dedupeKey  sql.NullString
			createdAt            sql.NullString
		)
		if err := rows.Scan(&id, &connectionID, &alerts, &metaJSON, &dedupeKey, &createdAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning buffer row: %w", err)
		}
		decoded, err := decodeAlerts(alerts)
		if err != nil {
			log.Error().Int64("id", id).Err(err).Msg("corrupted buffer entry, discarding")
			corrupt = append(corrupt, id)
			continue
		}
		var meta models.SyncMetadata
		if !metaJSON.Valid || json.Unmarshal([]byte(metaJSON.String), &meta) != nil {
			meta = DeriveMetadata(decoded, parseSQLiteTime(createdAt.String))
		}
		batches = append(batches, BufferedBatch{
			ID:  id,
			Key: dedupeKey.String,
			Payload: models.SyncPayload{
				ConnectionID: connectionID,
				Alerts:       decoded,
				SyncMetadata: meta,
			},
		})
	}
	iterErr := rows.Err()
	rows.Close()
	if iterErr != nil {
		return nil, fmt.Errorf("iterating buffer rows: %w", iterErr)
	}

	for _, id := range corrupt {
		if err := b.Ack(id); err != nil {
			return nil, err
		}
	}
	return batches, nil
}

// Ack removes a delivered batch (a single, atomic DELETE).
func (b *SQLiteBuffer) Ack(id int64) error {
	if _, err := b.db.Exec("DELETE FROM buffered_alerts WHERE id = ?", id); err != nil {
		return fmt.Errorf("deleting buffer entry %d: %w", id, err)
	}
	return nil
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
