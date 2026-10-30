package buffer

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/models"
)

func newTestBuffer(t *testing.T) *SQLiteBuffer {
	t.Helper()
	buf, err := NewSQLiteBuffer(filepath.Join(t.TempDir(), "test_buffer.db"))
	if err != nil {
		t.Fatalf("NewSQLiteBuffer failed: %v", err)
	}
	t.Cleanup(func() { buf.Close() })
	return buf
}

func payload(conn string, descriptions ...string) models.SyncPayload {
	alerts := make([]models.AlertImportTemplate, len(descriptions))
	for i, d := range descriptions {
		alerts[i] = models.AlertImportTemplate{ExternalID: d, Description: d, Severity: "high", AlertDate: "2026-10-28", TechniqueID: "T1110"}
	}
	return models.SyncPayload{
		ConnectionID: conn,
		Alerts:       alerts,
		SyncMetadata: models.SyncMetadata{
			DateFrom:          "2026-10-23T12:00:00Z",
			DateTo:            "2026-10-30T11:58:00Z",
			SIEMType:          "stellar_cyber",
			TotalFetched:      len(alerts) + 2,
			TotalAfterFilter:  len(alerts),
			DuplicatesRemoved: 1,
			AgentVersion:      "v1.2.3",
		},
	}
}

func descriptions(batches []BufferedBatch) []string {
	var out []string
	for _, b := range batches {
		for _, a := range b.Payload.Alerts {
			out = append(out, a.Description)
		}
	}
	return out
}

// implementations runs a behaviour test against both buffers.
func implementations(t *testing.T, test func(t *testing.T, buf Buffer)) {
	t.Run("sqlite", func(t *testing.T) { test(t, newTestBuffer(t)) })
	t.Run("memory", func(t *testing.T) { test(t, NewMemoryBuffer()) })
}

func TestBuffer_PushPeekAckKeepsMetadata(t *testing.T) {
	implementations(t, func(t *testing.T, buf Buffer) {
		p := payload("conn-1", "Alert 1", "Alert 2")
		if err := buf.Push(p, ""); err != nil {
			t.Fatal(err)
		}
		batches, err := buf.Peek(0, 10)
		if err != nil || len(batches) != 1 {
			t.Fatalf("Peek = %v, %v", batches, err)
		}
		if batches[0].ID <= 0 || !reflect.DeepEqual(batches[0].Payload, p) {
			t.Errorf("stored payload differs:\n got %+v\nwant %+v", batches[0].Payload, p)
		}
		// Peek does not remove.
		if n, _ := buf.Len(); n != 1 {
			t.Errorf("Len after Peek = %d, want 1", n)
		}
		if err := buf.Ack(batches[0].ID); err != nil {
			t.Fatal(err)
		}
		if n, _ := buf.Len(); n != 0 {
			t.Errorf("Len after Ack = %d, want 0", n)
		}
		if err := buf.Ack(batches[0].ID); err != nil {
			t.Errorf("acking an unknown id must be a no-op: %v", err)
		}
	})
}

func TestBuffer_FIFOAndCursor(t *testing.T) {
	implementations(t, func(t *testing.T, buf Buffer) {
		for _, d := range []string{"First", "Second", "Third"} {
			if err := buf.Push(payload("c", d), ""); err != nil {
				t.Fatal(err)
			}
		}
		first, _ := buf.Peek(0, 1)
		if got := descriptions(first); !reflect.DeepEqual(got, []string{"First"}) {
			t.Fatalf("Peek(0,1) = %v", got)
		}
		rest, _ := buf.Peek(first[0].ID, 10)
		if got := descriptions(rest); !reflect.DeepEqual(got, []string{"Second", "Third"}) {
			t.Fatalf("Peek(after first) = %v", got)
		}
		empty, err := buf.Peek(rest[1].ID, 10)
		if err != nil || len(empty) != 0 {
			t.Errorf("Peek past the end = %v, %v", empty, err)
		}
	})
}

func TestBuffer_PushWithKeyReplaces(t *testing.T) {
	implementations(t, func(t *testing.T, buf Buffer) {
		mustPush := func(p models.SyncPayload, key string) {
			t.Helper()
			if err := buf.Push(p, key); err != nil {
				t.Fatal(err)
			}
		}
		mustPush(payload("c", "old"), "k1")
		mustPush(payload("c", "other"), "k2")
		mustPush(payload("c", "new"), "k1")
		mustPush(payload("c", "unkeyed"), "")
		mustPush(payload("c", "unkeyed"), "")

		batches, _ := buf.Peek(0, 10)
		if got := descriptions(batches); !reflect.DeepEqual(got, []string{"other", "new", "unkeyed", "unkeyed"}) {
			t.Fatalf("buffer = %v", got)
		}
		if batches[1].Key != "k1" || batches[2].Key != "" {
			t.Errorf("keys = %q %q", batches[1].Key, batches[2].Key)
		}
	})
}

// A crash (or os.Exit) between Peek and Ack must not lose the batch.
func TestSQLiteBuffer_CrashBetweenPeekAndAck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "buffer.db")
	buf, err := NewSQLiteBuffer(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"A", "B"} {
		if err := buf.Push(payload("c", d), ""); err != nil {
			t.Fatal(err)
		}
	}
	peeked, _ := buf.Peek(0, 10)
	if len(peeked) != 2 {
		t.Fatalf("peeked %d", len(peeked))
	}
	buf.Close() // "crash" before acknowledging anything

	buf, err = NewSQLiteBuffer(path)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := buf.Peek(0, 10)
	if got := descriptions(again); !reflect.DeepEqual(got, []string{"A", "B"}) {
		t.Fatalf("after restart = %v, want both batches", got)
	}
	if err := buf.Ack(again[0].ID); err != nil {
		t.Fatal(err)
	}
	buf.Close()

	buf, err = NewSQLiteBuffer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()
	left, _ := buf.Peek(0, 10)
	if got := descriptions(left); !reflect.DeepEqual(got, []string{"B"}) {
		t.Fatalf("after ack and restart = %v, want [B]", got)
	}
}

func TestSQLiteBuffer_RawDataNumbersAreExact(t *testing.T) {
	buf := newTestBuffer(t)
	p := payload("c", "x")
	p.Alerts[0].RawData = map[string]any{"writeTime": json.Number("1793196390000"), "eventScore": json.Number("79.99")}
	if err := buf.Push(p, ""); err != nil {
		t.Fatal(err)
	}
	batches, _ := buf.Peek(0, 1)
	data, _ := json.Marshal(batches[0].Payload.Alerts[0].RawData)
	if string(data) != `{"eventScore":79.99,"writeTime":1793196390000}` {
		t.Errorf("rawData = %s", data)
	}
}

func TestSQLiteBuffer_CorruptRowIsDropped(t *testing.T) {
	buf := newTestBuffer(t)
	if err := buf.Push(payload("c", "good-1"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := buf.db.Exec(`INSERT INTO buffered_alerts (connection_id, alerts_json, alert_count) VALUES ('c', '{not json', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := buf.Push(payload("c", "good-2"), ""); err != nil {
		t.Fatal(err)
	}
	batches, err := buf.Peek(0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := descriptions(batches); !reflect.DeepEqual(got, []string{"good-1", "good-2"}) {
		t.Fatalf("Peek = %v", got)
	}
	if n, _ := buf.Len(); n != 2 {
		t.Errorf("Len = %d, want 2 (corrupt row removed)", n)
	}
}

// Rows written by older agents have no metadata; the migration derives the
// date range from their alerts so the platform accepts them.
func TestSQLiteBuffer_MigratesOldRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE buffered_alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			connection_id TEXT NOT NULL,
			alerts_json TEXT NOT NULL,
			alert_count INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX idx_buffered_created_at ON buffered_alerts(created_at)`,
		`INSERT INTO buffered_alerts (connection_id, alerts_json, alert_count, created_at) VALUES
			('conn-1', '[{"techniqueId":"T1110","description":"a","alertDate":"2026-10-27","severity":"high"},{"techniqueId":"T1059","description":"b","alertDate":"2026-10-25","severity":"low"},{"techniqueId":"T1059","description":"c","alertDate":"2026-10-29T23:30:00-05:00","severity":"low"}]', 3, '2026-10-30 08:00:00')`,
		`INSERT INTO buffered_alerts (connection_id, alerts_json, alert_count, created_at) VALUES
			('conn-1', '[{"techniqueId":"T1110","description":"no-date","alertDate":"","severity":"high"}]', 1, '2026-10-30 08:00:00')`,
	} {
		if _, err := old.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	old.Close()

	for round := 0; round < 2; round++ { // the migration is idempotent
		buf, err := NewSQLiteBuffer(path)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		batches, err := buf.Peek(0, 10)
		if err != nil || len(batches) != 2 {
			t.Fatalf("round %d: Peek = %v, %v", round, batches, err)
		}
		want := models.SyncMetadata{DateFrom: "2026-10-25T00:00:00Z", DateTo: "2026-10-30T23:59:59Z", TotalFetched: 3, TotalAfterFilter: 3}
		if got := batches[0].Payload.SyncMetadata; got != want {
			t.Errorf("round %d: derived metadata = %+v, want %+v", round, got, want)
		}
		if batches[0].Payload.ConnectionID != "conn-1" || len(batches[0].Payload.Alerts) != 3 {
			t.Errorf("round %d: payload = %+v", round, batches[0].Payload)
		}
		// No usable alert date: the day the batch was stored.
		if got := batches[1].Payload.SyncMetadata; got.DateFrom != "2026-10-30T00:00:00Z" || got.DateTo != "2026-10-30T23:59:59Z" {
			t.Errorf("round %d: fallback metadata = %+v", round, got)
		}

		var version int
		if err := buf.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != schemaVersion {
			t.Errorf("round %d: user_version = %d, %v", round, version, err)
		}
		var nullMeta int
		if err := buf.db.QueryRow("SELECT COUNT(*) FROM buffered_alerts WHERE metadata_json IS NULL").Scan(&nullMeta); err != nil || nullMeta != 0 {
			t.Errorf("round %d: rows without metadata = %d, %v", round, nullMeta, err)
		}
		buf.Close()
	}
}

func TestDeriveMetadata(t *testing.T) {
	stored := time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)
	got := DeriveMetadata(nil, stored)
	if got.DateFrom != "2026-10-30T00:00:00Z" || got.DateTo != "2026-10-30T23:59:59Z" || got.TotalFetched != 0 {
		t.Errorf("empty = %+v", got)
	}
	got = DeriveMetadata([]models.AlertImportTemplate{{AlertDate: "bogus"}, {AlertDate: "2026-02-28"}}, stored)
	if got.DateFrom != "2026-02-28T00:00:00Z" || got.DateTo != "2026-02-28T23:59:59Z" || got.TotalAfterFilter != 2 {
		t.Errorf("mixed = %+v", got)
	}
	if !strings.HasSuffix(DeriveMetadata(nil, time.Time{}).DateFrom, "T00:00:00Z") {
		t.Error("zero stored time must fall back to today")
	}
}
