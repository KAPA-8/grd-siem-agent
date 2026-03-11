package buffer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/grd-platform/grd-siem-agent/internal/models"
)

func newTestBuffer(t *testing.T) *SQLiteBuffer {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test_buffer.db")
	buf, err := NewSQLiteBuffer(path)
	if err != nil {
		t.Fatalf("NewSQLiteBuffer failed: %v", err)
	}
	t.Cleanup(func() {
		buf.Close()
		os.Remove(path)
	})
	return buf
}

func TestSQLiteBuffer_PushAndPop(t *testing.T) {
	buf := newTestBuffer(t)

	alerts := []models.AlertImportTemplate{
		{Description: "Alert 1", Severity: "high", AlertDate: "2024-01-01"},
		{Description: "Alert 2", Severity: "medium", AlertDate: "2024-01-02"},
	}

	// Push
	if err := buf.Push(alerts, "conn-1"); err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	// Check length
	length, err := buf.Len()
	if err != nil {
		t.Fatalf("Len failed: %v", err)
	}
	if length != 1 {
		t.Errorf("Len = %d, want 1", length)
	}

	// Pop
	batches, err := buf.Pop(10)
	if err != nil {
		t.Fatalf("Pop failed: %v", err)
	}
	if len(batches) != 1 {
		t.Fatalf("got %d batches, want 1", len(batches))
	}
	if batches[0].ConnectionID != "conn-1" {
		t.Errorf("ConnectionID = %q, want conn-1", batches[0].ConnectionID)
	}
	if len(batches[0].Alerts) != 2 {
		t.Errorf("Alerts len = %d, want 2", len(batches[0].Alerts))
	}
	if batches[0].Alerts[0].Description != "Alert 1" {
		t.Errorf("first alert description = %q, want Alert 1", batches[0].Alerts[0].Description)
	}

	// Should be empty now
	length, _ = buf.Len()
	if length != 0 {
		t.Errorf("Len after pop = %d, want 0", length)
	}
}

func TestSQLiteBuffer_FIFO(t *testing.T) {
	buf := newTestBuffer(t)

	// Push two batches
	buf.Push([]models.AlertImportTemplate{{Description: "First"}}, "conn-1")
	buf.Push([]models.AlertImportTemplate{{Description: "Second"}}, "conn-2")

	// Pop one at a time
	batches, _ := buf.Pop(1)
	if len(batches) != 1 {
		t.Fatalf("got %d batches, want 1", len(batches))
	}
	if batches[0].Alerts[0].Description != "First" {
		t.Errorf("expected First, got %q", batches[0].Alerts[0].Description)
	}

	batches, _ = buf.Pop(1)
	if batches[0].Alerts[0].Description != "Second" {
		t.Errorf("expected Second, got %q", batches[0].Alerts[0].Description)
	}
}

func TestSQLiteBuffer_EmptyPop(t *testing.T) {
	buf := newTestBuffer(t)

	batches, err := buf.Pop(10)
	if err != nil {
		t.Fatalf("Pop on empty buffer failed: %v", err)
	}
	if len(batches) != 0 {
		t.Errorf("expected empty result, got %d batches", len(batches))
	}
}
