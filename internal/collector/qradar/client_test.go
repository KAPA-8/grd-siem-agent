package qradar

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetSystemInfo(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/system/about" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("SEC") != "test-token" {
			t.Errorf("missing or wrong SEC header: %s", r.Header.Get("SEC"))
		}
		json.NewEncoder(w).Encode(QRadarSystemInfo{Version: "7.5.0"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token", false, "")
	info, err := client.GetSystemInfo(context.Background())
	if err != nil {
		t.Fatalf("GetSystemInfo failed: %v", err)
	}
	if info.Version != "7.5.0" {
		t.Errorf("Version = %q, want 7.5.0", info.Version)
	}
}

func TestGetOffenses(t *testing.T) {
	offenses := []QRadarOffense{
		{ID: 1, Description: "Test offense 1", Severity: 5, Status: "OPEN", LastUpdatedTime: 1000},
		{ID: 2, Description: "Test offense 2", Severity: 8, Status: "CLOSED", LastUpdatedTime: 2000},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/siem/offenses" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		// Verify SEC auth header
		if r.Header.Get("SEC") == "" {
			http.Error(w, "Unauthorized", 401)
			return
		}

		// Verify Range header is set
		rangeHeader := r.Header.Get("Range")
		if rangeHeader == "" {
			t.Error("missing Range header")
		}

		w.Header().Set("Content-Range", "items 0-1/2")
		json.NewEncoder(w).Encode(offenses)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token", false, "")
	result, err := client.GetOffenses(context.Background(), "severity >= 4", 100)
	if err != nil {
		t.Fatalf("GetOffenses failed: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("got %d offenses, want 2", len(result))
	}
	if result[0].ID != 1 {
		t.Errorf("first offense ID = %d, want 1", result[0].ID)
	}
}

func TestGetOffenses_Unauthorized(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", 401)
	}))
	defer server.Close()

	client := NewClient(server.URL, "bad-token", false, "")
	_, err := client.GetOffenses(context.Background(), "", 10)
	if err == nil {
		t.Fatal("expected error for unauthorized request")
	}
}

func TestGetOffenseNotes(t *testing.T) {
	notes := []QRadarNote{
		{ID: 1, NoteText: "Investigating", Username: "admin", CreateTime: 1000},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/siem/offenses/123/notes" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(notes)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token", false, "")
	result, err := client.GetOffenseNotes(context.Background(), 123)
	if err != nil {
		t.Fatalf("GetOffenseNotes failed: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("got %d notes, want 1", len(result))
	}
	if result[0].NoteText != "Investigating" {
		t.Errorf("note text = %q, want Investigating", result[0].NoteText)
	}
}
