package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/models"
)

func TestSendSync_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pathSync {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-agent-token" {
			t.Errorf("wrong auth header: %s", r.Header.Get("Authorization"))
		}

		var payload models.SyncPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		if payload.ConnectionID != "conn-123" {
			t.Errorf("ConnectionID = %q, want conn-123", payload.ConnectionID)
		}
		if len(payload.Alerts) != 1 {
			t.Errorf("Alerts len = %d, want 1", len(payload.Alerts))
		}

		json.NewEncoder(w).Encode(models.SyncResponse{
			Success:        true,
			AlertsImported: 1,
			AlertsSkipped:  0,
		})
	}))
	defer server.Close()

	sender := NewSender(config.PlatformConfig{
		URL:        server.URL,
		AgentToken: "test-agent-token",
	})

	payload := models.SyncPayload{
		ConnectionID: "conn-123",
		Alerts: []models.AlertImportTemplate{
			{Description: "Test alert", Severity: "high", AlertDate: "2024-01-01"},
		},
		SyncMetadata: models.SyncMetadata{
			SIEMType:     "qradar",
			TotalFetched: 1,
		},
	}

	resp, err := sender.SendSync(context.Background(), payload)
	if err != nil {
		t.Fatalf("SendSync failed: %v", err)
	}
	if !resp.Success {
		t.Error("expected success=true")
	}
	if resp.AlertsImported != 1 {
		t.Errorf("AlertsImported = %d, want 1", resp.AlertsImported)
	}
}

func TestSendSync_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal Server Error", 500)
	}))
	defer server.Close()

	sender := NewSender(config.PlatformConfig{
		URL:        server.URL,
		AgentToken: "test-token",
	})

	_, err := sender.SendSync(context.Background(), models.SyncPayload{})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestSendHeartbeat_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pathHeartbeat {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	sender := NewSender(config.PlatformConfig{
		URL:        server.URL,
		AgentToken: "test-token",
	})

	err := sender.SendHeartbeat(context.Background(), models.HeartbeatPayload{
		Status:        "healthy",
		UptimeSeconds: 3600,
		AgentVersion:  "1.0.0",
	})
	if err != nil {
		t.Fatalf("SendHeartbeat failed: %v", err)
	}
}

func TestRegister_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pathRegister {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer org-api-key" {
			t.Errorf("wrong auth: %s", r.Header.Get("Authorization"))
		}

		json.NewEncoder(w).Encode(models.RegisterResponse{
			Success:    true,
			AgentID:    "agent-uuid-123",
			AgentToken: "grd_agent_abc123",
		})
	}))
	defer server.Close()

	resp, err := Register(context.Background(), server.URL, "org-api-key", models.RegisterRequest{
		Name:         "Test Agent",
		Hostname:     "test-host",
		AgentVersion: "1.0.0",
		SIEMType:     "qradar",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if resp.AgentID != "agent-uuid-123" {
		t.Errorf("AgentID = %q, want agent-uuid-123", resp.AgentID)
	}
	if resp.AgentToken != "grd_agent_abc123" {
		t.Errorf("AgentToken = %q, want grd_agent_abc123", resp.AgentToken)
	}
}
