package qradar

import (
	"testing"

	"github.com/grd-platform/grd-siem-agent/internal/mapping"
	"github.com/grd-platform/grd-siem-agent/internal/models"
)

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		input    int
		expected models.Severity
	}{
		{0, models.SeverityInfo},
		{1, models.SeverityInfo},
		{2, models.SeverityLow},
		{3, models.SeverityLow},
		{4, models.SeverityMedium},
		{5, models.SeverityMedium},
		{6, models.SeverityHigh},
		{7, models.SeverityHigh},
		{8, models.SeverityCritical},
		{9, models.SeverityCritical},
		{10, models.SeverityCritical},
	}

	for _, tt := range tests {
		result := mapSeverity(tt.input)
		if result != tt.expected {
			t.Errorf("mapSeverity(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMapStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected models.AlertStatus
	}{
		{"OPEN", models.AlertStatusOpen},
		{"CLOSED", models.AlertStatusClosed},
		{"HIDDEN", models.AlertStatusHidden},
		{"UNKNOWN", models.AlertStatusOpen},
		{"", models.AlertStatusOpen},
	}

	for _, tt := range tests {
		result := mapStatus(tt.input)
		if result != tt.expected {
			t.Errorf("mapStatus(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMapOffenseToAlert(t *testing.T) {
	offense := QRadarOffense{
		ID:              12345,
		Description:     "Multiple Login Failures for admin",
		Severity:        8,
		Status:          "OPEN",
		Magnitude:       7,
		Credibility:     9,
		Relevance:       6,
		EventCount:      150,
		FlowCount:       0,
		OffenseSource:   "10.0.0.5",
		SourceNetwork:   "internal_network",
		StartTime:       1709308800000, // 2024-03-01T12:00:00Z
		LastUpdatedTime: 1709395200000,
		Categories:      []string{"Authentication", "User Login Failure"},
		Rules: []QRadarRule{
			{ID: 100, Type: "CRE"},
		},
	}

	alert := MapOffenseToAlert(offense)

	if alert.ID != "qradar:offense:12345" {
		t.Errorf("ID = %q, want qradar:offense:12345", alert.ID)
	}
	if alert.SourceID != "12345" {
		t.Errorf("SourceID = %q, want 12345", alert.SourceID)
	}
	if alert.SourceType != "qradar" {
		t.Errorf("SourceType = %q, want qradar", alert.SourceType)
	}
	if alert.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want critical", alert.Severity)
	}
	if alert.Status != models.AlertStatusOpen {
		t.Errorf("Status = %q, want open", alert.Status)
	}
	if alert.EventCount != 150 {
		t.Errorf("EventCount = %d, want 150", alert.EventCount)
	}
	if len(alert.Rules) != 1 {
		t.Errorf("Rules len = %d, want 1", len(alert.Rules))
	}
	if len(alert.SourceIPs) != 1 || alert.SourceIPs[0] != "10.0.0.5" {
		t.Errorf("SourceIPs = %v, want [10.0.0.5]", alert.SourceIPs)
	}
}

func TestMapOffenseToAlert_ImportTemplate(t *testing.T) {
	offense := QRadarOffense{
		ID:              77,
		Description:     "Multiple Login Failures for admin",
		Severity:        6,
		Status:          "OPEN",
		Magnitude:       5,
		OffenseSource:   "10.0.0.5",
		StartTime:       1709337600000, // 2024-03-02T00:00:00Z: 2024-03-01 west of UTC
		LastUpdatedTime: 1709395200000,
		Categories:      []string{"Authentication", "User Login Failure"},
	}

	template := mapping.AlertToImportTemplate(MapOffenseToAlert(offense))

	if template.ExternalID != "qradar-offense-77" {
		t.Errorf("ExternalID = %q, want qradar-offense-77", template.ExternalID)
	}
	if template.Severity != "high" {
		t.Errorf("Severity = %q, want high", template.Severity)
	}
	// The date is taken in UTC regardless of the host time zone.
	if template.AlertDate != "2024-03-02" {
		t.Errorf("AlertDate = %q, want 2024-03-02", template.AlertDate)
	}
	if template.SourceIP != "10.0.0.5" || template.AssetName != "10.0.0.5" {
		t.Errorf("SourceIP/AssetName = %q/%q, want 10.0.0.5", template.SourceIP, template.AssetName)
	}
	// Should extract MITRE from the "Authentication" category
	if template.TechniqueID != "T1110" || template.Tactic != "credential_access" {
		t.Errorf("technique/tactic = %q/%q, want T1110/credential_access", template.TechniqueID, template.Tactic)
	}
	if template.ImpactType != "" {
		t.Errorf("ImpactType = %q, want empty (resolved by the platform)", template.ImpactType)
	}
	if template.RawData["source"] != "qradar" || template.RawData["status"] != "OPEN" || template.RawData["offenseId"] != int64(77) {
		t.Errorf("RawData = %v", template.RawData)
	}
}
