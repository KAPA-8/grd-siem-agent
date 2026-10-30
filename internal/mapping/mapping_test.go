package mapping

import (
	"reflect"
	"testing"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/models"
)

func TestAlertToImportTemplate_NativeTechniqueWins(t *testing.T) {
	alert := models.Alert{
		ExternalID:     "ext-1",
		Description:    "brute force against admin", // heuristics would say T1110
		Severity:       models.SeverityHigh,
		TechniqueID:    "T1566",
		TechniqueName:  "Phishing",
		Tactic:         "TA0001",
		CreatedAt:      time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
		SourceIPs:      []string{"203.0.113.10", "203.0.113.11"},
		DestinationIPs: []string{"10.0.0.5"},
		Source:         "mail-gw-01",
		RawData:        map[string]any{"source": "x"},
	}

	got := AlertToImportTemplate(alert)
	want := models.AlertImportTemplate{
		ExternalID:    "ext-1",
		TechniqueID:   "T1566",
		TechniqueName: "Phishing",
		Description:   "brute force against admin",
		AlertDate:     "2026-10-28",
		Severity:      "high",
		SourceIP:      "203.0.113.10",
		DestinationIP: "10.0.0.5",
		AssetName:     "mail-gw-01",
		Tactic:        "TA0001",
		RawData:       map[string]any{"source": "x"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func TestAlertToImportTemplate_HeuristicFallback(t *testing.T) {
	got := AlertToImportTemplate(models.Alert{
		Description: "Multiple brute force attempts detected",
		Severity:    models.SeverityMedium,
		CreatedAt:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	})
	if got.TechniqueID != "T1110" || got.TechniqueName != "Brute Force" || got.Tactic != "credential_access" {
		t.Errorf("got technique %q/%q tactic %q, want T1110/Brute Force/credential_access", got.TechniqueID, got.TechniqueName, got.Tactic)
	}
	if got.ImpactType != "" {
		t.Errorf("ImpactType = %q, want empty", got.ImpactType)
	}
}

func TestAlertToImportTemplate_NativeTacticKeptWithHeuristicTechnique(t *testing.T) {
	got := AlertToImportTemplate(models.Alert{Description: "phishing mail", Tactic: "TA0043"})
	if got.TechniqueID != "T1566" || got.Tactic != "TA0043" {
		t.Errorf("got %q/%q, want T1566/TA0043", got.TechniqueID, got.Tactic)
	}
}

func TestAlertToImportTemplate_DateIsUTC(t *testing.T) {
	// 2026-10-29T23:30:00-05:00 is 2026-10-30 in UTC.
	guayaquil := time.FixedZone("ECT", -5*3600)
	got := AlertToImportTemplate(models.Alert{
		Description: "x",
		CreatedAt:   time.Date(2026, 10, 29, 23, 30, 0, 0, guayaquil),
	})
	if got.AlertDate != "2026-10-30" {
		t.Errorf("AlertDate = %q, want 2026-10-30", got.AlertDate)
	}
}

func TestAlertToImportTemplate_TitleWhenNoDescription(t *testing.T) {
	got := AlertToImportTemplate(models.Alert{Title: "Offense title", Description: "  "})
	if got.Description != "Offense title" {
		t.Errorf("Description = %q, want the title", got.Description)
	}
}

func TestAlertsToImportTemplates_PreservesOrder(t *testing.T) {
	got := AlertsToImportTemplates([]models.Alert{{ExternalID: "a"}, {ExternalID: "b"}, {ExternalID: "c"}})
	if len(got) != 3 || got[0].ExternalID != "a" || got[1].ExternalID != "b" || got[2].ExternalID != "c" {
		t.Fatalf("got %+v", got)
	}
	if empty := AlertsToImportTemplates(nil); empty == nil || len(empty) != 0 {
		t.Errorf("nil input should give an empty, non-nil slice, got %#v", empty)
	}
}
