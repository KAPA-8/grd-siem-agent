package qradar

import (
	"fmt"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/models"
)

// MapOffenseToAlert converts a QRadar offense into the internal normalized Alert model.
func MapOffenseToAlert(offense QRadarOffense) models.Alert {
	alert := models.Alert{
		ID:         fmt.Sprintf("qradar:offense:%d", offense.ID),
		SourceID:   fmt.Sprintf("%d", offense.ID),
		SourceType: "qradar",

		Title:       offense.Description,
		Description: offense.Description,
		Severity:    mapSeverity(offense.Severity),
		Status:      mapStatus(offense.Status),
		Categories:  offense.Categories,

		Score:       float64(offense.Magnitude),
		Credibility: float64(offense.Credibility),
		Relevance:   float64(offense.Relevance),

		CreatedAt: epochMsToTime(offense.StartTime),
		UpdatedAt: epochMsToTime(offense.LastUpdatedTime),

		Source:     offense.OffenseSource,
		AssignedTo: offense.AssignedTo,
		EventCount: offense.EventCount,
		FlowCount:  offense.FlowCount,

		SourceNetwork:       offense.SourceNetwork,
		DestinationNetworks: offense.DestinationNetworks,

		Rules: mapRules(offense.Rules),
	}

	// Use offense source as source IP if it looks like an IP
	if offense.OffenseSource != "" {
		alert.SourceIPs = []string{offense.OffenseSource}
	}

	if offense.CloseTime != nil {
		t := epochMsToTime(*offense.CloseTime)
		alert.ClosedAt = &t
	}

	return alert
}

// AlertToImportTemplate converts an internal Alert to the platform's AlertImportTemplate format.
// This is the format POST /api/v1/siem-agent/sync expects.
func AlertToImportTemplate(alert models.Alert) models.AlertImportTemplate {
	// Extract MITRE technique from description and categories
	mitre := ExtractMITRE(alert.Description, alert.Categories)

	template := models.AlertImportTemplate{
		TechniqueID:   mitre.TechniqueID,
		TechniqueName: mitre.TechniqueName,
		Description:   alert.Description,
		AlertDate:     alert.CreatedAt.Format("2006-01-02"),
		Severity:      string(alert.Severity),
		ImpactType:    mitre.ImpactType,
	}

	// Set network context
	if len(alert.SourceIPs) > 0 {
		template.SourceIP = alert.SourceIPs[0]
	}
	if len(alert.DestinationIPs) > 0 {
		template.DestinationIP = alert.DestinationIPs[0]
	}

	// Use offense source as asset name if available
	if alert.Source != "" {
		template.AssetName = alert.Source
	}

	return template
}

// MapNotes converts QRadar notes to the normalized AlertNote model.
func MapNotes(notes []QRadarNote) []models.AlertNote {
	result := make([]models.AlertNote, len(notes))
	for i, n := range notes {
		result[i] = models.AlertNote{
			ID:        fmt.Sprintf("%d", n.ID),
			Text:      n.NoteText,
			CreatedBy: n.Username,
			CreatedAt: epochMsToTime(n.CreateTime),
		}
	}
	return result
}

// mapSeverity converts QRadar severity (0-10) to normalized Severity.
func mapSeverity(qradarSeverity int) models.Severity {
	switch {
	case qradarSeverity <= 1:
		return models.SeverityInfo
	case qradarSeverity <= 3:
		return models.SeverityLow
	case qradarSeverity <= 5:
		return models.SeverityMedium
	case qradarSeverity <= 7:
		return models.SeverityHigh
	default:
		return models.SeverityCritical
	}
}

// mapStatus converts QRadar offense status to normalized AlertStatus.
func mapStatus(qradarStatus string) models.AlertStatus {
	switch qradarStatus {
	case "OPEN":
		return models.AlertStatusOpen
	case "CLOSED":
		return models.AlertStatusClosed
	case "HIDDEN":
		return models.AlertStatusHidden
	default:
		return models.AlertStatusOpen
	}
}

func mapRules(rules []QRadarRule) []models.AlertRule {
	result := make([]models.AlertRule, len(rules))
	for i, r := range rules {
		result[i] = models.AlertRule{
			ID:   fmt.Sprintf("%d", r.ID),
			Type: r.Type,
		}
	}
	return result
}

func epochMsToTime(epochMs int64) time.Time {
	return time.UnixMilli(epochMs)
}
