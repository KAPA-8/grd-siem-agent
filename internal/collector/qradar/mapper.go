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
		// Same format as the platform's direct QRadar adapter, so an offense
		// that is re-collected after an update is deduplicated.
		ExternalID: fmt.Sprintf("qradar-offense-%d", offense.ID),

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

		RawData: map[string]any{
			"source":      "qradar",
			"offenseId":   offense.ID,
			"status":      offense.Status,
			"magnitude":   offense.Magnitude,
			"credibility": offense.Credibility,
			"relevance":   offense.Relevance,
			"eventCount":  offense.EventCount,
			"lastUpdated": epochMsToTime(offense.LastUpdatedTime).UTC().Format(time.RFC3339),
		},
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
