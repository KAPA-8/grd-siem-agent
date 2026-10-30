// Package mapping converts the SIEM-agnostic models.Alert into the platform's
// AlertImportTemplate. Collectors whose source carries native ATT&CK data fill
// Alert.TechniqueID; otherwise the technique is inferred with internal/mitre.
package mapping

import (
	"strings"

	"github.com/grd-platform/grd-siem-agent/internal/mitre"
	"github.com/grd-platform/grd-siem-agent/internal/models"
)

// alertDateLayout is the platform's alertDate format. Dates are always UTC so
// the result does not depend on the host time zone.
const alertDateLayout = "2006-01-02"

// AlertToImportTemplate converts a normalized alert into the format accepted
// by POST /api/v1/siem-agent/sync.
//
// The impact type is intentionally left empty: the platform resolves it from
// its technique catalog and, failing that, from the tactic.
func AlertToImportTemplate(alert models.Alert) models.AlertImportTemplate {
	techniqueID := strings.TrimSpace(alert.TechniqueID)
	techniqueName := strings.TrimSpace(alert.TechniqueName)
	tactic := strings.TrimSpace(alert.Tactic)

	if techniqueID == "" {
		inferred := mitre.Extract(alert.Description, alert.Categories)
		techniqueID = inferred.TechniqueID
		techniqueName = inferred.TechniqueName
		if tactic == "" {
			tactic = inferred.Tactic
		}
	}

	description := alert.Description
	if strings.TrimSpace(description) == "" {
		description = alert.Title
	}

	template := models.AlertImportTemplate{
		ExternalID:    alert.ExternalID,
		TechniqueID:   techniqueID,
		TechniqueName: techniqueName,
		Description:   description,
		AlertDate:     alert.CreatedAt.UTC().Format(alertDateLayout),
		Severity:      string(alert.Severity),
		Tactic:        tactic,
		AssetName:     alert.Source,
		RawData:       alert.RawData,
	}

	if len(alert.SourceIPs) > 0 {
		template.SourceIP = alert.SourceIPs[0]
	}
	if len(alert.DestinationIPs) > 0 {
		template.DestinationIP = alert.DestinationIPs[0]
	}

	return template
}

// AlertsToImportTemplates converts a slice of alerts, preserving order.
func AlertsToImportTemplates(alerts []models.Alert) []models.AlertImportTemplate {
	templates := make([]models.AlertImportTemplate, 0, len(alerts))
	for _, alert := range alerts {
		templates = append(templates, AlertToImportTemplate(alert))
	}
	return templates
}
