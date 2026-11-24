package models

import (
	"strings"
	"time"
)

// Severity represents normalized alert severity levels.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// AlertStatus represents the current state of an alert.
type AlertStatus string

const (
	AlertStatusOpen   AlertStatus = "open"
	AlertStatusClosed AlertStatus = "closed"
	AlertStatusHidden AlertStatus = "hidden"
)

// Alert is the internal normalized, SIEM-agnostic alert model.
// Collectors map their native format into this structure.
// This is then converted to AlertImportTemplate for the platform API.
type Alert struct {
	// Core identification
	ID         string `json:"id"`
	SourceID   string `json:"source_id"`
	SourceType string `json:"source_type"`

	// ExternalID is the stable identifier of the alert in the source SIEM.
	// The platform deduplicates on (connection, externalId), so it must not
	// change when the alert is re-collected.
	ExternalID string `json:"external_id,omitempty"`

	// Native MITRE ATT&CK data, when the SIEM provides it. When TechniqueID is
	// empty the mapping package falls back to keyword heuristics.
	TechniqueID   string `json:"technique_id,omitempty"`
	TechniqueName string `json:"technique_name,omitempty"`
	Tactic        string `json:"tactic,omitempty"` // tactic ID (TA0006) or name

	// Classification
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Severity    Severity    `json:"severity"`
	Status      AlertStatus `json:"status"`
	Categories  []string    `json:"categories"`

	// Scoring (normalized 0-10 scale)
	Score       float64 `json:"score"`
	Credibility float64 `json:"credibility"`
	Relevance   float64 `json:"relevance"`

	// Timing
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	ClosedAt  *time.Time `json:"closed_at,omitempty"`

	// Context
	Source     string `json:"source"`
	AssignedTo string `json:"assigned_to,omitempty"`
	EventCount int64  `json:"event_count"`
	FlowCount  int64  `json:"flow_count"`

	// Network context
	SourceIPs           []string `json:"source_ips,omitempty"`
	DestinationIPs      []string `json:"destination_ips,omitempty"`
	SourceNetwork       string   `json:"source_network,omitempty"`
	DestinationNetworks []string `json:"destination_networks,omitempty"`

	// Rules that triggered this alert
	Rules []AlertRule `json:"rules,omitempty"`

	// Notes/comments from analysts
	Notes []AlertNote `json:"notes,omitempty"`

	// Raw data preserved for debugging/enrichment
	RawData map[string]any `json:"raw_data,omitempty"`
}

// AlertRule represents a rule that triggered an alert.
type AlertRule struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// AlertNote represents an analyst note/comment on an alert.
type AlertNote struct {
	ID        string    `json:"id"`
	Text      string    `json:"text"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// AlertImportTemplate is the format the platform API expects for alert ingestion.
// This matches the AlertImportTemplate type on the Next.js platform
// (lib/cyberrisk/types/fair-quantification.ts).
type AlertImportTemplate struct {
	// ExternalID is the stable SIEM-side ID; the platform deduplicates on it per connection.
	ExternalID    string `json:"externalId,omitempty"`
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName,omitempty"`
	Description   string `json:"description"`
	AlertDate     string `json:"alertDate"` // YYYY-MM-DD (UTC)
	Severity      string `json:"severity"`  // critical, high, medium, low, info
	SourceIP      string `json:"sourceIp,omitempty"`
	DestinationIP string `json:"destinationIp,omitempty"`
	AssetName     string `json:"assetName,omitempty"`
	// ImpactType is normally left empty: the platform resolves it from the
	// technique catalog and, failing that, from Tactic.
	ImpactType string `json:"impactType,omitempty"`
	// Tactic is a MITRE tactic ID (TA0010), name (Exfiltration) or snake_case name.
	Tactic string `json:"tactic,omitempty"`
	// SourceStatus is the alert's normalized status in the source SIEM
	// (lowercase, at most 64 characters), e.g. "new", "ignored" or
	// "manually_cleared/false_positive". Empty when the source has none.
	SourceStatus string `json:"sourceStatus,omitempty"`
	// FairExcluded reports that the source discarded the alert (false
	// positive, ignored...): the platform stores it but leaves it out of the
	// FAIR frequency. It is a pointer so a collector can send an explicit
	// false (FortiSIEM does, as its shared parity fixture encodes). Stellar
	// Cyber only sends true, like the app's mapper: when a template reports a
	// sourceStatus the platform treats a missing fairExcluded as false, so a
	// reopened alert counts again. Collectors that do not track the source
	// status (QRadar) leave both empty and never touch the stored value.
	FairExcluded *bool `json:"fairExcluded,omitempty"`
	// SignalClass is "threat_event" (the platform default) or "exposure".
	SignalClass string `json:"signalClass,omitempty"`
	// StatusOnly marks an alert first seen outside the import window: the
	// platform only refreshes its stored status and never inserts it.
	StatusOnly bool `json:"statusOnly,omitempty"`
	// RawData is compact source metadata stored in cyberrisk_alert_records.raw_data.
	RawData map[string]any `json:"rawData,omitempty"`
}

// Signal classes of AlertImportTemplate.SignalClass.
const (
	SignalClassThreatEvent = "threat_event"
	SignalClassExposure    = "exposure"
)

// MaxSourceStatusLength is the size of cyberrisk_alert_records.source_status.
const MaxSourceStatusLength = 64

// NormalizeSourceStatus lowercases and trims a source status and cuts it to
// MaxSourceStatusLength characters, as the platform stores it.
func NormalizeSourceStatus(status string) string {
	s := strings.ToLower(strings.TrimSpace(status))
	count := 0
	for i := range s {
		if count == MaxSourceStatusLength {
			return s[:i]
		}
		count++
	}
	return s
}

// Bool returns a pointer to b, for AlertImportTemplate.FairExcluded.
func Bool(b bool) *bool { return &b }
