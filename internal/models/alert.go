package models

import "time"

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
// This matches the AlertImportTemplate type on the Next.js platform.
type AlertImportTemplate struct {
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName"`
	Description   string `json:"description"`
	AlertDate     string `json:"alertDate"` // YYYY-MM-DD
	Severity      string `json:"severity"`  // critical, high, medium, low, info
	SourceIP      string `json:"sourceIp,omitempty"`
	DestinationIP string `json:"destinationIp,omitempty"`
	AssetName     string `json:"assetName,omitempty"`
	ImpactType    string `json:"impactType,omitempty"`
}
