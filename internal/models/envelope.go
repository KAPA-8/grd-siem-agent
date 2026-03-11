package models

// SyncPayload is the request body for POST /api/v1/siem-agent/sync.
// Matches the platform's expected sync format.
type SyncPayload struct {
	ConnectionID string                `json:"connection_id"`
	Alerts       []AlertImportTemplate `json:"alerts"`
	SyncMetadata SyncMetadata          `json:"sync_metadata"`
}

// SyncMetadata provides context about the sync cycle.
type SyncMetadata struct {
	DateFrom          string `json:"date_from"`           // ISO 8601
	DateTo            string `json:"date_to"`             // ISO 8601
	SIEMType          string `json:"siem_type"`
	TotalFetched      int    `json:"total_fetched"`
	TotalAfterFilter  int    `json:"total_after_filter"`
	DuplicatesRemoved int    `json:"duplicates_removed"`
	AgentVersion      string `json:"agent_version"`
}

// SyncResponse is the response from POST /api/v1/siem-agent/sync.
type SyncResponse struct {
	Success        bool   `json:"success"`
	SyncLogID      string `json:"sync_log_id"`
	ImportID       string `json:"import_id"`
	AlertsImported int    `json:"alerts_imported"`
	AlertsSkipped  int    `json:"alerts_skipped"`
	AlertsErrors   int    `json:"alerts_errors"`
	LimitReached   bool   `json:"limit_reached"`
}
