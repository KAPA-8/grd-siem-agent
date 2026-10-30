package models

// HeartbeatPayload is the request body for POST /api/v1/siem-agent/heartbeat.
// Matches the platform's expected heartbeat format; the platform stores the
// whole body in last_heartbeat_data and maps status "error" to an error state.
type HeartbeatPayload struct {
	Status            string  `json:"status"` // "healthy", "degraded", "error"
	StatusDetail      string  `json:"status_detail,omitempty"`
	UptimeSeconds     int64   `json:"uptime_seconds"`
	MemoryUsageMB     float64 `json:"memory_usage_mb"`
	ActiveConnections int     `json:"active_connections"`
	BufferedBatches   int     `json:"buffered_batches"`
	AgentVersion      string  `json:"agent_version"`
	Hostname          string  `json:"hostname"`
	OSInfo            string  `json:"os_info,omitempty"`
}
