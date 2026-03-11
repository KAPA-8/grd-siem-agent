package models

// HeartbeatPayload is the request body for POST /api/v1/siem-agent/heartbeat.
// Matches the platform's expected heartbeat format.
type HeartbeatPayload struct {
	Status            string  `json:"status"`             // "healthy", "degraded", "error"
	UptimeSeconds     int64   `json:"uptime_seconds"`
	MemoryUsageMB     float64 `json:"memory_usage_mb"`
	ActiveConnections int     `json:"active_connections"`
	AgentVersion      string  `json:"agent_version"`
	Hostname          string  `json:"hostname"`
}
