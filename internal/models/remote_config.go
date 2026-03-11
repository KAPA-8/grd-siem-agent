package models

// RemoteConfig is the response from GET /api/v1/siem-agent/config.
// The agent fetches this at startup to know which SIEMs to collect from.
type RemoteConfig struct {
	AgentID     string             `json:"agent_id"`
	Connections []RemoteConnection `json:"connections"`
}

// RemoteConnection describes a SIEM connection assigned to this agent.
type RemoteConnection struct {
	ID          string                 `json:"id"`
	SIEMType    string                 `json:"siem_type"`
	Name        string                 `json:"name"`
	APIURL      string                 `json:"api_url"`
	Credentials RemoteCredentials      `json:"credentials"`
	LookbackDays int                   `json:"lookback_days"`
	Filters     map[string]string      `json:"filters"`
}

// RemoteCredentials holds SIEM credentials from the platform.
type RemoteCredentials struct {
	APIKey      string `json:"apiKey"`
	ValidateSSL bool   `json:"validateSSL"`
}
