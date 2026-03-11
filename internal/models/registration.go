package models

// RegisterRequest is the body for POST /api/v1/siem-agent/register.
// Requires org API key as Bearer token.
type RegisterRequest struct {
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
	SIEMType     string `json:"siem_type"`
}

// RegisterResponse is the response from POST /api/v1/siem-agent/register.
// The agent_token is only shown once and must be saved.
type RegisterResponse struct {
	Success    bool   `json:"success"`
	AgentID    string `json:"agent_id"`
	AgentToken string `json:"agent_token"`
}
