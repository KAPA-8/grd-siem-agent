package qradar

// QRadarOffense represents the raw API response from QRadar's /siem/offenses endpoint.
// Field names match the QRadar REST API v19.0 schema.
type QRadarOffense struct {
	ID                         int64            `json:"id"`
	Description                string           `json:"description"`
	AssignedTo                 string           `json:"assigned_to"`
	Categories                 []string         `json:"categories"`
	CategoryCount              int              `json:"category_count"`
	CloseTime                  *int64           `json:"close_time"`
	ClosingUser                string           `json:"closing_user"`
	ClosingReasonID            *int64           `json:"closing_reason_id"`
	Credibility                int              `json:"credibility"`
	Relevance                  int              `json:"relevance"`
	Severity                   int              `json:"severity"`
	Magnitude                  int              `json:"magnitude"`
	DestinationNetworks        []string         `json:"destination_networks"`
	SourceNetwork              string           `json:"source_network"`
	DeviceCount                int              `json:"device_count"`
	EventCount                 int64            `json:"event_count"`
	FlowCount                  int64            `json:"flow_count"`
	Inactive                   bool             `json:"inactive"`
	LastUpdatedTime            int64            `json:"last_updated_time"`
	OffenseSource              string           `json:"offense_source"`
	OffenseType                int              `json:"offense_type"`
	Protected                  bool             `json:"protected"`
	FollowUp                   bool             `json:"follow_up"`
	SourceCount                int              `json:"source_count"`
	StartTime                  int64            `json:"start_time"`
	Status                     string           `json:"status"` // OPEN, HIDDEN, CLOSED
	UsernameCount              int              `json:"username_count"`
	SourceAddressIDs           []int64          `json:"source_address_ids"`
	LocalDestinationAddressIDs []int64          `json:"local_destination_address_ids"`
	LocalDestinationCount      int              `json:"local_destination_count"`
	RemoteDestinationCount     int              `json:"remote_destination_count"`
	DomainID                   *int64           `json:"domain_id"`
	LastPersistedTime          int64            `json:"last_persisted_time"`
	FirstPersistedTime         int64            `json:"first_persisted_time"`
	Rules                      []QRadarRule     `json:"rules"`
	LogSources                 []QRadarLogSource `json:"log_sources"`
}

// QRadarRule represents a rule associated with an offense.
type QRadarRule struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

// QRadarLogSource represents a log source associated with an offense.
type QRadarLogSource struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	TypeID   int64  `json:"type_id"`
	TypeName string `json:"type_name"`
}

// QRadarNote represents a note/comment on an offense.
type QRadarNote struct {
	ID         int64  `json:"id"`
	NoteText   string `json:"note_text"`
	Username   string `json:"username"`
	CreateTime int64  `json:"create_time"`
}

// QRadarSystemInfo represents the /system/about response.
type QRadarSystemInfo struct {
	Version string `json:"external_version"`
}
