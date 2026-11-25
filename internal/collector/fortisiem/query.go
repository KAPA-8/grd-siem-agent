package fortisiem

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// phoenixSuffix matches a pasted /phoenix/... API path (same rule as the
// platform's normalizeFortiSIEMBaseUrl).
var phoenixSuffix = regexp.MustCompile(`(?i)/phoenix(/.*)?$`)

const (
	// orderByLastSeen sorts by the field FortiSIEM filters timeFrom/timeTo
	// on (verified against FortiSIEM Cloud): incremental collection follows it.
	orderByLastSeen = "incidentLastSeen"
	// orderByFirstSeen is the documented sort, used when a server rejects
	// orderByLastSeen.
	orderByFirstSeen = "incidentFirstSeen"
)

// incidentFields are the fields requested from /phoenix/rest/pub/incident
// (DESIGN §1.3). FortiSIEM Cloud adds custId on its own.
var incidentFields = []string{
	"incidentId", "incidentTitle", "eventType", "eventName", "eventSeverity", "eventSeverityCat",
	"incidentFirstSeen", "incidentLastSeen", "incidentStatus", "incidentReso",
	"phIncidentCategory", "phSubIncidentCategory", "attackTactic", "attackTechnique",
	"incidentSrc", "incidentTarget", "incidentRptIp", "incidentRptDevName", "count", "customer", "phCustId",
}

// incidentQuery is the body of POST /phoenix/rest/pub/incident. timeFrom and
// timeTo are epoch milliseconds and apply to incidentLastSeen (inclusive).
type incidentQuery struct {
	Start      int      `json:"start"`
	Size       int      `json:"size"`
	TimeFrom   int64    `json:"timeFrom"`
	TimeTo     int64    `json:"timeTo"`
	OrderBy    string   `json:"orderBy"`
	Descending bool     `json:"descending"`
	Fields     []string `json:"fields"`
}

func newIncidentQuery(start, size int, from, to int64, orderBy string) incidentQuery {
	return incidentQuery{
		Start:    start,
		Size:     size,
		TimeFrom: from,
		TimeTo:   to,
		OrderBy:  orderBy,
		Fields:   incidentFields,
	}
}

// minSeverityFor validates sync.filters.min_severity. "info" (and empty)
// mean no filter.
func minSeverityFor(minSeverity string) (string, error) {
	switch s := strings.ToLower(strings.TrimSpace(minSeverity)); s {
	case "", "info":
		return "", nil
	case "low", "medium", "high", "critical":
		return s, nil
	default:
		return "", fmt.Errorf("sync.filters.min_severity debe ser info, low, medium, high o critical (valor: %q)", minSeverity)
	}
}

// NormalizeBaseURL turns user input into the API base URL: trims spaces,
// defaults the scheme to https, and strips a trailing slash and any
// /phoenix... suffix, query or fragment.
func NormalizeBaseURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("siem.api_url es obligatorio (la URL del Supervisor o de FortiSIEM Cloud)")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("siem.api_url %q no es una URL válida: %w", raw, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("siem.api_url %q debe usar https", raw)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("siem.api_url %q no tiene host", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("siem.api_url no debe incluir usuario ni contraseña: usa siem.credentials")
	}
	// Like the platform (WHATWG URL): lower-case host, no default port.
	u.Host = strings.ToLower(u.Host)
	if port := u.Port(); (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		u.Host = strings.TrimSuffix(u.Host, ":"+port)
	}
	u.Path = strings.TrimRight(phoenixSuffix.ReplaceAllString(u.Path, ""), "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
