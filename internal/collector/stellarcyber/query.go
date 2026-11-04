package stellarcyber

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// The Lucene expressions below are identical to the ones the platform's
// TypeScript adapter emits (DESIGN §1). The alert index is queried with URI
// search only: user-scoped keys accept Lucene but not a DSL body.

const (
	fieldWriteTime   = "write_time"
	fieldModifiedAt  = "modified_at"
	ignoredStatus    = "Ignored" // Stellar Cyber's "false positive" alert status
	probeAlertsQuery = "fidelity:<0"
)

// caseStatuses are queried one by one: some versions exclude Resolved when no
// status is given. Cancelled (false positive) is deliberately left out.
var caseStatuses = []string{"New", "In Progress", "Escalated", "Resolved"}

// rangeClause renders field:[fromMs TO toMs}, upper bound exclusive.
func rangeClause(field string, fromMs, toMs int64) string {
	return fmt.Sprintf("%s:[%d TO %d}", field, fromMs, toMs)
}

// buildAlertsQuery joins the window clause with the optional minimum score
// and tenant filters and the exclusion of Ignored alerts. Alerts without an
// event_status still match.
func buildAlertsQuery(window string, minScore int, tenantID string) string {
	parts := []string{window}
	if minScore > 0 {
		parts = append(parts, "event_score:>="+strconv.Itoa(minScore))
	}
	if tenantID != "" {
		parts = append(parts, "tenantid:"+quoteLucene(tenantID))
	}
	parts = append(parts, "NOT event_status:"+quoteLucene(ignoredStatus))
	return strings.Join(parts, " AND ")
}

// quoteLucene renders s as a Lucene phrase, escaping backslashes and quotes.
func quoteLucene(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// minScoreFor maps sync.filters.min_severity to the score floor of DESIGN §2:
// info=0, low=20, medium=40, high=60, critical=80. Empty means no filter.
func minScoreFor(minSeverity string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(minSeverity)) {
	case "", "info":
		return 0, nil
	case "low":
		return 20, nil
	case "medium":
		return 40, nil
	case "high":
		return 60, nil
	case "critical":
		return 80, nil
	default:
		return 0, fmt.Errorf("sync.filters.min_severity must be one of info, low, medium, high, critical (got %q)", minSeverity)
	}
}

// encodeQuery encodes query parameters with %20 for spaces ("In Progress"),
// which every server decodes, instead of url.Values' "+".
func encodeQuery(q url.Values) string {
	return strings.ReplaceAll(q.Encode(), "+", "%20")
}

// NormalizeBaseURL turns user input into the API base URL: trims spaces,
// defaults the scheme to https, and strips a trailing slash and any
// /connect/api... suffix, query or fragment.
func NormalizeBaseURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("siem.api_url is required")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("siem.api_url %q is not a valid URL: %w", raw, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("siem.api_url %q must use https", raw)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("siem.api_url %q has no host", raw)
	}
	path := u.Path
	if i := strings.Index(strings.ToLower(path), "/connect/api"); i >= 0 {
		path = path[:i]
	}
	u.Path = strings.TrimRight(path, "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	return u.String(), nil
}
