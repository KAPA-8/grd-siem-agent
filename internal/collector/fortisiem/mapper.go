package fortisiem

import (
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/models"
)

// The mapping below is shared with the platform's TypeScript adapter
// (lib/integrations/siem/fortisiem/mapper.ts). Both are checked against the
// same fixture (testdata/fortisiem-incidents-parity-cases.json, whose
// README.md in the platform repository spells out every rule); keep them in
// sync.

const (
	unmappedTechniqueID = "T0000"
	fallbackDescription = "Incidente FortiSIEM"
	alertDateLayout     = "2006-01-02"

	// maxSafeInteger is the largest integer a JSON number keeps exactly in
	// JavaScript (2^53 - 1): larger incident IDs cannot be compared reliably.
	maxSafeInteger = 1<<53 - 1
	// maxEpochMs is 9999-12-31T23:59:59.999Z, the last instant with a 4-digit
	// year. Later "dates" cannot be rendered as YYYY-MM-DD, so they count as
	// invalid (the platform's TypeScript mapper cannot render them either).
	maxEpochMs = 253402300799999
)

// rawDataKeys are the incident fields copied as-is into rawData, in order.
var rawDataKeys = []string{
	"incidentId", "eventType", "eventName", "phIncidentCategory", "phSubIncidentCategory", "count",
	"incidentLastSeen", "customer", "phCustId", "incidentStatus", "incidentReso", "incidentRptDevName",
}

var (
	numberPattern    = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
	digitsPattern    = regexp.MustCompile(`^\d+$`)
	techniquePattern = regexp.MustCompile(`(?i)^T\d{4}(\.\d{3})?$`)
)

// incidentStatus codes (documented integers; FortiSIEM Cloud sends the words).
var (
	statusNames = map[int64]string{0: "active", 1: "auto_cleared", 2: "manually_cleared", 3: "system_cleared"}
	statusWords = map[string]int64{"active": 0, "autocleared": 1, "clearedmanually": 2, "manuallycleared": 2, "systemcleared": 3}

	resoSuffixes = map[int64]string{2: "true_positive", 3: "false_positive", 4: "in_progress"}
	resoWords    = map[string]int64{"none": 0, "open": 1, "truepositive": 2, "falsepositive": 3, "inprogress": 4}
)

const (
	resoFalsePositive = 3
	categorySecurity  = 4
)

// severityRank orders the platform severities for sync.filters.min_severity.
var severityRank = map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

// Window is a closed interval of epoch milliseconds on incidentFirstSeen.
type Window struct {
	From int64
	To   int64
}

// MapOptions are the filters and the import window applied by MapIncident.
type MapOptions struct {
	// SecurityOnly keeps only incidents of the Security category.
	SecurityOnly bool
	// TenantID keeps only the incidents of one organization: its name
	// (customer, ignoring case and spaces) or its phCustId/custId.
	TenantID string
	// MinSeverity drops incidents below info|low|medium|high|critical ("" = no filter).
	MinSeverity string
	// Window, when set, marks incidents first seen outside it as statusOnly.
	Window *Window
}

var (
	// errNoID and errNoFirstSeen report incidents the platform cannot import.
	errNoID        = errors.New("incident has no usable incidentId")
	errNoFirstSeen = errors.New("incident has no usable incidentFirstSeen (epoch ms)")
	// errFiltered reports an incident dropped by securityOnly, tenantId or min_severity.
	errFiltered = errors.New("incident dropped by the configured filters")
)

// MapIncident converts one element of data[] of POST /phoenix/rest/pub/incident
// (decoded with UseNumber) into the platform's AlertImportTemplate. It fails
// with errNoID or errNoFirstSeen when the incident cannot be imported and
// with errFiltered when a filter of opts drops it. An incident first seen
// outside opts.Window is not dropped: it is mapped in full and marked
// StatusOnly, so the platform refreshes its status but never inserts it.
func MapIncident(inc map[string]any, opts MapOptions) (models.AlertImportTemplate, error) {
	id := incidentID(inc["incidentId"])
	if id == "" {
		return models.AlertImportTemplate{}, errNoID
	}
	firstSeen, ok := epochMs(inc["incidentFirstSeen"])
	if !ok {
		return models.AlertImportTemplate{}, errNoFirstSeen
	}
	if opts.SecurityOnly && !isSecurityCategory(inc["phIncidentCategory"]) {
		return models.AlertImportTemplate{}, errFiltered
	}
	if !matchesTenant(inc, opts.TenantID) {
		return models.AlertImportTemplate{}, errFiltered
	}
	severity := mapSeverity(inc)
	if minRank, set := severityRank[opts.MinSeverity]; set && severityRank[severity] < minRank {
		return models.AlertImportTemplate{}, errFiltered
	}

	techniqueID, techniqueName := mapTechnique(inc["attackTechnique"])
	src, target := keyValues(inc["incidentSrc"]), keyValues(inc["incidentTarget"])
	sourceStatus, falsePositive := mapStatus(inc["incidentStatus"], inc["incidentReso"])

	return models.AlertImportTemplate{
		ExternalID:    id,
		TechniqueID:   techniqueID,
		TechniqueName: techniqueName,
		Description:   firstNonEmpty(nonEmpty(inc["incidentTitle"]), nonEmpty(inc["eventName"]), fallbackDescription),
		AlertDate:     time.UnixMilli(firstSeen).UTC().Format(alertDateLayout),
		Severity:      severity,
		SourceIP:      firstNonEmpty(src["srcIpAddr"], src["hostIpAddr"]),
		DestinationIP: firstNonEmpty(target["destIpAddr"], target["hostIpAddr"]),
		AssetName:     firstNonEmpty(target["hostName"], src["hostName"]),
		Tactic:        firstTactic(inc["attackTactic"]),
		SourceStatus:  sourceStatus,
		FairExcluded:  models.Bool(falsePositive),
		SignalClass:   models.SignalClassThreatEvent,
		StatusOnly:    opts.Window != nil && (firstSeen < opts.Window.From || firstSeen > opts.Window.To),
		RawData:       rawData(inc),
	}, nil
}

// incidentID renders incidentId: a safe integer as decimal, a string trimmed.
func incidentID(v any) string {
	if f, ok := numeric(v); ok {
		if f == math.Trunc(f) && math.Abs(f) <= maxSafeInteger {
			return strconv.FormatInt(int64(f), 10)
		}
		return ""
	}
	return nonEmpty(v)
}

// epochMs parses an epoch-milliseconds value: a number >= 0 (truncated) or
// a digit string.
func epochMs(v any) (int64, bool) {
	var ms float64
	if f, ok := numeric(v); ok {
		if f < 0 {
			return 0, false
		}
		ms = math.Floor(f)
	} else if s, ok := v.(string); ok && digitsPattern.MatchString(strings.TrimSpace(s)) {
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return 0, false
		}
		ms = float64(n)
	} else {
		return 0, false
	}
	if ms > maxEpochMs {
		return 0, false
	}
	return int64(ms), true
}

// mapSeverity maps eventSeverity (0-10) and, without a usable number,
// eventSeverityCat.
func mapSeverity(inc map[string]any) string {
	if n, ok := number(inc["eventSeverity"]); ok && n >= 0 {
		switch {
		case n >= 10:
			return string(models.SeverityCritical)
		case n >= 9:
			return string(models.SeverityHigh)
		case n >= 5:
			return string(models.SeverityMedium)
		case n >= 1:
			return string(models.SeverityLow)
		default:
			return string(models.SeverityInfo)
		}
	}
	cat, _ := inc["eventSeverityCat"].(string)
	switch strings.ToUpper(strings.TrimSpace(cat)) {
	case "HIGH":
		return string(models.SeverityHigh)
	case "LOW":
		return string(models.SeverityLow)
	default:
		return string(models.SeverityMedium)
	}
}

// mapTechnique returns the first MITRE technique of attackTechnique: a JSON
// string (parsed up to twice), an array or an object, whose items are either
// technique ID strings or {"name", "techniqueid"} objects.
func mapTechnique(v any) (id, name string) {
	for range 2 {
		s, ok := v.(string)
		if !ok {
			break
		}
		var parsed any
		if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &parsed); err != nil {
			break
		}
		v = parsed
	}
	var items []any
	switch x := v.(type) {
	case nil:
	case []any:
		items = x
	default:
		items = []any{x}
	}
	for _, item := range items {
		switch it := item.(type) {
		case string:
			if t := strings.TrimSpace(it); techniquePattern.MatchString(t) {
				return strings.ToUpper(t), ""
			}
		case map[string]any:
			tid, present := it["techniqueid"]
			if !present {
				tid = it["techniqueId"]
			}
			if s, ok := tid.(string); ok && techniquePattern.MatchString(strings.TrimSpace(s)) {
				return strings.ToUpper(strings.TrimSpace(s)), nonEmpty(it["name"])
			}
		}
	}
	return unmappedTechniqueID, ""
}

// keyValues parses incidentSrc/incidentTarget ("key:value, key:value, "):
// pieces split on ",", each split on its first ":" (IPv6 stays whole); for
// each key the first non-empty value wins.
func keyValues(v any) map[string]string {
	out := map[string]string{}
	s, ok := v.(string)
	if !ok {
		return out
	}
	for _, piece := range strings.Split(s, ",") {
		key, value, found := strings.Cut(piece, ":")
		if !found {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		if _, dup := out[key]; !dup {
			out[key] = value
		}
	}
	return out
}

// firstTactic returns the first non-empty item of a comma-separated attackTactic.
func firstTactic(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	for _, piece := range strings.Split(s, ",") {
		if t := strings.TrimSpace(piece); t != "" {
			return t
		}
	}
	return ""
}

// mapStatus returns the normalized source status (incidentStatus plus the
// incidentReso suffix) and whether the incident was resolved as a false
// positive (which does not need a status).
func mapStatus(status, reso any) (string, bool) {
	resoCode, hasReso := codeOrWord(reso, resoWords)
	falsePositive := hasReso && resoCode == resoFalsePositive

	statusCode, ok := codeOrWord(status, statusWords)
	if !ok {
		return "", falsePositive
	}
	name, ok := statusNames[statusCode]
	if !ok {
		return "", falsePositive
	}
	if suffix, ok := resoSuffixes[resoCode]; hasReso && ok {
		name += "/" + suffix
	}
	return name, falsePositive
}

// isSecurityCategory reports whether phIncidentCategory is Security (code 4).
func isSecurityCategory(v any) bool {
	if code, ok := intCode(v); ok {
		return code == categorySecurity
	}
	return word(v) == "security"
}

// matchesTenant applies the tenant filter: customer (ignoring case and ASCII
// whitespace) or phCustId/custId (exact). An empty tenant matches everything.
func matchesTenant(inc map[string]any, tenant string) bool {
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return true
	}
	if customer, ok := inc["customer"].(string); ok && squash(customer) == squash(tenant) {
		return true
	}
	for _, key := range []string{"phCustId", "custId"} {
		if id, ok := idString(inc[key]); ok && id == tenant {
			return true
		}
	}
	return false
}

// idString renders an organization ID: an integer as decimal, a string trimmed.
func idString(v any) (string, bool) {
	if f, ok := numeric(v); ok {
		if f != math.Trunc(f) {
			return "", false
		}
		return strconv.FormatFloat(f, 'f', 0, 64), true
	}
	s, ok := v.(string)
	return strings.TrimSpace(s), ok
}

// rawData copies the rawDataKeys present (not null) with their JSON types.
func rawData(inc map[string]any) map[string]any {
	raw := make(map[string]any, len(rawDataKeys))
	for _, key := range rawDataKeys {
		if v, ok := inc[key]; ok && v != nil {
			raw[key] = v
		}
	}
	return raw
}

// --- value helpers ------------------------------------------------------------

// codeOrWord resolves a documented integer code (number or digit string) or,
// failing that, a word looked up in words.
func codeOrWord(v any, words map[string]int64) (int64, bool) {
	if code, ok := intCode(v); ok {
		return code, true
	}
	code, ok := words[word(v)]
	return code, ok
}

// intCode returns an integral JSON number, or a digit string, as an integer.
func intCode(v any) (int64, bool) {
	if f, ok := numeric(v); ok {
		if f != math.Trunc(f) || math.Abs(f) > maxSafeInteger {
			return 0, false
		}
		return int64(f), true
	}
	s, ok := v.(string)
	if !ok || !digitsPattern.MatchString(strings.TrimSpace(s)) {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n, err == nil
}

// number returns a JSON number, or a numeric string (-12, 3.5), as float64.
func number(v any) (float64, bool) {
	if f, ok := numeric(v); ok {
		return f, true
	}
	s, ok := v.(string)
	if !ok || !numberPattern.MatchString(strings.TrimSpace(s)) {
		return 0, false
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f, err == nil
}

// word lowercases a string after removing ASCII whitespace, '_' and '-':
// "Cleared Manually" -> "clearedmanually". Non-strings give "".
func word(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.ToLower(strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', '\f', '\v', '_', '-':
			return -1
		}
		return r
	}, s))
}

// squash lowercases a string after removing ASCII whitespace.
func squash(s string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			return -1
		}
		return r
	}, s))
}

// numeric returns v as a finite float64 when it is a JSON number.
func numeric(v any) (float64, bool) {
	var f float64
	switch n := v.(type) {
	case json.Number:
		parsed, err := n.Float64()
		if err != nil {
			return 0, false
		}
		f = parsed
	case float64:
		f = n
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	default:
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// nonEmpty returns v trimmed when it is a non-blank string, else "".
func nonEmpty(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
